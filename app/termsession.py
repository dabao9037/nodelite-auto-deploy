"""Detachable / resumable web-terminal sessions.

A browser WebSocket is only a *view* onto an SSH shell.  When the socket drops without
an explicit ``bye`` (mobile app switch, screen lock, network change, NAT timeout), the
shell is detached and kept alive for a grace period; its output keeps flowing into a
ring buffer.  The page reconnects with a random resume token (bound to the login session
and the server record) and gets the same shell back, plus everything it missed.

* Output is tracked with absolute byte offsets: the client reports how many bytes it has
  received and the server replays from there (bytes lost in a dead TCP connection are
  replayed too, nothing is shown twice).
* Heartbeats (``{"t":"ping"}``) keep NATs/proxies from dropping idle sockets.  They never
  count as activity: only real input and resizes reset the idle timer.
* Detached sessions count toward ``MAX_TERMINALS``; a reaper closes expired ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import threading
import time
from typing import Any

from .terminal import clamp_size

logger = logging.getLogger("nodelite_auto_deploy")

HEARTBEAT_SECONDS = 20.0
RESUME_SECONDS = 600
BUFFER_BYTES = 256 * 1024
UNLOAD_GRACE = 15.0  # page closed / refreshed: keep the shell just long enough for a refresh
SEND_TIMEOUT = 10.0
KICKED_MESSAGE = "该终端已在另一个页面中打开，这里已断开"


class OutputLog:
    """The last ``limit`` bytes of shell output, addressed by absolute offset."""

    def __init__(self, limit: int = BUFFER_BYTES):
        self.limit = limit
        self.data = bytearray()
        self.end = 0  # total bytes ever produced

    def append(self, chunk: bytes) -> None:
        self.data += chunk
        self.end += len(chunk)
        if len(self.data) > self.limit:
            del self.data[: len(self.data) - self.limit]

    def since(self, offset: int) -> bytes:
        start = self.end - len(self.data)
        offset = max(0, offset)
        if offset >= self.end:
            return b""
        return bytes(self.data[max(offset, start) - start:])


class Attachment:
    """One WebSocket currently showing a session."""

    def __init__(self, websocket: Any):
        self.websocket = websocket
        self.kicked = asyncio.Event()
        self.unload = False
        self.last_rx = time.monotonic()  # last message from the browser (input, ping, pong…)


class TermSession:
    def __init__(self, sid: str, server_id: int, shell: Any, buffer_bytes: int):
        self.token = secrets.token_urlsafe(32)  # resume token: never logged, never in a URL
        self.sid = sid
        self.server_id = server_id
        self.shell = shell
        self.log = OutputLog(buffer_bytes)
        self.attachment: Attachment | None = None
        self.detached_at: float | None = time.monotonic()
        self.grace: float | None = None  # overrides the default grace period (page unload)
        self.last_input = time.monotonic()
        self.closed = False
        self.close_message: str | None = None
        self.ended = asyncio.Event()
        self.out_lock = asyncio.Lock()
        self.write_lock = threading.Lock()
        self.pump: asyncio.Task | None = None

    def write(self, data: bytes) -> None:
        with self.write_lock:
            self.shell.write(data)


class TerminalManager:
    def __init__(self, max_sessions: int, resume_seconds: float = RESUME_SECONDS, idle_seconds: float = 1800,
                 heartbeat: float = HEARTBEAT_SECONDS, buffer_bytes: int = BUFFER_BYTES):
        self.max_sessions = max_sessions
        self.resume_seconds = resume_seconds
        self.idle_seconds = idle_seconds
        self.heartbeat = heartbeat
        self.buffer_bytes = buffer_bytes
        self.sessions: list[TermSession] = []
        self.active = 0  # shells being opened + live shells (attached or detached)
        spans = [s / 4 for s in (resume_seconds, idle_seconds) if s > 0]
        self.reap_interval = max(0.05, min([5.0, *spans]))
        self._reaper: asyncio.Task | None = None

    # ---- lookup / lifecycle ----------------------------------------------------------
    def full(self) -> bool:
        return self.active >= self.max_sessions

    def find(self, token: str, sid: str, server_id: int) -> TermSession | None:
        """Constant-time match of resume token *and* login session."""
        token_b, sid_b = str(token).encode(), str(sid).encode()
        found = None
        for session in list(self.sessions):
            ok = secrets.compare_digest(session.token.encode(), token_b)
            ok = secrets.compare_digest(session.sid.encode(), sid_b) and ok
            if ok and session.server_id == server_id and not session.closed:
                found = session
        return found

    def add(self, sid: str, server_id: int, shell: Any) -> TermSession:
        """Register an opened shell. The caller has already reserved a slot in ``active``."""
        session = TermSession(sid, server_id, shell, self.buffer_bytes)
        self.sessions.append(session)
        session.pump = asyncio.create_task(self._pump(session))
        if self._reaper is None or self._reaper.done():
            self._reaper = asyncio.create_task(self._reap_loop())
        return session

    async def close(self, session: TermSession, message: str | None = None) -> None:
        """Really close the shell (bye, remote exit, idle, grace expiry, logout, shutdown)."""
        if session.closed:
            return
        session.closed = True
        session.close_message = message
        if session in self.sessions:
            self.sessions.remove(session)
        self.active -= 1
        session.ended.set()
        if session.pump is not None and session.pump is not asyncio.current_task():
            session.pump.cancel()
        # shield: even if the caller is cancelled the SSH connection is closed
        closer = asyncio.ensure_future(asyncio.to_thread(session.shell.close))
        await asyncio.shield(closer)
        logger.info("terminal closed for server record %s", session.server_id)

    async def close_sid(self, sid: str) -> None:
        for session in [s for s in self.sessions if secrets.compare_digest(s.sid.encode(), str(sid).encode())]:
            await self.close(session, "已退出登录")

    async def shutdown(self) -> None:
        if self._reaper is not None:
            self._reaper.cancel()
            await asyncio.gather(self._reaper, return_exceptions=True)
        for session in list(self.sessions):
            await self.close(session, "服务正在重启，终端已断开")

    async def reap(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        for session in list(self.sessions):
            if now - session.last_input >= self.idle_seconds:
                idle = int(self.idle_seconds)
                span = f"{idle // 60} 分钟" if idle >= 60 else f"{idle} 秒"
                await self.close(session, f"超过 {span}没有操作，已自动断开")
            elif session.attachment is None and session.detached_at is not None:
                grace = session.grace if session.grace is not None else self.resume_seconds
                if now - session.detached_at >= grace:
                    await self.close(session, None)

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(self.reap_interval)
            try:
                await self.reap()
            except Exception:  # noqa: BLE001 - never let the reaper die
                logger.exception("terminal reaper error")

    # ---- shell -> browser ------------------------------------------------------------
    async def _pump(self, session: TermSession) -> None:
        try:
            while not session.closed:
                data = await asyncio.to_thread(session.shell.read)
                if data is None:
                    await self.close(session, "远程会话已结束")
                    return
                if data:
                    await self._deliver(session, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("terminal output pump ended: %s", type(exc).__name__)
            await self.close(session, "远程会话已结束")

    async def _deliver(self, session: TermSession, data: bytes) -> None:
        async with session.out_lock:
            session.log.append(data)
            att = session.attachment
            if att is None:
                return
            try:
                await asyncio.wait_for(att.websocket.send_bytes(data), SEND_TIMEOUT)
            except Exception:  # noqa: BLE001 - dead socket: keep the output for the resume
                self._detach_locked(session, att)

    async def _send(self, session: TermSession, att: Attachment, body: dict) -> None:
        async with session.out_lock:
            if session.attachment is att:
                await asyncio.wait_for(att.websocket.send_text(json.dumps(body, ensure_ascii=False)), SEND_TIMEOUT)

    # ---- attach / detach -------------------------------------------------------------
    def _detach_locked(self, session: TermSession, att: Attachment) -> None:
        if session.attachment is att:
            session.attachment = None
            session.detached_at = time.monotonic()
            if att.unload:
                session.grace = UNLOAD_GRACE

    async def attach(self, session: TermSession, att: Attachment, offset: int, resumed: bool, extra: dict) -> None:
        websocket = att.websocket
        async with session.out_lock:
            old = session.attachment
            session.attachment = att
            session.detached_at = None
            session.grace = None
            if old is not None:
                old.kicked.set()  # its own handler tells the old page and closes it
            body = {"t": "ready", "m": "已连接", "token": session.token, "resumed": resumed, **extra}
            await asyncio.wait_for(websocket.send_text(json.dumps(body, ensure_ascii=False)), SEND_TIMEOUT)
            replay = session.log.since(offset)
            if replay:
                await asyncio.wait_for(websocket.send_bytes(replay), SEND_TIMEOUT)

    async def serve(self, session: TermSession, websocket: Any, offset: int, resumed: bool, **extra: Any) -> None:
        """Run one WebSocket attachment until it drops, is kicked, says bye, or the shell ends."""
        att = Attachment(websocket)
        outcome = "drop"
        try:
            try:
                await self.attach(session, att, offset, resumed, extra)
            except Exception:  # noqa: BLE001 - socket died during attach: stay detached
                return
            tasks = {
                "up": asyncio.create_task(self._upstream(session, att)),
                "hb": asyncio.create_task(self._heartbeat(session, att)),
                "kick": asyncio.create_task(att.kicked.wait()),
                "ended": asyncio.create_task(session.ended.wait()),
            }
            try:
                await asyncio.wait(tasks.values(), return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks.values():
                    task.cancel()
                await asyncio.gather(*tasks.values(), return_exceptions=True)
            up = tasks["up"]
            if up.done() and not up.cancelled() and up.exception() is None:
                outcome = up.result()
            if att.kicked.is_set():
                await _quiet(websocket.send_text(json.dumps({"t": "kicked", "m": KICKED_MESSAGE}, ensure_ascii=False)))
                await _quiet(websocket.close(code=4001))
            elif session.closed:
                if session.close_message:
                    body = {"t": "closed", "m": session.close_message}
                    await _quiet(websocket.send_text(json.dumps(body, ensure_ascii=False)))
                await _quiet(websocket.close())
            elif outcome == "bye":
                await self.close(session, None)
                await _quiet(websocket.close())
            elif tasks["hb"].done() and not tasks["hb"].cancelled():
                await _quiet(websocket.close(code=4002))  # heartbeat timeout: the page will reconnect
        finally:
            if not session.closed:
                async with session.out_lock:
                    self._detach_locked(session, att)

    async def _heartbeat(self, session: TermSession, att: Attachment) -> None:
        while True:
            await asyncio.sleep(self.heartbeat)
            # The page pings every 20s: silence for 3 intervals = the socket died silently
            # (mobile network gone without a FIN). Detach so the grace period starts.
            if time.monotonic() - att.last_rx > self.heartbeat * 3:
                return
            await self._send(session, att, {"t": "ping"})  # not activity: idle timer untouched

    async def _write(self, session: TermSession, data: bytes) -> bool:
        session.last_input = time.monotonic()
        try:
            await asyncio.to_thread(session.write, data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("terminal write failed: %s", type(exc).__name__)
            await self.close(session, "远程会话已结束")
            return False
        return True

    async def _upstream(self, session: TermSession, att: Attachment) -> str:
        websocket = att.websocket
        while True:
            message = await websocket.receive()
            att.last_rx = time.monotonic()
            if message["type"] == "websocket.disconnect":
                return "unload" if att.unload else "drop"
            raw = message.get("text")
            if raw is None:
                data = message.get("bytes") or b""
                if data and not await self._write(session, data[:65536]):
                    return "ended"
                continue
            try:
                body = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(body, dict):
                continue
            kind = body.get("t")
            if kind == "i" and isinstance(body.get("d"), str):
                if not await self._write(session, body["d"][:65536].encode("utf-8", errors="replace")):
                    return "ended"
            elif kind == "r":
                session.last_input = time.monotonic()
                cols, rows = clamp_size(body.get("c"), body.get("r"))
                try:
                    await asyncio.to_thread(session.shell.resize, cols, rows)
                except Exception:  # noqa: BLE001 - a failed resize is harmless
                    pass
            elif kind == "ping":
                await self._send(session, att, {"t": "pong"})
            elif kind == "bye":
                return "bye"
            elif kind == "unload":
                att.unload = True


async def _quiet(awaitable) -> None:
    try:
        await asyncio.wait_for(awaitable, SEND_TIMEOUT)
    except Exception:  # noqa: BLE001 - peer already gone
        pass
