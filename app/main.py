from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field, SecretStr, field_validator

from .config import Settings, is_loopback_host
from .deployer import DeployHostKeyMismatch, DeploymentError, DeploySpec, HostKeyMismatch, deploy
from .security import (
    TargetRejected,
    csrf_token,
    csrf_valid,
    resolve_and_validate_target,
    validate_hostname,
    validate_port,
    validate_username,
)
from .store import ServerStore
from .tasks import Reporter, TaskStore
from .terminal import IDLE_TIMEOUT, ShellSession, TerminalError, TicketStore, clamp_size

BASE = Path(__file__).resolve().parent
logger = logging.getLogger("nodelite_auto_deploy")
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]{2,45}\](:[0-9]{1,5})?$")
SESSION_COOKIE = "nlad_session"
PRE_COOKIE = "nlad_pre"


class RateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, count: int, window: int) -> bool:
        now = time.time()
        bucket = self.events[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= count:
            return False
        bucket.append(now)
        return True


class DeployRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int | str | None = Field(default=None, validate_default=True)
    ssh_user: str | None = Field(default=None, max_length=32, validate_default=True)
    # 留空 = 使用该服务器记录里已保存的密码（重新部署）
    ssh_password: SecretStr | None = Field(default=None, max_length=512)
    save_password: bool = True
    disable_ipv6: bool = True
    authorized: bool = False

    @field_validator("host")
    @classmethod
    def host_valid(cls, value: str) -> str:
        return validate_hostname(value)

    @field_validator("ssh_port", mode="before")
    @classmethod
    def port_valid(cls, value: Any) -> int:
        if value is None or (isinstance(value, str) and not value.strip()):
            return 22
        return validate_port(value, "SSH 端口")

    @field_validator("ssh_user", mode="before")
    @classmethod
    def user_valid(cls, value: Any) -> str:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "root"
        return validate_username(str(value))


class TerminalRequest(BaseModel):
    ssh_password: SecretStr | None = Field(default=None, max_length=512)
    save_password: bool = False
    cols: int = 120
    rows: int = 32


class TrustKeyRequest(BaseModel):
    fingerprint: str = Field(min_length=10, max_length=128)


class State:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.serializer = URLSafeTimedSerializer(settings.session_secret, salt="nlad-session-v1")
        self.pre_serializer = URLSafeTimedSerializer(settings.session_secret, salt="nlad-login-v1")
        self.tasks = TaskStore(settings.max_concurrent_tasks, settings.task_ttl_seconds)
        self.login_limiter = RateLimiter()
        self.task_limiter = RateLimiter()
        self.background: set[asyncio.Task] = set()
        self.store = ServerStore(settings.data_dir)
        self.tickets = TicketStore()
        self.terminals = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    for task in list(app.state.core.background):
        task.cancel()
    if app.state.core.background:
        await asyncio.gather(*app.state.core.background, return_exceptions=True)
    app.state.core.store.close()


def render(name: str, **values: str) -> str:
    text = (BASE / "static" / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", html.escape(value, quote=True))
    return text


def create_app(settings: Settings | None = None, deploy_fn=deploy, shell_factory=ShellSession) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(
        title="NodeLite Auto Deploy",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.core = State(settings)
    bp = settings.base_path  # 子路径前缀，空 = 根目录
    app.mount(bp + "/static", StaticFiles(directory=BASE / "static"), name="static")

    def session_id(request: Request) -> str:
        token = request.cookies.get(SESSION_COOKIE, "")
        try:
            payload = app.state.core.serializer.loads(token, max_age=settings.session_ttl_seconds)
        except (BadSignature, SignatureExpired):
            raise HTTPException(401, "请先登录") from None
        if not isinstance(payload, dict) or not payload.get("sid"):
            raise HTTPException(401, "请先登录")
        return str(payload["sid"])

    def require_csrf(request: Request, sid: str = Depends(session_id)) -> str:
        if not csrf_valid(settings.session_secret, sid, request.headers.get("x-csrf-token")):
            raise HTTPException(403, "CSRF 校验失败，请刷新页面后重试")
        return sid

    def client_key(request: Request) -> str:
        peer = request.client.host if request.client else "unknown"
        if settings.trust_proxy and is_loopback_host(peer):
            real = request.headers.get("x-real-ip", "").strip()
            if real:
                return real[:64]
        return peer

    def same_origin(request: Request) -> bool:
        # 浏览器在 Referrer-Policy: no-referrer 下，同源表单 / fetch 的 POST 也会带
        # "Origin: null"，之前因此把正常操作当成跨站拒绝。null 时改看 Sec-Fetch-Site。
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if origin and origin != "null":
            return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()
        if fetch_site:
            return fetch_site in {"same-origin", "none"}
        # 无 Origin 也无 Sec-Fetch-Site：非浏览器客户端，交给 CSRF token 校验
        return origin is None

    def ws_sources(host: str) -> str:
        # 'self' 在部分浏览器里不包含 ws:/wss:，显式加上同主机（Host 头先做白名单校验，防止注入 CSP）
        host = (host or "").lower()
        return f" ws://{host} wss://{host}" if SAFE_HOST_RE.fullmatch(host) else ""

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not same_origin(request):
            return JSONResponse({"detail": "跨站请求已拒绝"}, status_code=403)
        response = await call_next(request)
        # 终端页：xterm.js 会插入 <style> 元素，用每次响应随机的 nonce 放行，不使用 unsafe-inline
        nonce = getattr(request.state, "style_nonce", "")
        style_src = f"'self' 'nonce-{nonce}'" if nonce else "'self'"
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Content-Security-Policy": (
                    f"default-src 'self'; img-src 'self' data:; style-src {style_src}; "
                    f"script-src 'self'; connect-src 'self'{ws_sources(request.headers.get('host', ''))}; "
                    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                ),
            }
        )
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        # Never echo request input back (it may contain the SSH password).
        messages = []
        for error in exc.errors():
            ctx = error.get("ctx") or {}
            if isinstance(ctx.get("error"), ValueError):
                messages.append(str(ctx["error"]))
            else:
                field = ".".join(str(p) for p in error.get("loc", [])[1:]) or "请求"
                messages.append(f"{field} 字段无效")
        return JSONResponse({"detail": "；".join(messages) or "请求无效"}, status_code=422)

    async def healthz():
        return {"status": "ok"}

    # 根路径和子路径都提供健康检查：安装/更新脚本直连 127.0.0.1 探活，不受 WEB_BASE_PATH 影响
    app.add_api_route("/healthz", healthz, methods=["GET"])
    if bp:
        app.add_api_route(bp + "/healthz", healthz, methods=["GET"])

    @app.get(bp + "/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str = ""):
        try:
            session_id(request)
            return RedirectResponse(bp + "/", 303)
        except HTTPException:
            pass
        nonce = secrets.token_urlsafe(24)
        messages = {"1": "用户名或密码错误", "2": "登录尝试过多，请稍后再试", "3": "页面已过期，请重试"}
        response = HTMLResponse(
            render("login.html", csrf=app.state.core.pre_serializer.dumps(nonce), error=messages.get(error, ""), base=bp)
        )
        response.set_cookie(
            PRE_COOKIE, nonce, max_age=900, httponly=True, secure=settings.cookie_secure,
            samesite="strict", path=bp + "/login",
        )
        return response

    @app.post(bp + "/login")
    async def login(
        request: Request,
        username: str = Form(..., max_length=128),
        password: str = Form(..., max_length=512),
        csrf: str = Form("", max_length=512),
    ):
        state: State = app.state.core
        if not state.login_limiter.allow(client_key(request), settings.login_attempts, settings.login_window_seconds):
            return RedirectResponse(bp + "/login?error=2", 303)
        try:
            nonce = state.pre_serializer.loads(csrf, max_age=900)
        except (BadSignature, SignatureExpired):
            nonce = None
        cookie = request.cookies.get(PRE_COOKIE, "")
        if not nonce or not cookie or not hmac.compare_digest(str(nonce), cookie):
            return RedirectResponse(bp + "/login?error=3", 303)
        ok = hmac.compare_digest(username.encode(), settings.admin_user.encode())
        ok = hmac.compare_digest(password.encode(), settings.admin_password.encode()) and ok
        if not ok:
            logger.warning("login failed from %s", client_key(request))
            return RedirectResponse(bp + "/login?error=1", 303)
        token = state.serializer.dumps({"sid": secrets.token_urlsafe(24)})
        response = RedirectResponse(bp + "/", 303)
        response.set_cookie(
            SESSION_COOKIE, token, max_age=settings.session_ttl_seconds, httponly=True,
            secure=settings.cookie_secure, samesite="strict", path=bp + "/",
        )
        response.delete_cookie(PRE_COOKIE, path=bp + "/login")
        return response

    @app.post(bp + "/logout")
    async def logout(request: Request, csrf: str = Form("", max_length=256)):
        try:
            sid = session_id(request)
        except HTTPException:
            return RedirectResponse(bp + "/login", 303)
        if not csrf_valid(settings.session_secret, sid, csrf):
            raise HTTPException(403, "CSRF 校验失败")
        response = RedirectResponse(bp + "/login", 303)
        response.delete_cookie(SESSION_COOKIE, path=bp + "/")
        return response

    if bp:
        @app.get(bp)
        async def base_redirect():
            return RedirectResponse(bp + "/", 308)

    @app.get(bp + "/", response_class=HTMLResponse)
    async def home(request: Request):
        try:
            sid = session_id(request)
        except HTTPException:
            return RedirectResponse(bp + "/login", 303)
        return HTMLResponse(
            render(
                "index.html",
                csrf=csrf_token(settings.session_secret, sid),
                ttl=str(settings.task_ttl_seconds // 60),
                base=bp,
            )
        )

    @app.post(bp + "/api/tasks", status_code=202)
    async def create_task(payload: DeployRequest, sid: str = Depends(require_csrf)):
        state: State = app.state.core
        if not payload.authorized:
            raise HTTPException(422, "请先确认你拥有或已获授权管理这台服务器")
        if state.tasks.active_count() >= settings.max_concurrent_tasks * 2:
            raise HTTPException(429, "当前排队任务过多，请稍后再试")
        if not state.task_limiter.allow(sid, settings.task_attempts, settings.task_window_seconds):
            raise HTTPException(429, "创建任务过于频繁，请稍后再试")
        try:
            target = await resolve_and_validate_target(payload.host, settings)
        except (ValueError, TargetRejected) as exc:
            raise HTTPException(422, str(exc)) from exc
        store = state.store
        host, port, user = target.original, int(payload.ssh_port), str(payload.ssh_user)
        record = store.find(host, port, user)
        password = payload.ssh_password.get_secret_value() if payload.ssh_password else ""
        typed_password = bool(password)
        if not password and record:
            password = store.ssh_password(record["id"]) or ""
        if not password:
            raise HTTPException(422, "请填写 SSH 密码（该服务器没有已保存的密码）")
        # 用户新输入且勾选了保存，才写入（登录成功后）；沿用已保存的密码时不重复写
        save = {"password": password if (typed_password and payload.save_password) else None}
        ids: dict[str, int] = {}

        def on_connected(fingerprint: str, key_type: str) -> None:
            ids["server"] = store.ensure_server(host, port, user, fingerprint, key_type)
            if save["password"]:
                store.set_ssh_password(ids["server"], save["password"])
            save["password"] = None

        holder = {
            "spec": DeploySpec(
                host=host,
                resolved_addresses=target.addresses,
                typed_ipv6=target.typed_ipv6,
                ssh_port=port,
                ssh_user=user,
                ssh_password=password,
                disable_ipv6=payload.disable_ipv6,
                expected_fingerprint=(record or {}).get("fingerprint") or "",
                on_connected=on_connected,
            )
        }
        del payload, password
        task = await state.tasks.create(sid)

        async def worker(reporter: Reporter) -> dict[str, Any]:
            spec = holder.pop("spec")
            try:
                result = await asyncio.to_thread(deploy_fn, spec, reporter, settings)
            except DeployHostKeyMismatch as exc:
                if record:
                    store.set_pending_fingerprint(record["id"], exc.mismatch.actual, exc.mismatch.key_type)
                    store.record_failure(record["id"])
                store.add_history(host, port, user, "failed", error="SSH 主机密钥不一致，已拒绝连接")
                raise
            except Exception as exc:  # noqa: BLE001
                error = exc if isinstance(exc, DeploymentError) else DeploymentError(f"部署异常：{type(exc).__name__}")
                try:
                    store.record_failure(ids.get("server"))
                    store.add_history(host, port, user, "failed", error=str(error), server_id=ids.get("server"))
                except Exception:  # noqa: BLE001
                    logger.exception("saving failed deploy history")
                if error is exc:
                    raise
                raise error from None
            finally:
                # CPython strings cannot be zeroed; drop every reference we hold.
                spec.ssh_password = None
                spec.on_connected = None
                save["password"] = None
                del spec
            status = "warn" if "warn" in reporter.task.steps.values() else "success"
            try:
                server_id = ids.get("server") or store.ensure_server(
                    host, port, user, result.get("fingerprint", ""), result.get("key_type", "")
                )
                store.record_success(server_id, {**result, "status": status})
                store.add_history(host, port, user, status, version=str(result.get("version") or ""),
                                  server_id=server_id)
                result["server_id"] = server_id
            except Exception:  # noqa: BLE001 - never lose the deploy result because of the record store
                logger.exception("saving server record")
                reporter.info("警告：服务器记录保存失败，请立即手动保存以上信息")
            return result

        runner = asyncio.create_task(state.tasks.run(task, worker))
        state.background.add(runner)
        runner.add_done_callback(state.background.discard)
        return {"task_id": task.id, "status": task.status}

    @app.get(bp + "/api/tasks/{task_id}")
    async def get_task(task_id: str, since: int = 0, sid: str = Depends(session_id)):
        task = await app.state.core.tasks.get(task_id, sid)
        if not task:
            raise HTTPException(404, "任务不存在、已过期或无权访问")
        return task.public(max(0, since))

    @app.delete(bp + "/api/tasks/{task_id}")
    async def delete_task(task_id: str, sid: str = Depends(require_csrf)):
        if not await app.state.core.tasks.discard(task_id, sid):
            raise HTTPException(404, "任务不存在、仍在运行或无权访问")
        return {"ok": True}


    # ---- 服务器记录 ---------------------------------------------------------------
    def record_or_404(server_id: int) -> dict[str, Any]:
        record = app.state.core.store.get(server_id)
        if not record:
            raise HTTPException(404, "服务器记录不存在")
        return record

    @app.get(bp + "/api/servers")
    async def list_servers(_sid: str = Depends(session_id)):
        return {"servers": app.state.core.store.list()}

    @app.get(bp + "/api/servers/{server_id}")
    async def get_server(server_id: int, _sid: str = Depends(session_id)):
        return record_or_404(server_id)

    @app.get(bp + "/api/servers/{server_id}/history")
    async def server_history(server_id: int, _sid: str = Depends(session_id)):
        record_or_404(server_id)
        return {"history": app.state.core.store.history(server_id)}

    @app.post(bp + "/api/servers/{server_id}/reveal")
    async def reveal_panel_password(server_id: int, sid: str = Depends(require_csrf)):
        record_or_404(server_id)
        if not app.state.core.task_limiter.allow(f"reveal:{sid}", 60, 300):
            raise HTTPException(429, "操作过于频繁，请稍后再试")
        password = app.state.core.store.panel_password(server_id)
        if password is None:
            raise HTTPException(404, "该记录没有保存面板密码")
        logger.info("panel password revealed for server record %s", server_id)
        return {"password": password}

    @app.delete(bp + "/api/servers/{server_id}/ssh-password")
    async def forget_ssh_password(server_id: int, _sid: str = Depends(require_csrf)):
        record_or_404(server_id)
        app.state.core.store.forget_ssh_password(server_id)
        logger.info("saved ssh password deleted for server record %s", server_id)
        return {"ok": True}

    @app.delete(bp + "/api/servers/{server_id}")
    async def delete_server(server_id: int, _sid: str = Depends(require_csrf)):
        if not app.state.core.store.delete(server_id):
            raise HTTPException(404, "服务器记录不存在")
        logger.info("server record %s deleted", server_id)
        return {"ok": True}

    @app.post(bp + "/api/servers/{server_id}/trust-key")
    async def trust_new_key(server_id: int, payload: TrustKeyRequest, _sid: str = Depends(require_csrf)):
        record_or_404(server_id)
        if not app.state.core.store.trust_pending_fingerprint(server_id, payload.fingerprint.strip()):
            raise HTTPException(409, "没有待确认的新主机密钥，或指纹不一致")
        logger.warning("server record %s: operator trusted a new SSH host key", server_id)
        return app.state.core.store.get(server_id)

    # ---- 网页 SSH 终端 -------------------------------------------------------------
    @app.get(bp + "/terminal/{server_id}", response_class=HTMLResponse)
    async def terminal_page(request: Request, server_id: int):
        try:
            sid = session_id(request)
        except HTTPException:
            return RedirectResponse(bp + "/login", 303)
        record = app.state.core.store.get(server_id)
        if not record:
            return RedirectResponse(bp + "/", 303)
        nonce = secrets.token_urlsafe(18)
        request.state.style_nonce = nonce
        title = f"{record['ssh_user']}@{record['host']}:{record['ssh_port']}"
        return HTMLResponse(
            render(
                "terminal.html", csrf=csrf_token(settings.session_secret, sid), base=bp,
                server_id=str(server_id), title=title, nonce=nonce,
            )
        )

    @app.post(bp + "/api/servers/{server_id}/terminal")
    async def create_terminal_ticket(server_id: int, payload: TerminalRequest, sid: str = Depends(require_csrf)):
        state: State = app.state.core
        record = record_or_404(server_id)
        if state.terminals >= settings.max_terminals:
            raise HTTPException(429, f"同时打开的终端已达上限（{settings.max_terminals} 个）")
        if not state.task_limiter.allow(f"term:{sid}", 30, 300):
            raise HTTPException(429, "连接过于频繁，请稍后再试")
        password = payload.ssh_password.get_secret_value() if payload.ssh_password else None
        if not password and not record["has_ssh_password"]:
            return JSONResponse({"detail": "该服务器没有保存 SSH 密码，请输入密码", "need_password": True}, 409)
        try:
            target = await resolve_and_validate_target(record["host"], settings)
        except (ValueError, TargetRejected) as exc:
            raise HTTPException(422, str(exc)) from exc
        cols, rows = clamp_size(payload.cols, payload.rows)
        ticket = state.tickets.issue(
            sid, server_id, target.addresses, password or None, bool(password and payload.save_password), cols, rows
        )
        del password, payload
        return {"ticket": ticket, "ws_path": f"{bp}/api/servers/{server_id}/terminal/ws"}

    def ws_origin_ok(websocket: WebSocket) -> bool:
        origin = websocket.headers.get("origin")
        host = websocket.headers.get("host", "").lower()
        if origin and origin != "null":
            return urlsplit(origin).netloc.lower() == host
        if origin == "null":
            return websocket.headers.get("sec-fetch-site", "").lower() == "same-origin"
        return False  # 浏览器的 WebSocket 一定带 Origin

    @app.websocket(bp + "/api/servers/{server_id}/terminal/ws")
    async def terminal_ws(websocket: WebSocket, server_id: int, ticket: str = ""):
        state: State = app.state.core
        if not ws_origin_ok(websocket):
            await websocket.close(code=1008)
            return
        token = websocket.cookies.get(SESSION_COOKIE, "")
        try:
            payload = state.serializer.loads(token, max_age=settings.session_ttl_seconds)
            sid = str(payload["sid"])
        except (BadSignature, SignatureExpired, TypeError, KeyError):
            await websocket.close(code=1008)
            return
        grant = state.tickets.consume(ticket, sid) if ticket else None
        if not grant or grant.server_id != server_id:
            await websocket.close(code=1008)
            return
        record = state.store.get(server_id)
        if not record or state.terminals >= settings.max_terminals:
            grant.password = None
            await websocket.close(code=1013)
            return
        state.terminals += 1
        await websocket.accept()
        shell = shell_factory(grant.addresses, record["ssh_port"], record["ssh_user"], record["fingerprint"],
                              settings.ssh_connect_timeout)

        async def control(kind: str, **values: Any) -> None:
            await websocket.send_text(json.dumps({"t": kind, **values}, ensure_ascii=False))

        try:
            password = grant.password or state.store.ssh_password(server_id) or ""
            save, grant.password = grant.save, None
            if not password:
                await control("error", m="没有可用的 SSH 密码，请重新连接并输入密码", need_password=True)
                return
            await control("status", m=f"正在连接 {record['ssh_user']}@{record['host']}:{record['ssh_port']} …")
            try:
                await asyncio.to_thread(shell.open, password, grant.cols, grant.rows)
            except HostKeyMismatch as exc:
                state.store.set_pending_fingerprint(server_id, exc.actual, exc.key_type)
                logger.warning("server record %s: SSH host key mismatch, terminal refused", server_id)
                await control("hostkey", expected=exc.expected, actual=exc.actual, key_type=exc.key_type)
                return
            except TerminalError as exc:
                await control("error", m=str(exc), need_password="认证失败" in str(exc))
                return
            if save:
                state.store.set_ssh_password(server_id, password)
            del password
            logger.info("terminal opened for server record %s", server_id)
            await control("ready", m="已连接", saved=save)
            await bridge(websocket, shell, settings.terminal_idle_seconds, control)
        except Exception:  # noqa: BLE001
            logger.exception("terminal session error")
        finally:
            state.terminals -= 1
            # shield：即使本协程被取消（浏览器断开 / 服务停止），SSH 连接也一定会被关闭
            closer = asyncio.ensure_future(asyncio.to_thread(shell.close))
            try:
                await asyncio.shield(closer)
            except asyncio.CancelledError:
                raise
            else:
                try:
                    await websocket.close()
                except Exception:  # noqa: BLE001 - already closed by the peer
                    pass

    return app


async def bridge(websocket: WebSocket, shell: Any, idle_seconds: int, control) -> None:
    """Pump bytes between the browser and the SSH channel until either side ends."""
    idle_seconds = idle_seconds or IDLE_TIMEOUT
    write_lock = threading.Lock()

    def write(data: bytes) -> None:
        with write_lock:
            shell.write(data)

    async def downstream() -> None:
        while True:
            data = await asyncio.to_thread(shell.read)
            if data is None:
                await control("closed", m="远程会话已结束")
                return
            if data:
                await websocket.send_bytes(data)

    async def upstream() -> None:
        while True:
            try:
                message = await asyncio.wait_for(websocket.receive(), timeout=idle_seconds)
            except asyncio.TimeoutError:
                await control("closed", m=f"超过 {idle_seconds // 60} 分钟没有操作，已自动断开")
                return
            if message["type"] == "websocket.disconnect":
                return
            raw = message.get("text")
            if raw is None:
                data = message.get("bytes") or b""
                if data:
                    await asyncio.to_thread(write, data[:65536])
                continue
            try:
                body = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(body, dict):
                continue
            if body.get("t") == "i" and isinstance(body.get("d"), str):
                await asyncio.to_thread(write, body["d"][:65536].encode("utf-8", errors="replace"))
            elif body.get("t") == "r":
                cols, rows = clamp_size(body.get("c"), body.get("r"))
                await asyncio.to_thread(shell.resize, cols, rows)
            elif body.get("t") == "bye":
                return

    tasks = [asyncio.create_task(downstream()), asyncio.create_task(upstream())]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            exc = task.exception()
            if exc and not isinstance(exc, (OSError, RuntimeError)):
                logger.warning("terminal bridge ended: %s", type(exc).__name__)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def run() -> None:  # pragma: no cover - exercised by the systemd unit
    import uvicorn

    settings = Settings.load()
    if settings.allow_public_listen:
        logger.warning("WEB_ALLOW_PUBLIC_LISTEN=1：本程序处理 root 密码，务必放在 HTTPS 之后")
    uvicorn.run(
        create_app(settings),
        host=settings.listen_host,
        port=settings.listen_port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        ws="wsproto",
        ws_max_size=1 << 20,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
