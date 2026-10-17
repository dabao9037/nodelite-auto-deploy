"""Heartbeat, detach-on-drop and resume of web-terminal sessions."""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.termsession import OutputLog

from .conftest import login
from .test_records import (  # noqa: F401 - _reset_shell is an autouse fixture
    ORIGIN,
    FakeShell,
    _reset_shell,
    recv_bytes_containing,
    recv_until,
    ticket,
)
from .test_records import terminal_client as _terminal_client

_clients: list = []


def terminal_client(tmp_path, **overrides):
    result = _terminal_client(tmp_path, **overrides)
    _clients.append(result[0])
    return result


@pytest.fixture(autouse=True)
def _close_clients():
    yield
    while _clients:
        client = _clients.pop()
        try:
            client.__exit__(None, None, None)  # lifespan shutdown closes detached shells
        except Exception:  # noqa: BLE001 - already exited by the test
            pass

WS = "ws://127.0.0.1:8780"


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class Open:
    """Open the terminal WS with a ticket as first message (optionally with an output offset)."""

    def __init__(self, client, data, offset=0):
        self.client, self.data, self.offset = client, data, offset

    def __enter__(self):
        self.cm = self.client.websocket_connect(WS + self.data["ws_path"], headers={"origin": ORIGIN})
        ws = self.cm.__enter__()
        ws.send_text(json.dumps({"t": "auth", "ticket": self.data["ticket"], "offset": self.offset}))
        return ws

    def __exit__(self, *exc):
        return self.cm.__exit__(*exc)


def manager(client):
    return client.app.state.core.terminals


def start(client, server_id):
    """Open a fresh terminal, type something, drop the socket without 'bye'. Returns the resume token."""
    data = ticket(client, server_id).json()
    with Open(client, data) as ws:
        ready = recv_until(ws, "ready")
        assert ready["resumed"] is False and len(ready["token"]) >= 40
        recv_bytes_containing(ws, b"welcome")
        ws.send_text(json.dumps({"t": "i", "d": "export MARK=1\r"}))
        recv_bytes_containing(ws, b"echo:export MARK=1")
    # context exit = abrupt drop (no 'bye')
    assert wait_for(lambda: manager(client).sessions and manager(client).sessions[0].attachment is None)
    return ready["token"]


def test_output_log_ring_buffer_offsets():
    log = OutputLog(limit=8)
    log.append(b"abcdef")
    assert log.since(0) == b"abcdef" and log.since(4) == b"ef" and log.since(6) == b""
    log.append(b"ghijkl")
    assert log.end == 12 and log.since(0) == b"efghijkl"  # oldest bytes dropped
    assert log.since(10) == b"kl" and log.since(99) == b""


def test_drop_detaches_and_resume_reattaches_same_shell_with_replay(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    token = start(client, server_id)
    shell = FakeShell.instances[0]
    assert not shell.closed and manager(client).active == 1
    shell.out.put(b"after-drop\r\n")  # produced while nobody is attached
    assert wait_for(lambda: b"after-drop" in manager(client).sessions[0].log.since(0))

    response = ticket(client, server_id, resume=token, cols=90, rows=20)
    assert response.status_code == 200
    with Open(client, response.json()) as ws:
        ready = recv_until(ws, "ready")
        assert ready["resumed"] is True and ready["token"] == token
        seen = recv_bytes_containing(ws, b"after-drop")
        assert b"welcome" in seen  # offset 0: whole buffer replayed
        ws.send_text(json.dumps({"t": "i", "d": "echo $MARK\r"}))
        recv_bytes_containing(ws, b"echo:echo $MARK")
        ws.send_text(json.dumps({"t": "bye"}))
    assert len(FakeShell.instances) == 1  # no second SSH login
    assert (90, 20) in shell.resized
    assert shell.written[-1] == b"echo $MARK\r"
    assert wait_for(lambda: shell.closed) and manager(client).active == 0 and manager(client).sessions == []


def test_resume_replays_only_missing_bytes(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    token = start(client, server_id)
    session = manager(client).sessions[0]
    seen = session.log.end
    FakeShell.instances[0].out.put(b"NEW")
    assert wait_for(lambda: session.log.end == seen + 3)
    with Open(client, ticket(client, server_id, resume=token).json(), offset=seen) as ws:
        recv_until(ws, "ready")
        assert ws.receive()["bytes"] == b"NEW"
        ws.send_text(json.dumps({"t": "bye"}))


def test_resume_rejected_for_wrong_token_or_other_session(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    token = start(client, server_id)
    bad = ticket(client, server_id, resume="x" * 43)
    assert bad.status_code == 410 and bad.json()["expired"] is True
    assert ticket(client, server_id + 1, resume=token).status_code in {404, 410}
    other = TestClient(client.app, base_url=ORIGIN)
    login(other)
    from .test_records import csrf_of_prefixed

    res = other.post(f"/api/servers/{server_id}/terminal", json={"resume": token},
                     headers={"x-csrf-token": csrf_of_prefixed(other)})
    assert res.status_code == 410
    # A resume ticket stolen by another session is useless too.
    data = ticket(client, server_id, resume=token).json()
    with pytest.raises(WebSocketDisconnect) as info:
        with Open(other, data) as ws:
            ws.receive_text()
    assert info.value.code == 1008
    assert not FakeShell.instances[0].closed and len(FakeShell.instances) == 1


def test_logout_closes_detached_sessions(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    token = start(client, server_id)
    from .test_records import csrf_of_prefixed

    csrf = csrf_of_prefixed(client)
    assert client.post("/logout", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert wait_for(lambda: FakeShell.instances[0].closed) and manager(client).active == 0
    login(client)
    assert ticket(client, server_id, resume=token).status_code == 410


def test_bye_closes_for_real(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    with Open(client, data) as ws:
        token = recv_until(ws, "ready")["token"]
        ws.send_text(json.dumps({"t": "bye"}))
    assert wait_for(lambda: FakeShell.instances[0].closed)
    assert manager(client).active == 0
    assert ticket(client, server_id, resume=token).status_code == 410


def test_grace_expiry_closes_detached_shell(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, terminal_resume_seconds=1)
    token = start(client, server_id)
    m = manager(client)
    assert m.reap_interval <= 0.25
    assert wait_for(lambda: FakeShell.instances[0].closed, timeout=4)
    assert m.active == 0 and m.sessions == []
    assert ticket(client, server_id, resume=token).status_code == 410


def test_unload_uses_short_grace(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    with Open(client, ticket(client, server_id).json()) as ws:
        recv_until(ws, "ready")
        ws.send_text(json.dumps({"t": "unload"}))
        recv_bytes_containing(ws, b"welcome")
    m = manager(client)
    assert wait_for(lambda: m.sessions and m.sessions[0].attachment is None)
    assert m.sessions[0].grace is not None and m.sessions[0].grace < m.resume_seconds


def test_second_attach_kicks_first(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    with Open(client, data) as first:
        token = recv_until(first, "ready")["token"]
        with Open(client, ticket(client, server_id, resume=token).json()) as second:
            assert recv_until(second, "ready")["resumed"] is True
            kicked = recv_until(first, "kicked")
            assert "另一个页面" in kicked["m"]
            for _ in range(50):
                message = first.receive()
                if message["type"] == "websocket.close":
                    break
            assert message["type"] == "websocket.close" and message["code"] == 4001
            second.send_text(json.dumps({"t": "i", "d": "still\r"}))
            recv_bytes_containing(second, b"echo:still")
            second.send_text(json.dumps({"t": "bye"}))
    assert len(FakeShell.instances) == 1 and wait_for(lambda: FakeShell.instances[0].closed)


def test_concurrency_cap_counts_detached_sessions(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, max_terminals=1)
    token = start(client, server_id)  # detached, still holds the only slot
    assert manager(client).active == 1
    assert ticket(client, server_id).status_code == 429
    assert ticket(client, server_id, resume=token).status_code == 200  # resuming needs no new slot


def test_heartbeat_pings_and_pong_do_not_reset_idle(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    m = manager(client)
    m.heartbeat = 0.1
    with Open(client, ticket(client, server_id).json()) as ws:
        recv_until(ws, "ready")
        session = m.sessions[0]
        before = session.last_input
        recv_until(ws, "ping")
        recv_until(ws, "ping")
        ws.send_text(json.dumps({"t": "ping"}))
        recv_until(ws, "pong")
        ws.send_text(json.dumps({"t": "pong"}))
        time.sleep(0.15)
        assert session.last_input == before  # heartbeats are not activity
        ws.send_text(json.dumps({"t": "i", "d": "x"}))
        recv_bytes_containing(ws, b"echo:x")
        assert session.last_input > before
        after_input = session.last_input
        ws.send_text(json.dumps({"t": "r", "c": 80, "r": 24}))
        assert wait_for(lambda: session.last_input > after_input)
        ws.send_text(json.dumps({"t": "bye"}))


def test_idle_timeout_closes_even_with_heartbeats(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, terminal_idle_seconds=1)
    m = manager(client)
    m.heartbeat = 0.1
    with Open(client, ticket(client, server_id).json()) as ws:
        recv_until(ws, "ready")
        ws.send_text(json.dumps({"t": "ping"}))
        kinds = []
        for _ in range(200):
            message = ws.receive()
            if message["type"] == "websocket.close":
                break
            if message.get("text"):
                kinds.append(json.loads(message["text"]))
                if kinds[-1]["t"] == "ping":
                    ws.send_text(json.dumps({"t": "pong"}))  # like terminal.js
                if kinds[-1]["t"] == "closed":
                    break
        assert {"ping", "pong"} <= {k["t"] for k in kinds}  # heartbeats flowed until the idle close
        assert kinds[-1]["t"] == "closed" and "没有操作" in kinds[-1]["m"]
    assert FakeShell.instances[0].closed and m.active == 0


def test_remote_exit_closes_and_cannot_resume(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    with Open(client, ticket(client, server_id).json()) as ws:
        token = recv_until(ws, "ready")["token"]
        FakeShell.instances[0].closed = True  # read() -> None, like EOF
        assert "远程会话已结束" in recv_until(ws, "closed")["m"]
    assert manager(client).active == 0
    assert ticket(client, server_id, resume=token).status_code == 410


def test_shutdown_closes_detached_sessions(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    start(client, server_id)
    client.__exit__(None, None, None)  # runs the lifespan shutdown
    assert FakeShell.instances[0].closed


def test_resume_token_never_logged_or_in_url(tmp_path, caplog):
    from pathlib import Path

    caplog.set_level("DEBUG")
    client, server_id, _ = terminal_client(tmp_path)
    token = start(client, server_id)
    data = ticket(client, server_id, resume=token).json()
    assert token not in data["ws_path"] and data["ticket"] != token
    with Open(client, data) as ws:
        recv_until(ws, "ready")
        ws.send_text(json.dumps({"t": "bye"}))
    assert token not in caplog.text
    js = Path("app/static/terminal.js").read_text(encoding="utf-8")
    assert "resume=" not in js.replace("resume: ", "")


def test_silent_client_is_detached_by_server_heartbeat(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    m = manager(client)
    m.heartbeat = 0.1
    with Open(client, ticket(client, server_id).json()) as ws:
        recv_until(ws, "ready")
        # the client never answers: after ~3 heartbeats the server gives up on this socket
        for _ in range(100):
            message = ws.receive()
            if message["type"] == "websocket.close":
                break
        assert message["type"] == "websocket.close" and message["code"] == 4002
        assert wait_for(lambda: m.sessions and m.sessions[0].attachment is None, timeout=3)
        assert not FakeShell.instances[0].closed  # detached, not closed
