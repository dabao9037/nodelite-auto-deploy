from __future__ import annotations

import json
import os
import queue
import stat
import time

import paramiko
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import cli
from app.deployer import DeployHostKeyMismatch, DeploymentError, HostKeyMismatch, PinnedKeyPolicy, fingerprint_sha256
from app.main import create_app
from app.store import ServerStore
from app.terminal import TerminalError

from .conftest import ADMIN, ADMIN_PW, csrf_of, login, make_settings

SSH_PW = "Ssh-Root-Pass-XYZ-123"
PANEL_PW = "NodeLitePw-Secret-98765"
FP = "SHA256:fakefingerprintAAAAAAAAAAAAAAAAAAAAAAAAAAA"
ORIGIN = "http://127.0.0.1:8780"


def result(**extra):
    data = {
        "mode": "install",
        "panel_url": "http://203.0.113.10:45000/panel-abcdef0123456789/login",
        "alt_panel_url": None,
        "username": "admin",
        "password": PANEL_PW,
        "version": "v0.3.33-native",
        "fingerprint": FP,
        "key_type": "ssh-ed25519",
        "ssh_address": "203.0.113.10",
        "os": "Ubuntu",
        "arch": "x86_64",
        "ipv6": {"requested": True, "disabled": True, "message": "IPv6 已关闭"},
        "reachability": {"local": True, "public": None, "public_note": "skip"},
    }
    data.update(extra)
    return data


class FakeDeploy:
    """Simulates deployer.deploy: 'login' via on_connected, then return a result."""

    def __init__(self):
        self.specs: list[dict] = []
        self.fail_before_login: str | None = None
        self.fail_after_login: str | None = None
        self.mismatch = False
        self.warn = False

    def __call__(self, spec, reporter, settings):
        self.specs.append({"password": spec.ssh_password, "expected": spec.expected_fingerprint})
        reporter.stage("connect", "连接中")
        if self.mismatch:
            raise DeployHostKeyMismatch(HostKeyMismatch(spec.expected_fingerprint, "SHA256:newkeyBBBB", "ssh-ed25519"))
        if self.fail_before_login:
            raise DeploymentError(self.fail_before_login)
        spec.ssh_password = None
        spec.on_connected(FP, "ssh-ed25519")
        if self.fail_after_login:
            raise DeploymentError(self.fail_after_login)
        if self.warn:
            reporter.step("ipv6", "warn")
        return result()


def make_client(data_dir, deploy_fn=None, shell_factory=None, **overrides):
    kwargs = {}
    if shell_factory is not None:
        kwargs["shell_factory"] = shell_factory
    app = create_app(make_settings(data_dir=str(data_dir), **overrides), deploy_fn=deploy_fn or FakeDeploy(), **kwargs)
    client = TestClient(app, base_url=ORIGIN)
    # 进入上下文：所有请求共用一个事件循环，后台部署任务才不会随单个请求结束被取消
    client.__enter__()
    return client


def wait_done(client, task_id, prefix=""):
    for _ in range(200):
        body = client.get(f"{prefix}/api/tasks/{task_id}").json()
        if body["status"] in {"success", "failed"}:
            return body
        time.sleep(0.02)
    raise AssertionError("task did not finish")


def deploy(client, prefix="", **extra):
    token = csrf_of_prefixed(client, prefix)
    body = {"host": "8.8.8.8", "ssh_password": SSH_PW, "authorized": True}
    body.update(extra)
    response = client.post(f"{prefix}/api/tasks", json=body, headers={"x-csrf-token": token})
    assert response.status_code == 202, response.text
    return wait_done(client, response.json()["task_id"], prefix)


def csrf_of_prefixed(client, prefix=""):
    if not prefix:
        return csrf_of(client)
    import re

    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(prefix + "/").text).group(1)


def logged_in(data_dir, **kwargs):
    import re

    client = make_client(data_dir, **kwargs)
    prefix = kwargs.get("base_path", "")
    page = client.get(prefix + "/login")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    response = client.post(prefix + "/login", data={"username": ADMIN, "password": ADMIN_PW, "csrf": token},
                           follow_redirects=False)
    assert response.headers["location"] == prefix + "/"
    return client


# --- persistence and encryption ------------------------------------------------------


def test_record_persists_across_restart_and_has_no_secrets(tmp_path):
    client = logged_in(tmp_path)
    body = deploy(client)
    assert body["status"] == "success" and body["result"]["server_id"]
    client.__exit__(None, None, None)

    again = logged_in(tmp_path)  # a brand new app instance = restart
    servers = again.get("/api/servers").json()["servers"]
    assert len(servers) == 1
    record = servers[0]
    assert record["host"] == "8.8.8.8" and record["ssh_port"] == 22 and record["ssh_user"] == "root"
    assert record["fingerprint"] == FP and record["panel_user"] == "admin"
    assert record["panel_url"].startswith("http://203.0.113.10") and record["version"] == "v0.3.33-native"
    assert record["last_status"] == "success" and record["first_deploy_at"] and record["ipv6_status"]
    assert record["has_ssh_password"] is True and record["has_panel_password"] is True
    listing = again.get("/api/servers").text + again.get(f"/api/servers/{record['id']}").text
    assert SSH_PW not in listing and PANEL_PW not in listing and "_enc" not in listing


def test_secrets_encrypted_at_rest_and_file_modes(tmp_path):
    client = logged_in(tmp_path)
    deploy(client)
    client.__exit__(None, None, None)
    raw = (tmp_path / "data.db").read_bytes()
    assert raw  # really written
    assert SSH_PW.encode() not in raw and PANEL_PW.encode() not in raw
    assert b"8.8.8.8" in raw  # non-secret fields are plain
    for name in ("data.db", "secret.key"):
        mode = stat.S_IMODE(os.stat(tmp_path / name).st_mode)
        assert mode == 0o600, (name, oct(mode))
    assert len((tmp_path / "secret.key").read_bytes()) == 32
    # Same key decrypts after restart; a different key cannot.
    store = ServerStore(tmp_path)
    server_id = store.list()[0]["id"]
    assert store.ssh_password(server_id) == SSH_PW and store.panel_password(server_id) == PANEL_PW
    store.close()
    (tmp_path / "secret.key").write_bytes(os.urandom(32))
    store = ServerStore(tmp_path)
    with pytest.raises(Exception):
        store.ssh_password(server_id)
    store.close()


def test_corrupt_key_file_refuses_to_start(tmp_path):
    (tmp_path / "secret.key").write_bytes(b"short")
    with pytest.raises(RuntimeError):
        ServerStore(tmp_path)


def test_ciphertext_bound_to_record(tmp_path):
    store = ServerStore(tmp_path)
    a = store.ensure_server("1.1.1.1", 22, "root", FP, "ssh-ed25519")
    b = store.ensure_server("1.1.1.2", 22, "root", FP, "ssh-ed25519")
    store.set_ssh_password(a, "pw-a-123456")
    with store._lock:
        store._db.execute("UPDATE servers SET ssh_password_enc=(SELECT ssh_password_enc FROM servers WHERE id=?) "
                          "WHERE id=?", (a, b))
    with pytest.raises(Exception):
        store.ssh_password(b)
    store.close()


def test_save_password_unchecked_does_not_store(tmp_path):
    client = logged_in(tmp_path)
    deploy(client, save_password=False)
    record = client.get("/api/servers").json()["servers"][0]
    assert record["has_ssh_password"] is False and record["has_panel_password"] is True


def test_redeploy_updates_same_record_uses_saved_password_and_pins_key(tmp_path):
    fake = FakeDeploy()
    client = logged_in(tmp_path, deploy_fn=fake)
    deploy(client)
    second = deploy(client, ssh_password=None)  # 重新部署：密码留空
    assert second["status"] == "success"
    assert fake.specs[0] == {"password": SSH_PW, "expected": ""}
    assert fake.specs[1] == {"password": SSH_PW, "expected": FP}  # saved password + pinned key
    servers = client.get("/api/servers").json()["servers"]
    assert len(servers) == 1
    history = client.get(f"/api/servers/{servers[0]['id']}/history").json()["history"]
    assert [h["status"] for h in history] == ["success", "success"]


def test_no_saved_password_requires_one(tmp_path):
    client = logged_in(tmp_path)
    token = csrf_of(client)
    response = client.post("/api/tasks", json={"host": "8.8.8.8", "authorized": True}, headers={"x-csrf-token": token})
    assert response.status_code == 422 and "SSH 密码" in response.json()["detail"]


def test_failed_before_login_creates_no_record_but_history(tmp_path):
    fake = FakeDeploy()
    fake.fail_before_login = "SSH 认证失败：用户名或密码错误"
    client = logged_in(tmp_path, deploy_fn=fake)
    assert deploy(client)["status"] == "failed"
    assert client.get("/api/servers").json()["servers"] == []
    store = client.app.state.core.store
    with store._lock:
        rows = store._db.execute("SELECT status, error FROM history").fetchall()
    assert [r["status"] for r in rows] == ["failed"] and "认证失败" in rows[0]["error"]


def test_failed_after_login_keeps_record_with_history(tmp_path):
    fake = FakeDeploy()
    client = logged_in(tmp_path, deploy_fn=fake)
    deploy(client)
    fake.fail_after_login = "NodeLite 安装失败（退出码 1）"
    assert deploy(client)["status"] == "failed"
    record = client.get("/api/servers").json()["servers"][0]
    assert record["last_status"] == "failed" and record["panel_user"] == "admin"
    history = client.get(f"/api/servers/{record['id']}/history").json()["history"]
    assert history[0]["status"] == "failed" and "安装失败" in history[0]["error"]


def test_warning_deploy_is_recorded_as_warn(tmp_path):
    fake = FakeDeploy()
    fake.warn = True
    client = logged_in(tmp_path, deploy_fn=fake)
    deploy(client)
    assert client.get("/api/servers").json()["servers"][0]["last_status"] == "warn"


# --- reveal / delete -----------------------------------------------------------------


def test_reveal_requires_session_and_csrf(tmp_path):
    client = logged_in(tmp_path)
    deploy(client)
    server_id = client.get("/api/servers").json()["servers"][0]["id"]
    token = csrf_of(client)
    assert client.post(f"/api/servers/{server_id}/reveal").status_code == 403
    assert client.post(f"/api/servers/{server_id}/reveal", headers={"x-csrf-token": "x"}).status_code == 403
    assert client.get(f"/api/servers/{server_id}/reveal").status_code == 405
    cross = client.post(f"/api/servers/{server_id}/reveal",
                        headers={"x-csrf-token": token, "origin": "https://evil.example"})
    assert cross.status_code == 403
    ok = client.post(f"/api/servers/{server_id}/reveal", headers={"x-csrf-token": token})
    assert ok.status_code == 200 and ok.json() == {"password": PANEL_PW}
    anon = make_client(tmp_path)
    assert anon.post(f"/api/servers/{server_id}/reveal", headers={"x-csrf-token": token}).status_code == 401
    assert anon.get("/api/servers").status_code == 401


def test_forget_ssh_password_and_delete_record(tmp_path):
    client = logged_in(tmp_path)
    deploy(client)
    server_id = client.get("/api/servers").json()["servers"][0]["id"]
    token = csrf_of(client)
    assert client.delete(f"/api/servers/{server_id}/ssh-password").status_code == 403
    assert client.delete(f"/api/servers/{server_id}/ssh-password", headers={"x-csrf-token": token}).status_code == 200
    record = client.get(f"/api/servers/{server_id}").json()
    assert record["has_ssh_password"] is False and record["has_panel_password"] is True
    assert client.delete(f"/api/servers/{server_id}").status_code == 403
    assert client.delete(f"/api/servers/{server_id}", headers={"x-csrf-token": token}).status_code == 200
    assert client.get("/api/servers").json()["servers"] == []
    assert client.get(f"/api/servers/{server_id}").status_code == 404
    store = client.app.state.core.store
    with store._lock:
        assert store._db.execute("SELECT COUNT(*) FROM history").fetchone()[0] == 0


def test_cli_forget_passwords(tmp_path, monkeypatch, capsys):
    client = logged_in(tmp_path)
    deploy(client)
    client.__exit__(None, None, None)
    monkeypatch.setenv("WEB_DATA_DIR", str(tmp_path))
    assert cli.main(["forget-passwords"]) == 0
    assert "1" in capsys.readouterr().out
    store = ServerStore(tmp_path)
    record = store.list()[0]
    assert record["has_ssh_password"] is False and store.panel_password(record["id"]) == PANEL_PW
    store.close()
    assert SSH_PW.encode() not in (tmp_path / "data.db").read_bytes()


# --- host key pinning ----------------------------------------------------------------


def test_pinned_policy_accepts_match_and_refuses_mismatch():
    key = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    PinnedKeyPolicy(fingerprint_sha256(key)).missing_host_key(None, "h", key)
    with pytest.raises(HostKeyMismatch) as info:
        PinnedKeyPolicy(fingerprint_sha256(key)).missing_host_key(None, "h", other)
    assert info.value.actual == fingerprint_sha256(other)
    with pytest.raises(HostKeyMismatch):
        PinnedKeyPolicy("").missing_host_key(None, "h", key)


def test_deploy_host_key_mismatch_refused_then_trust_new_key(tmp_path):
    fake = FakeDeploy()
    client = logged_in(tmp_path, deploy_fn=fake)
    deploy(client)
    fake.mismatch = True
    body = deploy(client)
    assert body["status"] == "failed" and "主机密钥" in body["error"] and "信任新密钥" in body["error"]
    record = client.get("/api/servers").json()["servers"][0]
    assert record["fingerprint"] == FP and record["pending_fingerprint"] == "SHA256:newkeyBBBB"
    assert record["last_status"] == "failed"
    token = csrf_of(client)
    url = f"/api/servers/{record['id']}/trust-key"
    assert client.post(url, json={"fingerprint": "SHA256:newkeyBBBB"}).status_code == 403
    wrong = client.post(url, json={"fingerprint": "SHA256:somethingelse"}, headers={"x-csrf-token": token})
    assert wrong.status_code == 409
    ok = client.post(url, json={"fingerprint": "SHA256:newkeyBBBB"}, headers={"x-csrf-token": token})
    assert ok.status_code == 200 and ok.json()["fingerprint"] == "SHA256:newkeyBBBB"
    assert ok.json()["pending_fingerprint"] == ""
    fake.mismatch = False
    deploy(client, ssh_password=None)
    assert fake.specs[-1]["expected"] == "SHA256:newkeyBBBB"


# --- web terminal --------------------------------------------------------------------


class FakeShell:
    instances: list = []
    mode = "ok"

    def __init__(self, addresses, port, user, fingerprint, timeout):
        self.args = (addresses, port, user, fingerprint)
        self.out: queue.Queue = queue.Queue()
        self.written: list[bytes] = []
        self.resized: list[tuple[int, int]] = []
        self.password = None
        self.closed = False
        FakeShell.instances.append(self)

    def open(self, password, cols, rows):
        self.password = password
        if FakeShell.mode == "mismatch":
            raise HostKeyMismatch(self.args[3], "SHA256:otherKEY", "ssh-ed25519")
        if FakeShell.mode == "auth":
            raise TerminalError("SSH 认证失败：密码错误或服务器禁用了密码登录")
        self.resized.append((cols, rows))
        self.out.put(b"welcome\r\n")

    def read(self):
        if self.closed:
            return None
        try:
            return self.out.get(timeout=0.05)
        except queue.Empty:
            return b""

    def write(self, data):
        self.written.append(data)
        self.out.put(b"echo:" + data)

    def resize(self, cols, rows):
        self.resized.append((cols, rows))

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_shell():
    FakeShell.instances.clear()
    FakeShell.mode = "ok"


def terminal_client(tmp_path, save_password=True, **overrides):
    client = logged_in(tmp_path, shell_factory=FakeShell, **overrides)
    prefix = overrides.get("base_path", "")
    deploy(client, prefix=prefix, save_password=save_password)
    server_id = client.get(f"{prefix}/api/servers").json()["servers"][0]["id"]
    return client, server_id, prefix


class _Conn:
    """Opens the terminal WebSocket and sends the ticket as the first message (like terminal.js)."""

    def __init__(self, client, path, headers):
        self.client, self.path, self.headers = client, path, headers

    def __enter__(self):
        url, _, query = self.path.partition("?ticket=")
        self.cm = self.client.websocket_connect(url, headers=self.headers)
        ws = self.cm.__enter__()
        ws.send_text(json.dumps({"t": "auth", "ticket": query}))
        return ws

    def __exit__(self, *exc):
        return self.cm.__exit__(*exc)


def ws_open(client, path, headers):
    return _Conn(client, path, headers)


def ticket(client, server_id, prefix="", **body):
    token = csrf_of_prefixed(client, prefix)
    return client.post(f"{prefix}/api/servers/{server_id}/terminal", json=body, headers={"x-csrf-token": token})


def recv_until(ws, kind):
    for _ in range(50):
        message = ws.receive()
        if message.get("text"):
            body = json.loads(message["text"])
            if body["t"] == kind:
                return body
    raise AssertionError(f"no {kind}")


def recv_bytes_containing(ws, needle: bytes):
    seen = b""
    for _ in range(50):
        message = ws.receive()
        seen += message.get("bytes") or b""
        if needle in seen:
            return seen
    raise AssertionError(seen)


def test_terminal_full_flow_uses_saved_password_and_resize(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    response = ticket(client, server_id, cols=100, rows=30)
    assert response.status_code == 200
    data = response.json()
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        recv_until(ws, "ready")
        recv_bytes_containing(ws, b"welcome")
        ws.send_text(json.dumps({"t": "i", "d": "echo hello\r"}))
        recv_bytes_containing(ws, b"echo:echo hello")
        ws.send_text(json.dumps({"t": "r", "c": 9999, "r": 50}))
        ws.send_bytes(b"x")
        recv_bytes_containing(ws, b"echo:x")
        ws.send_text(json.dumps({"t": "bye"}))
    shell = FakeShell.instances[0]
    assert shell.password == SSH_PW and shell.args[3] == FP and shell.args[0] == ("8.8.8.8",)
    assert shell.resized[0] == (100, 30) and (500, 50) in shell.resized  # clamped
    for _ in range(250):
        if shell.closed:
            break
        time.sleep(0.02)
    assert shell.closed and client.app.state.core.terminals == 0


def test_ticket_is_single_use(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    url = f"{data['ws_path']}?ticket={data['ticket']}"
    with ws_open(client, "ws://127.0.0.1:8780" + url, headers={"origin": ORIGIN}) as ws:
        recv_until(ws, "ready")
        ws.send_text(json.dumps({"t": "bye"}))
    with pytest.raises(WebSocketDisconnect) as info:
        with ws_open(client, "ws://127.0.0.1:8780" + url, headers={"origin": ORIGIN}) as ws:
            ws.receive_text()
    assert info.value.code == 1008


def test_ticket_requires_csrf_and_is_session_bound(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    assert client.post(f"/api/servers/{server_id}/terminal", json={}).status_code == 403
    data = ticket(client, server_id).json()
    other = TestClient(client.app, base_url=ORIGIN)  # same app, different session
    login(other)
    with pytest.raises(WebSocketDisconnect) as info:
        with ws_open(other, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
            ws.receive_text()
    assert info.value.code == 1008
    # Burned by the failed attempt, so the rightful owner cannot reuse it either.
    with pytest.raises(WebSocketDisconnect):
        with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
            ws.receive_text()


@pytest.mark.parametrize("headers", [
    {"origin": "https://evil.example"},
    {"origin": "http://127.0.0.1:9999"},
    {"origin": "null", "sec-fetch-site": "cross-site"},
    {},
])
def test_ws_rejects_bad_origin(tmp_path, headers):
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    with pytest.raises(WebSocketDisconnect) as info:
        with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers=headers) as ws:
            ws.receive_text()
    assert info.value.code == 1008
    assert FakeShell.instances == []


def test_ws_rejects_missing_session(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    anon = TestClient(client.app, base_url=ORIGIN)  # same app, no session cookie
    with pytest.raises(WebSocketDisconnect) as info:
        with ws_open(anon, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
            ws.receive_text()
    assert info.value.code == 1008
    with pytest.raises(WebSocketDisconnect):  # no ticket at all
        with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket=", headers={"origin": ORIGIN}) as ws:
            ws.receive_text()
    assert FakeShell.instances == []


def test_terminal_without_saved_password_prompts_then_one_time_password(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, save_password=False)
    first = ticket(client, server_id)
    assert first.status_code == 409 and first.json()["need_password"] is True
    data = ticket(client, server_id, ssh_password="typed-once-pw").json()
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        assert recv_until(ws, "ready")["saved"] is False
        ws.send_text(json.dumps({"t": "bye"}))
    assert FakeShell.instances[0].password == "typed-once-pw"
    assert client.get(f"/api/servers/{server_id}").json()["has_ssh_password"] is False
    # Ticking "save" stores it after a successful login.
    data = ticket(client, server_id, ssh_password="typed-and-saved", save_password=True).json()
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        assert recv_until(ws, "ready")["saved"] is True
        ws.send_text(json.dumps({"t": "bye"}))
    assert client.app.state.core.store.ssh_password(server_id) == "typed-and-saved"


def test_terminal_host_key_mismatch_refused(tmp_path):
    client, server_id, _ = terminal_client(tmp_path)
    FakeShell.mode = "mismatch"
    data = ticket(client, server_id).json()
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        body = recv_until(ws, "hostkey")
    assert body["expected"] == FP and body["actual"] == "SHA256:otherKEY"
    record = client.get(f"/api/servers/{server_id}").json()
    assert record["fingerprint"] == FP and record["pending_fingerprint"] == "SHA256:otherKEY"


def test_terminal_auth_failure_does_not_save(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, save_password=False)
    FakeShell.mode = "auth"
    data = ticket(client, server_id, ssh_password="wrong-pw", save_password=True).json()
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        body = recv_until(ws, "error")
    assert body["need_password"] is True
    assert client.get(f"/api/servers/{server_id}").json()["has_ssh_password"] is False


def test_terminal_concurrency_cap(tmp_path):
    client, server_id, _ = terminal_client(tmp_path, max_terminals=1)
    client.app.state.core.terminals = 1
    assert ticket(client, server_id).status_code == 429


def test_terminal_under_base_path(tmp_path):
    client, server_id, prefix = terminal_client(tmp_path, base_path="/p4th")
    page = client.get(f"/p4th/terminal/{server_id}")
    assert page.status_code == 200
    assert 'src="/p4th/static/vendor/xterm/xterm.js"' in page.text
    assert '<meta name="base-path" content="/p4th">' in page.text
    csp = page.headers["content-security-policy"]
    assert "style-src 'self' 'nonce-" in csp and "unsafe-inline" not in csp
    assert "ws://127.0.0.1:8780" in csp and "wss://127.0.0.1:8780" in csp
    assert client.get("/p4th/static/vendor/xterm/xterm.css").status_code == 200
    assert client.get(f"/terminal/{server_id}").status_code == 404
    data = ticket(client, server_id, prefix=prefix).json()
    assert data["ws_path"] == f"/p4th/api/servers/{server_id}/terminal/ws"
    with ws_open(client, f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}", headers={"origin": ORIGIN}) as ws:
        recv_until(ws, "ready")
        ws.send_text(json.dumps({"t": "bye"}))


def test_hidden_attribute_wins_over_layout_css():
    from pathlib import Path

    assert "[hidden] { display: none !important; }" in Path("app/static/style.css").read_text(encoding="utf-8")


def test_csp_host_header_injection_ignored(tmp_path):
    client = make_client(tmp_path)
    csp = client.get("/login", headers={"host": "evil; script-src *"}).headers["content-security-policy"]
    assert "script-src 'self'" in csp and "evil" not in csp


def test_main_page_has_records_tab_and_save_checkbox(tmp_path):
    client = logged_in(tmp_path)
    page = client.get("/").text
    assert "服务器记录" in page and 'id="save_password" name="save_password" checked' in page
    assert "保存 SSH 密码（加密存储，用于以后一键连接）" in page
    for label in ("连接服务器", "重新部署", "查看历史", "删除记录"):
        assert label in page
    assert ADMIN and ADMIN_PW


def test_ws_ticket_never_in_url_and_auth_message_required(tmp_path):
    from pathlib import Path

    assert "?ticket=" not in Path("app/static/terminal.js").read_text(encoding="utf-8")
    client, server_id, _ = terminal_client(tmp_path)
    data = ticket(client, server_id).json()
    # Ticket in the query string is ignored: the server waits for the auth message.
    with pytest.raises(WebSocketDisconnect) as info:
        with client.websocket_connect(f"ws://127.0.0.1:8780{data['ws_path']}?ticket={data['ticket']}",
                                      headers={"origin": ORIGIN}) as ws:
            ws.send_text(json.dumps({"t": "i", "d": "ls\r"}))
            ws.receive_text()
    assert info.value.code == 1008 and FakeShell.instances == []
