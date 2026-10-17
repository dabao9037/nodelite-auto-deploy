from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.deployer import DeploymentError
from app.main import create_app

from .conftest import ADMIN_PW, csrf_of, login, make_settings

SSH_PW = "Ssh-Root-Pass-XYZ-123"
FAKE_RESULT = {
    "mode": "install",
    "panel_url": "http://203.0.113.10:45000/panel-abcdef0123456789/login",
    "alt_panel_url": None,
    "username": "admin",
    "password": "NodeLitePw123456",
    "version": "v0.3.33-native",
    "fingerprint": "SHA256:abc",
    "key_type": "ssh-ed25519",
    "ssh_address": "203.0.113.10",
    "os": "Ubuntu",
    "arch": "x86_64",
    "ipv6": {"requested": True, "disabled": True, "message": "ok"},
    "reachability": {"local": True, "public": None, "public_note": "skip"},
}


def client_for(deploy_fn=None, **overrides) -> tuple[TestClient, list]:
    calls: list = []

    def fake_deploy(spec, reporter, settings):
        calls.append(
            {
                "host": spec.host,
                "port": spec.ssh_port,
                "user": spec.ssh_user,
                "password": spec.ssh_password,
                "ipv6": spec.disable_ipv6,
                "typed_ipv6": spec.typed_ipv6,
            }
        )
        reporter.stage("connect", "连接中")
        reporter.log("hello")
        return dict(FAKE_RESULT)

    app = create_app(make_settings(**overrides), deploy_fn=deploy_fn or fake_deploy)
    return TestClient(app, base_url="http://127.0.0.1:8780"), calls


def wait_done(client, task_id):
    for _ in range(100):
        body = client.get(f"/api/tasks/{task_id}").json()
        if body["status"] in {"success", "failed"}:
            return body
        time.sleep(0.02)
    raise AssertionError("task did not finish")


def payload(**extra):
    data = {"host": "8.8.8.8", "ssh_password": SSH_PW, "authorized": True}
    data.update(extra)
    return data


def test_requires_login():
    client, _ = client_for()
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/api/tasks/x").status_code == 401
    assert client.post("/api/tasks", json=payload()).status_code == 401


def test_login_wrong_password_and_rate_limit():
    client, _ = client_for(login_attempts=3)
    for _ in range(3):
        response = login(client, password="wrong-password-1234")
        assert response.headers["location"] == "/login?error=1"
    assert login(client).headers["location"] == "/login?error=2"


def test_login_requires_csrf_nonce():
    client, _ = client_for()
    client.get("/login")
    response = client.post(
        "/login", data={"username": "admin", "password": ADMIN_PW, "csrf": "bogus"}, follow_redirects=False
    )
    assert response.headers["location"] == "/login?error=3"


def test_login_sets_strict_httponly_cookie():
    client, _ = client_for()
    response = login(client)
    assert response.status_code == 303 and response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_task_requires_csrf_header():
    client, calls = client_for()
    login(client)
    assert client.post("/api/tasks", json=payload()).status_code == 403
    assert client.post("/api/tasks", json=payload(), headers={"x-csrf-token": "nope"}).status_code == 403
    assert calls == []


def test_cross_origin_post_rejected():
    client, _ = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post(
        "/api/tasks", json=payload(), headers={"x-csrf-token": token, "origin": "https://evil.example"}
    )
    assert response.status_code == 403


def test_full_task_flow_defaults_and_result():
    client, calls = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post(
        "/api/tasks", json=payload(ssh_port="", ssh_user=""), headers={"x-csrf-token": token}
    )
    assert response.status_code == 202, response.text
    assert SSH_PW not in response.text
    body = wait_done(client, response.json()["task_id"])
    assert body["status"] == "success"
    assert body["result"]["password"] == "NodeLitePw123456"
    assert "hello" in body["logs"]
    assert calls[0]["port"] == 22 and calls[0]["user"] == "root" and calls[0]["ipv6"] is True
    assert calls[0]["password"] == SSH_PW
    # Incremental log polling
    again = client.get(f"/api/tasks/{body['id']}?since={body['log_next']}").json()
    assert again["logs"] == []


def test_task_is_session_bound_and_deletable():
    client, _ = client_for()
    login(client)
    token = csrf_of(client)
    task_id = client.post("/api/tasks", json=payload(), headers={"x-csrf-token": token}).json()["task_id"]
    wait_done(client, task_id)
    other = TestClient(client.app, base_url="http://127.0.0.1:8780")
    login(other)
    assert other.get(f"/api/tasks/{task_id}").status_code == 404
    assert client.delete(f"/api/tasks/{task_id}").status_code == 403
    assert client.delete(f"/api/tasks/{task_id}", headers={"x-csrf-token": token}).status_code == 200
    assert client.get(f"/api/tasks/{task_id}").status_code == 404


def test_authorization_checkbox_required():
    client, calls = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post("/api/tasks", json=payload(authorized=False), headers={"x-csrf-token": token})
    assert response.status_code == 422 and calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"ssh_port": 0},
        {"ssh_port": 70000},
        {"ssh_port": "abc"},
        {"ssh_user": "root;rm -rf /"},
        {"ssh_user": "$(id)"},
        {"host": "evil host"},
        {"host": "1.2.3.4; id"},
        {"host": "http://203.0.113.10"},
    ],
)
def test_input_validation_never_echoes_password(extra):
    client, calls = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post("/api/tasks", json=payload(**extra), headers={"x-csrf-token": token})
    assert response.status_code == 422
    assert SSH_PW not in response.text
    assert calls == []


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"])
def test_private_targets_rejected_by_default(host):
    client, calls = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post("/api/tasks", json=payload(host=host), headers={"x-csrf-token": token})
    assert response.status_code == 422 and calls == []


def test_private_targets_allowed_when_enabled_but_never_loopback():
    client, calls = client_for(allow_private_targets=True)
    login(client)
    token = csrf_of(client)
    ok = client.post("/api/tasks", json=payload(host="10.0.0.5"), headers={"x-csrf-token": token})
    assert ok.status_code == 202
    bad = client.post("/api/tasks", json=payload(host="127.0.0.1"), headers={"x-csrf-token": token})
    assert bad.status_code == 422


def test_allowlist_enforced():
    import ipaddress

    client, _ = client_for(target_allowlist=(ipaddress.ip_network("1.1.1.0/24"),))
    login(client)
    token = csrf_of(client)
    assert client.post("/api/tasks", json=payload(), headers={"x-csrf-token": token}).status_code == 422
    good = client.post("/api/tasks", json=payload(host="1.1.1.1"), headers={"x-csrf-token": token})
    assert good.status_code == 202


def test_ipv6_literal_flagged():
    client, calls = client_for()
    login(client)
    token = csrf_of(client)
    response = client.post("/api/tasks", json=payload(host="2001:4860:4860::8888"), headers={"x-csrf-token": token})
    assert response.status_code == 202
    wait_done(client, response.json()["task_id"])
    assert calls[0]["typed_ipv6"] is True


def test_failed_task_error_is_reported():
    def failing(spec, reporter, settings):
        reporter.stage("install", "安装中")
        raise DeploymentError("NodeLite 安装失败")

    client, _ = client_for(deploy_fn=failing)
    login(client)
    token = csrf_of(client)
    task_id = client.post("/api/tasks", json=payload(), headers={"x-csrf-token": token}).json()["task_id"]
    body = wait_done(client, task_id)
    assert body["status"] == "failed" and body["result"] is None
    assert body["steps"]["install"] == "failed"
    assert "NodeLite 安装失败" in body["error"]


def test_unexpected_exception_is_sanitized():
    def boom(spec, reporter, settings):
        raise RuntimeError(f"leak {SSH_PW}")

    client, _ = client_for(deploy_fn=boom)
    login(client)
    token = csrf_of(client)
    task_id = client.post("/api/tasks", json=payload(), headers={"x-csrf-token": token}).json()["task_id"]
    body = wait_done(client, task_id)
    assert SSH_PW not in str(body)


def test_task_rate_limit():
    client, _ = client_for(task_attempts=2)
    login(client)
    token = csrf_of(client)
    codes = [client.post("/api/tasks", json=payload(), headers={"x-csrf-token": token}).status_code for _ in range(3)]
    assert codes[-1] == 429


def test_security_headers_present():
    client, _ = client_for()
    response = client.get("/login")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"


def test_settings_reject_weak_and_public_listen(monkeypatch):
    base = {
        "WEB_ADMIN_USER": "admin",
        "WEB_ADMIN_PASSWORD": "Strong-Password-123",
        "WEB_SESSION_SECRET": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
    }
    for key, value in base.items():
        monkeypatch.setenv(key, value)
    assert Settings.load().listen_host == "127.0.0.1"
    monkeypatch.setenv("WEB_LISTEN_HOST", "0.0.0.0")
    with pytest.raises(RuntimeError):
        Settings.load()
    monkeypatch.setenv("WEB_ALLOW_PUBLIC_LISTEN", "1")
    assert Settings.load().listen_host == "0.0.0.0"
    monkeypatch.setenv("WEB_ADMIN_PASSWORD", "short")
    with pytest.raises(RuntimeError):
        Settings.load()


def test_static_assets_have_no_browser_storage():
    from pathlib import Path

    js = Path("app/static/app.js").read_text(encoding="utf-8")
    assert "localStorage" not in js and "sessionStorage" not in js
