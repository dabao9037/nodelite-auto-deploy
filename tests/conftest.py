from __future__ import annotations

import re
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.config import Settings

ADMIN = "admin"
ADMIN_PW = "Correct-Horse-Battery-9"


def make_settings(**overrides) -> Settings:
    values = dict(
        admin_user=ADMIN,
        admin_password=ADMIN_PW,
        session_secret="s3cr3t-session-key-abcdefghijklmnopqrstuvwxyz-0123456789",
        cookie_secure=False,
        allow_private_targets=False,
        target_allowlist=(),
        max_concurrent_tasks=2,
        task_ttl_seconds=900,
        session_ttl_seconds=3600,
        login_attempts=5,
        login_window_seconds=300,
        task_attempts=5,
        task_window_seconds=300,
        ssh_connect_timeout=5.0,
        install_timeout=600,
        listen_host="127.0.0.1",
        listen_port=8780,
        allow_public_listen=False,
        nodelite_installer_url="https://raw.githubusercontent.com/dabao9037/nodelite/main/install.sh",
        # 每个测试实例独立的数据目录，绝不碰 /var/lib
        data_dir=tempfile.mkdtemp(prefix="nlad-test-"),
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


def login(client: TestClient, username: str = ADMIN, password: str = ADMIN_PW):
    page = client.get("/login")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf": token},
        follow_redirects=False,
    )


def csrf_of(client: TestClient) -> str:
    page = client.get("/")
    return re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
