from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

WEAK_PASSWORDS = {"password", "changeme", "admin123456", "replace-with-at-least-14-random-characters"}


def _flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc
    return max(low, min(value, high))


def is_loopback_host(host: str) -> bool:
    if host in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Settings:
    admin_user: str
    admin_password: str
    session_secret: str
    cookie_secure: bool
    allow_private_targets: bool
    target_allowlist: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    max_concurrent_tasks: int
    task_ttl_seconds: int
    session_ttl_seconds: int
    login_attempts: int
    login_window_seconds: int
    task_attempts: int
    task_window_seconds: int
    ssh_connect_timeout: float
    install_timeout: int
    listen_host: str
    listen_port: int
    allow_public_listen: bool
    nodelite_installer_url: str

    @classmethod
    def load(cls) -> "Settings":
        user = os.getenv("WEB_ADMIN_USER", "").strip()
        password = os.getenv("WEB_ADMIN_PASSWORD", "")
        secret = os.getenv("WEB_SESSION_SECRET", "")
        if not user or len(user) > 64:
            raise RuntimeError("WEB_ADMIN_USER 必须配置（1-64 个字符）")
        if len(password) < 14 or password.lower() in WEAK_PASSWORDS:
            raise RuntimeError("WEB_ADMIN_PASSWORD 必须是至少 14 位的强密码")
        if len(secret) < 32 or len(set(secret)) < 12:
            raise RuntimeError("WEB_SESSION_SECRET 至少需要 32 个高熵字符")
        allowlist_raw = os.getenv("TARGET_ALLOWLIST_CIDRS", "").strip()
        try:
            allowlist = tuple(
                ipaddress.ip_network(item.strip(), strict=False)
                for item in allowlist_raw.split(",")
                if item.strip()
            )
        except ValueError as exc:
            raise RuntimeError("TARGET_ALLOWLIST_CIDRS 包含无效 CIDR") from exc
        try:
            timeout = max(3.0, min(float(os.getenv("SSH_CONNECT_TIMEOUT", "15")), 120.0))
        except ValueError as exc:
            raise RuntimeError("SSH_CONNECT_TIMEOUT 必须是数字") from exc
        settings = cls(
            admin_user=user,
            admin_password=password,
            session_secret=secret,
            cookie_secure=_flag("WEB_COOKIE_SECURE", False),
            allow_private_targets=_flag("ALLOW_PRIVATE_TARGETS", False),
            target_allowlist=allowlist,
            max_concurrent_tasks=_int("MAX_CONCURRENT_TASKS", 2, 1, 16),
            task_ttl_seconds=_int("TASK_RESULT_TTL_SECONDS", 900, 60, 86400),
            session_ttl_seconds=_int("WEB_SESSION_TTL_SECONDS", 28800, 300, 604800),
            login_attempts=_int("LOGIN_RATE_LIMIT", 5, 1, 100),
            login_window_seconds=_int("LOGIN_RATE_WINDOW_SECONDS", 300, 10, 86400),
            task_attempts=_int("TASK_RATE_LIMIT", 5, 1, 100),
            task_window_seconds=_int("TASK_RATE_WINDOW_SECONDS", 300, 10, 86400),
            ssh_connect_timeout=timeout,
            install_timeout=_int("INSTALL_TIMEOUT_SECONDS", 1500, 120, 7200),
            listen_host=os.getenv("WEB_LISTEN_HOST", "127.0.0.1").strip(),
            listen_port=_int("WEB_LISTEN_PORT", 8780, 1, 65535),
            allow_public_listen=_flag("WEB_ALLOW_PUBLIC_LISTEN", False),
            nodelite_installer_url=os.getenv(
                "NODELITE_INSTALLER_URL",
                "https://raw.githubusercontent.com/dabao9037/nodelite/main/install.sh",
            ).strip(),
        )
        if not is_loopback_host(settings.listen_host) and not settings.allow_public_listen:
            raise RuntimeError(
                "WEB_LISTEN_HOST 不是回环地址；本程序处理 root 密码，"
                "如确需公网监听请设置 WEB_ALLOW_PUBLIC_LISTEN=1 并配合 HTTPS"
            )
        if not settings.nodelite_installer_url.startswith("https://"):
            raise RuntimeError("NODELITE_INSTALLER_URL 必须是 https 地址")
        return settings
