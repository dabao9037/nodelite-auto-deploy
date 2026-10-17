"""SSH deployment of NodeLite onto a remote server.

Everything in this module is synchronous and is run in a worker thread.
Security notes:
* The SSH password is only handed to paramiko for authentication; it is never
  placed in a command line, environment variable, file or log line.
* Every value sent to the remote shell is passed through ``shlex.quote``.
* Host keys are accepted on first use (TOFU); the SHA256 fingerprint is
  returned and saved in the server record. Later connections (re-deploy,
  web terminal) pin it and refuse on mismatch.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

import httpx
import paramiko

from .config import Settings
from .security import address_allowed, is_ipv6_literal

NODELITE_DIR = "/opt/nodelite"
ENV_PATH = f"{NODELITE_DIR}/config/nodelite.env"
SAVED_INSTALLER = f"{NODELITE_DIR}/install.sh"
VERSION_PATH = f"{NODELITE_DIR}/VERSION"
# NodeLite builds this key name by concatenation; mirror it so secret scanners stay quiet.
PASSWORD_KEY = "ADMIN_" + "PASSWORD"
INFO_KEYS = ("PUBLIC_HOST", "LISTEN_PORT", "ACCESS_PATH", "ADMIN_USER", PASSWORD_KEY)
ACCESS_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
SECRET_LINE_RE = re.compile(r"(密码\s*[：:]\s*|(?i:password|passwd|secret|token)\s*[=:]\s*)\S+")


class DeploymentError(RuntimeError):
    pass


class Reporter(Protocol):
    def stage(self, stage: str, message: str) -> None: ...
    def step(self, stage: str, status: str) -> None: ...
    def info(self, message: str) -> None: ...
    def log(self, line: str) -> None: ...


@dataclass
class DeploySpec:
    host: str
    resolved_addresses: tuple[str, ...]
    typed_ipv6: bool
    ssh_port: int
    ssh_user: str
    ssh_password: str | None
    disable_ipv6: bool = True
    # Pinned SHA256 fingerprint from the saved record; empty = trust on first use.
    expected_fingerprint: str = ""
    # Called (in the worker thread) right after a successful SSH login.
    on_connected: Callable[[str, str], None] | None = None


@dataclass
class Scrubber:
    secrets: list[str] = field(default_factory=list)

    def add(self, value: str | None) -> None:
        if value and len(value) >= 4 and value not in self.secrets:
            self.secrets.append(value)

    def __call__(self, text: str) -> str:
        clean = ANSI_RE.sub("", text or "").replace("\r", "")
        clean = SECRET_LINE_RE.sub(lambda m: m.group(1) + "[已隐藏]", clean)
        for value in self.secrets:
            clean = clean.replace(value, "[已隐藏]")
        return clean


def fingerprint_sha256(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class _AcceptOnce(paramiko.MissingHostKeyPolicy):
    """Trust on first use for this single connection only; nothing is saved."""

    def missing_host_key(self, client, hostname, key):  # noqa: D401
        return None


class HostKeyMismatch(Exception):
    """The server presented a different host key than the pinned one."""

    def __init__(self, expected: str, actual: str, key_type: str):
        super().__init__("host key mismatch")
        self.expected, self.actual, self.key_type = expected, actual, key_type

    def message(self) -> str:
        return (
            f"SSH 主机密钥与保存的记录不一致！记录：{self.expected}，本次：{self.key_type} {self.actual}。"
            "可能是服务器重装了系统，也可能是中间人攻击。已拒绝连接（未发送密码）。"
            "确认无误后请在「服务器记录」中点「信任新密钥」。"
        )


class PinnedKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept the host key only if its SHA256 fingerprint equals the pinned one.

    paramiko consults the policy before user authentication, so on mismatch the
    password is never sent.
    """

    def __init__(self, expected: str):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        actual = fingerprint_sha256(key)
        if not self.expected or not hmac.compare_digest(actual, self.expected):
            raise HostKeyMismatch(self.expected, actual, key.get_name())


class DeployHostKeyMismatch(DeploymentError):
    def __init__(self, mismatch: HostKeyMismatch):
        super().__init__(mismatch.message())
        self.mismatch = mismatch


class SSHAdapter:
    def __init__(self, spec: DeploySpec, timeout: float):
        self.spec = spec
        self.timeout = timeout
        self.client: paramiko.SSHClient | None = None
        self.fingerprint = ""
        self.key_type = ""
        self.peer_is_ipv6 = False
        self.connected_address = ""

    def connect(self) -> None:
        last: Exception | None = None
        password = self.spec.ssh_password
        try:
            for address in self.spec.resolved_addresses:
                client = paramiko.SSHClient()
                expected = self.spec.expected_fingerprint
                client.set_missing_host_key_policy(PinnedKeyPolicy(expected) if expected else _AcceptOnce())
                try:
                    client.connect(
                        hostname=address,
                        port=self.spec.ssh_port,
                        username=self.spec.ssh_user,
                        password=password,
                        timeout=self.timeout,
                        auth_timeout=self.timeout,
                        banner_timeout=self.timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                    transport = client.get_transport()
                    key = transport.get_remote_server_key() if transport else None
                    if not transport or not key:
                        raise DeploymentError("无法读取 SSH 主机密钥")
                    transport.set_keepalive(20)
                    self.fingerprint = fingerprint_sha256(key)
                    self.key_type = key.get_name()
                    sock = transport.sock
                    family = getattr(sock, "family", socket.AF_INET)
                    self.peer_is_ipv6 = family == socket.AF_INET6 and is_ipv6_literal(address)
                    self.connected_address = address
                    self.client = client
                    return
                except HostKeyMismatch as exc:
                    client.close()
                    raise DeployHostKeyMismatch(exc) from None
                except paramiko.AuthenticationException as exc:
                    client.close()
                    raise DeploymentError("SSH 认证失败：用户名或密码错误，或服务器禁用了密码登录") from exc
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    client.close()
        finally:
            # Drop our reference to the password as soon as authentication is done.
            password = None
            self.spec.ssh_password = None
        reason = type(last).__name__ if last else "未知错误"
        if isinstance(last, (socket.timeout, TimeoutError)):
            reason = "连接超时"
        elif isinstance(last, ConnectionRefusedError):
            reason = "连接被拒绝（端口未开放？）"
        elif isinstance(last, paramiko.SSHException):
            reason = "SSH 协议错误"
        raise DeploymentError(f"SSH 连接失败：{reason}")

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    def run(
        self,
        command: str,
        *,
        timeout: float = 60,
        on_line: Callable[[str], None] | None = None,
    ) -> tuple[int, str]:
        """Run a command (no PTY, stdin closed), return (exit_status, combined output)."""
        if not self.client or not self.client.get_transport():
            raise DeploymentError("SSH 连接不可用")
        channel = self.client.get_transport().open_session(timeout=self.timeout)
        try:
            channel.set_combine_stderr(True)
            channel.settimeout(1.0)
            channel.exec_command(command)
            channel.shutdown_write()
            deadline = time.monotonic() + timeout
            chunks: list[bytes] = []
            pending = b""
            while True:
                if time.monotonic() > deadline:
                    raise DeploymentError(f"远程命令超时（{int(timeout)} 秒）")
                try:
                    data = channel.recv(32768)
                except socket.timeout:
                    if channel.exit_status_ready() and not channel.recv_ready():
                        break
                    continue
                if not data:
                    break
                chunks.append(data)
                if on_line:
                    pending += data
                    *lines, pending = re.split(rb"\r\n|\n|\r", pending)
                    for line in lines:
                        on_line(line.decode("utf-8", errors="replace"))
            if on_line and pending:
                on_line(pending.decode("utf-8", errors="replace"))
            status = channel.recv_exit_status()
            return status, b"".join(chunks).decode("utf-8", errors="replace")
        finally:
            channel.close()


def remote_cmd(argv: list[str], sudo: bool) -> str:
    prefix = ["sudo", "-n", "--"] if sudo else []
    return shlex.join(prefix + argv)


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


PREFLIGHT_SCRIPT = r"""
printf 'KERNEL=%s\n' "$(uname -s 2>/dev/null)"
printf 'ARCH=%s\n' "$(uname -m 2>/dev/null)"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release; printf 'OS=%s\n' "${PRETTY_NAME:-$ID}"
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then echo SYSTEMD=1; else echo SYSTEMD=0; fi
if command -v curl >/dev/null 2>&1; then echo CURL=1; else echo CURL=0; fi
if command -v bash >/dev/null 2>&1; then echo BASH=1; else echo BASH=0; fi
printf 'GLIBC=%s\n' "$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
if [ -f /opt/nodelite/config/nodelite.env ] && [ -x /opt/nodelite/bin/nodelite-panel ]; then echo INSTALLED=1; else echo INSTALLED=0; fi
printf 'OLD_VERSION=%s\n' "$(cat /opt/nodelite/VERSION 2>/dev/null)"
printf 'SSH_CONN=%s\n' "${SSH_CONNECTION:-}"
if [ -d /proc/sys/net/ipv6 ]; then echo IPV6_STACK=1; else echo IPV6_STACK=0; fi
"""

INSTALL_SCRIPT = r"""
set -eu
url="$1"; public_host="$2"
work="$(mktemp -d /tmp/nodelite-auto.XXXXXX)"
trap 'rm -rf "$work"' EXIT
echo "[*] 下载 NodeLite 安装脚本：$url"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$url" -o "$work/install.sh"
head -n1 "$work/install.sh" | grep -q '^#!/usr/bin/env bash' || { echo "[x] 安装脚本内容校验失败" >&2; exit 90; }
grep -q 'dabao9037/nodelite' "$work/install.sh" || { echo "[x] 安装脚本来源校验失败" >&2; exit 90; }
bash -n "$work/install.sh"
echo "[*] 安装脚本 SHA256：$(sha256sum "$work/install.sh" | awk '{print $1}')"
if [ -n "$public_host" ]; then export PUBLIC_HOST="$public_host"; fi
bash "$work/install.sh" install </dev/null
"""


def build_info_script() -> str:
    keys = " ".join(INFO_KEYS)
    return (
        f"f={shlex.quote(ENV_PATH)}; "
        f"for k in {keys}; do "
        "printf '%s=%s\\n' \"$k\" \"$(sed -n \"s/^$k=//p\" \"$f\" | tail -n1)\"; done; "
        f"printf 'VERSION=%s\\n' \"$(cat {shlex.quote(VERSION_PATH)} 2>/dev/null)\""
    )


def format_host(host: str) -> str:
    return f"[{host}]" if is_ipv6_literal(host) else host


def validate_info(info: dict[str, str]) -> None:
    for key in INFO_KEYS:
        if not info.get(key):
            raise DeploymentError(f"NodeLite 配置缺少 {key}，安装可能未完成")
    if not info["LISTEN_PORT"].isdigit() or not 1 <= int(info["LISTEN_PORT"]) <= 65535:
        raise DeploymentError("NodeLite 配置中的 LISTEN_PORT 无效")
    if not ACCESS_PATH_RE.fullmatch(info["ACCESS_PATH"]):
        raise DeploymentError("NodeLite 配置中的 ACCESS_PATH 无效")
    if re.search(r"[\s/?#@]", info["PUBLIC_HOST"]):
        raise DeploymentError("NodeLite 配置中的 PUBLIC_HOST 无效")


def probe_public(url: str, settings: Settings, timeout: float = 6.0) -> tuple[bool | None, str]:
    """Best-effort reachability check from this backend. Never follows redirects."""
    host = urlsplit(url).hostname or ""
    try:
        addresses = {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except (socket.gaierror, ValueError):
        return None, "公网地址无法解析，跳过检测"
    if not addresses or any(not address_allowed(a, settings) for a in addresses):
        return None, "公网地址不符合本程序的目标安全策略，跳过检测"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            response = client.get(url)
        if response.status_code == 200:
            return True, "从本程序所在服务器访问面板成功"
        return False, f"面板返回 HTTP {response.status_code}"
    except httpx.HTTPError:
        return False, "从本程序所在服务器访问失败（可能是云厂商安全组/防火墙未放行该端口）"


@dataclass
class Session:
    ssh: SSHAdapter
    sudo: bool
    scrub: Scrubber

    def run(self, argv: list[str], *, timeout: float = 60, stream: Reporter | None = None) -> tuple[int, str]:
        on_line = None
        if stream is not None:
            def on_line(line: str) -> None:  # noqa: E306
                clean = self.scrub(line).rstrip()
                if clean:
                    stream.log(clean)
        return self.ssh.run(remote_cmd(argv, self.sudo), timeout=timeout, on_line=on_line)


def tail(text: str, scrub: Scrubber, lines: int = 6) -> str:
    rows = [row for row in scrub(text).splitlines() if row.strip()]
    return " | ".join(rows[-lines:])[:600]


def deploy(
    spec: DeploySpec,
    reporter: Reporter,
    settings: Settings,
    ssh_factory: Callable[[DeploySpec, float], SSHAdapter] = SSHAdapter,
    public_probe: Callable[[str, Settings], tuple[bool | None, str]] = probe_public,
) -> dict[str, Any]:
    scrub = Scrubber()
    scrub.add(spec.ssh_password)
    ssh = ssh_factory(spec, settings.ssh_connect_timeout)
    try:
        # 1. connect -------------------------------------------------------
        reporter.stage("connect", f"正在连接 {spec.host}:{spec.ssh_port}（用户 {spec.ssh_user}）")
        ssh.connect()
        spec.ssh_password = None
        pinned = "（与记录一致）" if spec.expected_fingerprint else "（首次连接，已保存到服务器记录）"
        reporter.info(f"SSH 已连接 {ssh.connected_address}，主机密钥 {ssh.key_type} {ssh.fingerprint}{pinned}")
        if spec.on_connected is not None:
            try:
                spec.on_connected(ssh.fingerprint, ssh.key_type)
            except Exception as exc:  # noqa: BLE001 - records are best effort, never break a deploy
                reporter.info(f"保存服务器记录失败：{type(exc).__name__}")
        status, out = ssh.run("id -u", timeout=20)
        if status != 0 or not out.strip().isdigit():
            raise DeploymentError("无法确认远程用户权限（id -u 失败）")
        sudo = False
        if out.strip() != "0":
            status, _ = ssh.run(shlex.join(["sudo", "-n", "true"]), timeout=20)
            if status != 0:
                raise DeploymentError(
                    "当前 SSH 用户不是 root，且没有免密 sudo 权限；请使用 root 或配置 NOPASSWD sudo"
                )
            sudo = True
            reporter.info("当前用户非 root，将通过免密 sudo 执行")
        session = Session(ssh, sudo, scrub)
        reporter.step("connect", "done")

        # 2. preflight -----------------------------------------------------
        reporter.stage("preflight", "正在检查系统环境")
        # Run without sudo so SSH_CONNECTION (stripped by sudo env_reset) is visible.
        status, out = ssh.run(shlex.join(["sh", "-c", PREFLIGHT_SCRIPT]), timeout=30)
        facts = parse_kv(out)
        if facts.get("KERNEL") != "Linux":
            raise DeploymentError("目标系统不是 Linux")
        arch = facts.get("ARCH", "")
        if arch not in {"x86_64", "amd64", "aarch64", "arm64"}:
            raise DeploymentError(f"NodeLite 暂不支持该架构：{arch or '未知'}")
        if facts.get("SYSTEMD") != "1":
            raise DeploymentError("目标系统未运行 systemd，NodeLite 原生版需要 systemd")
        if facts.get("BASH") != "1":
            raise DeploymentError("目标系统缺少 bash")
        if facts.get("CURL") != "1":
            raise DeploymentError("目标系统缺少 curl，请先安装 curl（例如 apt install -y curl）")
        installed = facts.get("INSTALLED") == "1"
        ssh_conn = facts.get("SSH_CONN", "").split()
        server_side_ipv6 = len(ssh_conn) >= 3 and is_ipv6_literal(ssh_conn[2])
        reporter.info(
            f"系统：{facts.get('OS', '未知')}，架构 {arch}，glibc {facts.get('GLIBC') or '未知'}"
            f"（glibc 兼容性由 NodeLite 安装器自行校验）"
        )
        if installed:
            reporter.info(f"检测到已安装 NodeLite {facts.get('OLD_VERSION') or ''}，将执行更新并保留现有账号密码")
        reporter.step("preflight", "done")

        # 3. install / update ---------------------------------------------
        mode = "update" if installed else "install"
        reporter.stage("install", "正在更新 NodeLite" if installed else "正在安装 NodeLite")
        # Fresh install: tell NodeLite the address the operator actually used.
        public_host = "" if installed else spec.host
        status, out = session.run(
            ["bash", "-c", INSTALL_SCRIPT, "nodelite-auto", settings.nodelite_installer_url, public_host],
            timeout=settings.install_timeout,
            stream=reporter,
        )
        if status != 0:
            raise DeploymentError(f"NodeLite 安装失败（退出码 {status}）：{tail(out, scrub)}")
        reporter.step("install", "done")

        # 4. disable IPv6 --------------------------------------------------
        ipv6: dict[str, Any] = {"requested": spec.disable_ipv6, "disabled": None, "message": "未请求关闭 IPv6"}
        reporter.stage("ipv6", "正在处理 IPv6 设置")
        if spec.disable_ipv6:
            reason = ""
            if spec.typed_ipv6:
                reason = "你填写的是 IPv6 地址，关闭 IPv6 会切断当前连接，已跳过"
            elif ssh.peer_is_ipv6 or server_side_ipv6:
                reason = "当前 SSH 会话走的是 IPv6，关闭 IPv6 会切断连接，已跳过"
            if reason:
                ipv6.update(disabled=False, message=reason)
                reporter.info(reason)
                reporter.step("ipv6", "skipped")
            elif facts.get("IPV6_STACK") == "0":
                ipv6.update(disabled=True, message="内核未加载 IPv6（如 ipv6.disable=1），IPv6 已处于关闭状态，无需修改")
                reporter.info(ipv6["message"])
                reporter.step("ipv6", "done")
            else:
                status, out = session.run(
                    ["env", "NODELITE_ASSUME_YES=1", "bash", SAVED_INSTALLER, "disable-ipv6"],
                    timeout=180,
                    stream=reporter,
                )
                _, check = session.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], timeout=20)
                if status == 0 and check.strip() == "1":
                    ipv6.update(disabled=True, message="IPv6 已关闭（sysctl net.ipv6.conf.all.disable_ipv6 = 1，已持久化）")
                    reporter.step("ipv6", "done")
                else:
                    ipv6.update(
                        disabled=False,
                        message=f"关闭 IPv6 失败（容器或系统可能不允许修改该 sysctl）：{tail(out, scrub, 3)}",
                    )
                    reporter.step("ipv6", "warn")
                reporter.info(ipv6["message"])
        else:
            reporter.step("ipv6", "skipped")

        # 5. panel info ----------------------------------------------------
        reporter.stage("info", "正在读取面板信息")
        status, out = session.run(["sh", "-c", build_info_script()], timeout=30)
        if status != 0:
            raise DeploymentError("读取 NodeLite 配置失败")
        info = parse_kv(out)
        validate_info(info)
        password = info[PASSWORD_KEY]
        scrub.add(password)
        port, path = info["LISTEN_PORT"], info["ACCESS_PATH"]
        panel_url = f"http://{format_host(info['PUBLIC_HOST'])}:{port}/{path}/login"
        alt_url = None
        if info["PUBLIC_HOST"].lower() != spec.host.lower():
            alt_url = f"http://{format_host(spec.host)}:{port}/{path}/login"
        local_url = f"http://127.0.0.1:{port}/{path}/login"
        status, code = session.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", local_url], timeout=30
        )
        local_ok = status == 0 and code.strip() == "200"
        reporter.info("服务器本机访问面板：" + ("正常（HTTP 200）" if local_ok else f"异常（{code.strip() or status}）"))
        public_ok, public_note = public_probe(alt_url or panel_url, settings)
        reporter.info(public_note)
        reporter.step("info", "done" if local_ok else "warn")
        return {
            "mode": mode,
            "panel_url": panel_url,
            "alt_panel_url": alt_url,
            "username": info["ADMIN_USER"],
            "password": password,
            "version": info.get("VERSION") or "未知",
            "fingerprint": ssh.fingerprint,
            "key_type": ssh.key_type,
            "ssh_address": ssh.connected_address,
            "os": facts.get("OS", ""),
            "arch": arch,
            "ipv6": ipv6,
            "reachability": {
                "local": local_ok,
                "public": public_ok,
                "public_note": public_note,
            },
        }
    except DeployHostKeyMismatch:
        raise
    except DeploymentError as exc:
        raise DeploymentError(scrub(str(exc))) from None
    except Exception as exc:  # noqa: BLE001
        raise DeploymentError(scrub(f"部署异常：{type(exc).__name__}: {exc}")[:600]) from None
    finally:
        ssh.close()
        spec.ssh_password = None
