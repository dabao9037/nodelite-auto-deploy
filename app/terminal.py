"""Interactive web SSH terminal (paramiko invoke_shell bridged over a WebSocket).

* Host keys are pinned: the SHA256 fingerprint saved at deploy time must match,
  otherwise the connection is refused before any password is sent.
* All blocking paramiko I/O runs in worker threads.
* Tickets are one-time, short-lived, bound to the session and to a record.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
from dataclasses import dataclass, field

import paramiko

from .deployer import HostKeyMismatch, PinnedKeyPolicy

TICKET_TTL = 60
IDLE_TIMEOUT = 30 * 60
MAX_COLS, MAX_ROWS = 500, 200


class TerminalError(RuntimeError):
    pass


@dataclass
class Ticket:
    sid: str
    server_id: int
    expires_at: float
    addresses: tuple[str, ...] = ()
    password: str | None = None  # one-time password typed by the operator
    save: bool = False  # save that password after a successful login
    cols: int = 120
    rows: int = 32


@dataclass
class TicketStore:
    ttl: int = TICKET_TTL
    tickets: dict[str, Ticket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def issue(self, sid: str, server_id: int, addresses: tuple[str, ...], password: str | None = None,
              save: bool = False, cols: int = 120, rows: int = 32) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            self.tickets[token] = Ticket(sid, server_id, time.time() + self.ttl, addresses, password, save, cols, rows)
        return token

    def consume(self, token: str, sid: str) -> Ticket | None:
        with self._lock:
            self._purge()
            ticket = self.tickets.pop(token, None)  # single use: removed even if the session mismatches
        if not ticket or not secrets.compare_digest(ticket.sid, sid):
            return None
        return ticket

    def _purge(self) -> None:
        now = time.time()
        for key in [k for k, t in self.tickets.items() if t.expires_at <= now]:
            ticket = self.tickets.pop(key, None)
            if ticket:
                ticket.password = None


def clamp_size(cols, rows) -> tuple[int, int]:
    try:
        cols, rows = int(cols), int(rows)
    except (TypeError, ValueError):
        return 120, 32
    return max(10, min(cols, MAX_COLS)), max(4, min(rows, MAX_ROWS))


class ShellSession:
    """A paramiko interactive shell. All methods are blocking; call from threads."""

    def __init__(self, addresses: tuple[str, ...], port: int, user: str, fingerprint: str, timeout: float):
        self.addresses, self.port, self.user = addresses, port, user
        self.fingerprint, self.timeout = fingerprint, timeout
        self.client: paramiko.SSHClient | None = None
        self.channel: paramiko.Channel | None = None

    def open(self, password: str, cols: int, rows: int) -> None:
        last: Exception | None = None
        for address in self.addresses:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(PinnedKeyPolicy(self.fingerprint))
            try:
                client.connect(
                    hostname=address, port=self.port, username=self.user, password=password,
                    timeout=self.timeout, auth_timeout=self.timeout, banner_timeout=self.timeout,
                    look_for_keys=False, allow_agent=False,
                )
            except HostKeyMismatch:
                client.close()
                raise
            except paramiko.AuthenticationException:
                client.close()
                raise TerminalError("SSH 认证失败：密码错误或服务器禁用了密码登录") from None
            except Exception as exc:  # noqa: BLE001
                last = exc
                client.close()
                continue
            transport = client.get_transport()
            transport.set_keepalive(30)
            channel = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
            channel.settimeout(0.5)
            self.client, self.channel = client, channel
            return
        reason = "连接超时" if isinstance(last, (socket.timeout, TimeoutError)) else (
            "连接被拒绝" if isinstance(last, ConnectionRefusedError) else type(last).__name__ if last else "未知错误"
        )
        raise TerminalError(f"SSH 连接失败：{reason}")

    def read(self) -> bytes | None:
        """Return bytes, b'' when nothing arrived within the poll interval, None at EOF."""
        channel = self.channel
        if channel is None:
            return None
        try:
            data = channel.recv(32768)
        except socket.timeout:
            return None if channel.closed or channel.exit_status_ready() and not channel.recv_ready() else b""
        except (OSError, EOFError, paramiko.SSHException):
            return None
        return data or None

    def write(self, data: bytes) -> None:
        if self.channel is not None:
            self.channel.sendall(data)

    def resize(self, cols: int, rows: int) -> None:
        if self.channel is not None:
            self.channel.resize_pty(width=cols, height=rows)

    def close(self) -> None:
        try:
            if self.channel is not None:
                self.channel.close()
        finally:
            self.channel = None
            if self.client is not None:
                self.client.close()
                self.client = None
