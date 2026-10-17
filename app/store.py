"""Persistent server records (SQLite) with AES-GCM encrypted secrets.

* One record per (host, ssh_port, ssh_user).
* Secrets (saved SSH password, NodeLite panel password) are encrypted with
  AES-256-GCM. The key is 32 random bytes in ``<data_dir>/secret.key`` (0600)
  and is never logged. The record id + field name is bound as associated data,
  so a ciphertext cannot be moved to another record or field.
* List APIs never include secrets; callers must ask for them explicitly.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "secret.key"
DB_FILE = "data.db"
MAX_HISTORY = 50
SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL,
    ssh_user TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    key_type TEXT NOT NULL DEFAULT '',
    first_deploy_at REAL,
    last_deploy_at REAL,
    last_status TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    ipv6_status TEXT NOT NULL DEFAULT '',
    panel_url TEXT NOT NULL DEFAULT '',
    alt_panel_url TEXT NOT NULL DEFAULT '',
    panel_user TEXT NOT NULL DEFAULT '',
    panel_password_enc BLOB,
    ssh_password_enc BLOB,
    pending_fingerprint TEXT NOT NULL DEFAULT '',
    pending_key_type TEXT NOT NULL DEFAULT '',
    UNIQUE (host, ssh_port, ssh_user)
);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL,
    ssh_user TEXT NOT NULL,
    at REAL NOT NULL,
    status TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS history_target ON history (host, ssh_port, ssh_user, at);
"""
PUBLIC_FIELDS = (
    "id", "host", "ssh_port", "ssh_user", "fingerprint", "key_type", "first_deploy_at", "last_deploy_at",
    "last_status", "version", "ipv6_status", "panel_url", "alt_panel_url", "panel_user",
    "pending_fingerprint", "pending_key_type",
)


class StoreError(RuntimeError):
    pass


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_or_create_key(data_dir: Path) -> bytes:
    path = data_dir / KEY_FILE
    if not path.exists():
        try:
            _write_private(path, secrets.token_bytes(32))
        except FileExistsError:
            pass
    key = path.read_bytes()
    if len(key) != 32:
        raise StoreError(f"{path} 长度不正确（应为 32 字节），拒绝启动以免覆盖已有密钥")
    os.chmod(path, 0o600)
    return key


class Cipher:
    VERSION = b"\x01"

    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    def encrypt(self, value: str, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return self.VERSION + nonce + self._aead.encrypt(nonce, value.encode("utf-8"), aad)

    def decrypt(self, blob: bytes, aad: bytes) -> str:
        if not blob or blob[:1] != self.VERSION:
            raise StoreError("密文格式无效")
        return self._aead.decrypt(blob[1:13], blob[13:], aad).decode("utf-8")


def _aad(server_id: int, name: str) -> bytes:
    return f"nlad:{server_id}:{name}".encode()


class ServerStore:
    def __init__(self, data_dir: str | os.PathLike[str]):
        self.dir = Path(data_dir)
        try:
            self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreError(f"无法创建数据目录 {self.dir}：{exc.strerror}") from None
        if not os.access(self.dir, os.W_OK):
            raise StoreError(f"数据目录 {self.dir} 不可写")
        self.cipher = Cipher(load_or_create_key(self.dir))
        self.path = self.dir / DB_FILE
        if not self.path.exists():
            _write_private(self.path, b"")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA secure_delete = ON")
        self._db.executescript(SCHEMA)
        os.chmod(self.path, 0o600)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- helpers -------------------------------------------------------------
    def _one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        data = {key: row[key] for key in PUBLIC_FIELDS}
        data["has_ssh_password"] = row["ssh_password_enc"] is not None
        data["has_panel_password"] = row["panel_password_enc"] is not None
        return data

    def find(self, host: str, port: int, user: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM servers WHERE host=? AND ssh_port=? AND ssh_user=?", (host, port, user))
        return self._public(row) if row else None

    def get(self, server_id: int) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM servers WHERE id=?", (server_id,))
        return self._public(row) if row else None

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM servers ORDER BY last_deploy_at DESC, id DESC").fetchall()
        return [self._public(row) for row in rows]

    # -- writes --------------------------------------------------------------
    def ensure_server(self, host: str, port: int, user: str, fingerprint: str, key_type: str) -> int:
        """Create the record after a successful SSH login (or return the existing one)."""
        with self._lock:
            self._db.execute(
                "INSERT INTO servers (host, ssh_port, ssh_user, fingerprint, key_type) VALUES (?,?,?,?,?) "
                "ON CONFLICT (host, ssh_port, ssh_user) DO NOTHING",
                (host, port, user, fingerprint, key_type),
            )
            row = self._db.execute(
                "SELECT id, fingerprint FROM servers WHERE host=? AND ssh_port=? AND ssh_user=?", (host, port, user)
            ).fetchone()
            if not row["fingerprint"]:
                self._db.execute(
                    "UPDATE servers SET fingerprint=?, key_type=? WHERE id=?", (fingerprint, key_type, row["id"])
                )
            return int(row["id"])

    def record_success(self, server_id: int, result: dict[str, Any]) -> None:
        now = time.time()
        ipv6 = result.get("ipv6") or {}
        panel_enc = self.cipher.encrypt(result["password"], _aad(server_id, "panel")) if result.get("password") else None
        with self._lock:
            self._db.execute(
                "UPDATE servers SET first_deploy_at=COALESCE(first_deploy_at, ?), last_deploy_at=?, last_status=?, "
                "version=?, ipv6_status=?, panel_url=?, alt_panel_url=?, panel_user=?, panel_password_enc=?, "
                "fingerprint=?, key_type=?, pending_fingerprint='', pending_key_type='' WHERE id=?",
                (
                    now, now, result.get("status", "success"), str(result.get("version") or ""),
                    str(ipv6.get("message") or "")[:300], result.get("panel_url") or "",
                    result.get("alt_panel_url") or "", result.get("username") or "", panel_enc,
                    result.get("fingerprint") or "", result.get("key_type") or "", server_id,
                ),
            )

    def record_failure(self, server_id: int | None) -> None:
        if server_id is None:
            return
        with self._lock:
            self._db.execute(
                "UPDATE servers SET last_deploy_at=?, last_status='failed' WHERE id=?", (time.time(), server_id)
            )

    def add_history(self, host: str, port: int, user: str, status: str, version: str = "", error: str = "",
                    server_id: int | None = None) -> None:
        with self._lock:
            if server_id is None:
                row = self._db.execute(
                    "SELECT id FROM servers WHERE host=? AND ssh_port=? AND ssh_user=?", (host, port, user)
                ).fetchone()
                server_id = int(row["id"]) if row else None
            self._db.execute(
                "INSERT INTO history (server_id, host, ssh_port, ssh_user, at, status, version, error) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (server_id, host, port, user, time.time(), status, version[:64], error[:300]),
            )
            # Keep the history bounded per target.
            self._db.execute(
                "DELETE FROM history WHERE host=? AND ssh_port=? AND ssh_user=? AND id NOT IN ("
                "SELECT id FROM history WHERE host=? AND ssh_port=? AND ssh_user=? ORDER BY id DESC LIMIT ?)",
                (host, port, user, host, port, user, MAX_HISTORY),
            )

    def history(self, server_id: int) -> list[dict[str, Any]]:
        server = self._one("SELECT host, ssh_port, ssh_user FROM servers WHERE id=?", (server_id,))
        if not server:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT at, status, version, error FROM history WHERE server_id=? OR "
                "(host=? AND ssh_port=? AND ssh_user=?) ORDER BY id DESC LIMIT ?",
                (server_id, server["host"], server["ssh_port"], server["ssh_user"], MAX_HISTORY),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_ssh_password(self, server_id: int, password: str) -> None:
        blob = self.cipher.encrypt(password, _aad(server_id, "ssh"))
        with self._lock:
            self._db.execute("UPDATE servers SET ssh_password_enc=? WHERE id=?", (blob, server_id))

    def ssh_password(self, server_id: int) -> str | None:
        row = self._one("SELECT ssh_password_enc FROM servers WHERE id=?", (server_id,))
        if not row or row["ssh_password_enc"] is None:
            return None
        return self.cipher.decrypt(row["ssh_password_enc"], _aad(server_id, "ssh"))

    def panel_password(self, server_id: int) -> str | None:
        row = self._one("SELECT panel_password_enc FROM servers WHERE id=?", (server_id,))
        if not row or row["panel_password_enc"] is None:
            return None
        return self.cipher.decrypt(row["panel_password_enc"], _aad(server_id, "panel"))

    def forget_ssh_password(self, server_id: int) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE servers SET ssh_password_enc=NULL WHERE id=?", (server_id,))
        return cur.rowcount > 0

    def forget_all_ssh_passwords(self) -> int:
        with self._lock:
            cur = self._db.execute("UPDATE servers SET ssh_password_enc=NULL WHERE ssh_password_enc IS NOT NULL")
            self._db.execute("VACUUM")
        return cur.rowcount

    def set_pending_fingerprint(self, server_id: int, fingerprint: str, key_type: str) -> None:
        """Remember a mismatching key so the operator can review and explicitly trust it."""
        with self._lock:
            self._db.execute(
                "UPDATE servers SET pending_fingerprint=?, pending_key_type=? WHERE id=?",
                (fingerprint, key_type, server_id),
            )

    def trust_pending_fingerprint(self, server_id: int, fingerprint: str) -> bool:
        """Replace the pinned key with the pending one, only if the operator confirmed that exact value."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE servers SET fingerprint=pending_fingerprint, key_type=pending_key_type, "
                "pending_fingerprint='', pending_key_type='' WHERE id=? AND pending_fingerprint!='' "
                "AND pending_fingerprint=?",
                (server_id, fingerprint),
            )
        return cur.rowcount > 0

    def delete(self, server_id: int) -> bool:
        server = self._one("SELECT host, ssh_port, ssh_user FROM servers WHERE id=?", (server_id,))
        if not server:
            return False
        with self._lock:
            self._db.execute(
                "DELETE FROM history WHERE server_id=? OR (host=? AND ssh_port=? AND ssh_user=?)",
                (server_id, server["host"], server["ssh_port"], server["ssh_user"]),
            )
            self._db.execute("DELETE FROM servers WHERE id=?", (server_id,))
        return True
