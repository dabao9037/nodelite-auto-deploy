"""Maintenance commands for the server record store (run by `nladmin`)."""

from __future__ import annotations

import os
import sys

from .store import ServerStore


def main(argv: list[str]) -> int:
    data_dir = os.getenv("WEB_DATA_DIR", "").strip() or "/var/lib/nodelite-auto-deploy"
    command = argv[0] if argv else ""
    if command == "forget-passwords":
        store = ServerStore(data_dir)
        count = store.forget_all_ssh_passwords()
        store.close()
        print(f"已删除 {count} 条保存的 SSH 密码（服务器记录和面板信息保留）")
        return 0
    if command == "count":
        store = ServerStore(data_dir)
        servers = store.list()
        store.close()
        saved = sum(1 for item in servers if item["has_ssh_password"])
        print(f"服务器记录 {len(servers)} 条，其中 {saved} 条保存了 SSH 密码")
        return 0
    print("用法: python -m app.cli {forget-passwords|count}", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
