from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import socket
from dataclasses import dataclass

from .config import Settings

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetRejected(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedTarget:
    original: str
    addresses: tuple[str, ...]
    typed_ipv6: bool


def validate_hostname(value: str) -> str:
    """Accept an IPv4/IPv6 literal or a DNS hostname. Nothing else."""
    value = (value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not HOST_RE.fullmatch(value) or value.replace(".", "").isdigit():
        raise ValueError("服务器地址格式不正确，请填写 IP 或域名")
    return value.rstrip(".").lower()


def validate_username(value: str) -> str:
    value = (value or "").strip()
    if not USERNAME_RE.fullmatch(value):
        raise ValueError("SSH 用户名仅允许字母、数字、点、下划线和短横线，且不能以数字开头")
    return value


def validate_port(value: int, label: str = "端口") -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label}必须在 1-65535 之间")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}必须在 1-65535 之间") from exc
    if not 1 <= number <= 65535:
        raise ValueError(f"{label}必须在 1-65535 之间")
    return number


def is_ipv6_literal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is None:
        return True
    return False


def is_public_address(address: IPAddress) -> bool:
    return address.is_global and not (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address.is_private
    )


def address_allowed(address: IPAddress, settings: Settings) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if settings.target_allowlist and not any(
        address.version == network.version and address in network
        for network in settings.target_allowlist
    ):
        return False
    if settings.allow_private_targets:
        return not (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        )
    return is_public_address(address)


async def resolve_addresses(host: str) -> set[IPAddress]:
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetRejected("目标域名解析失败") from exc
    return {ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records}


async def resolve_and_validate_target(host: str, settings: Settings) -> ResolvedTarget:
    """Resolve once and pin the addresses (prevents DNS rebinding between check and use)."""
    host = validate_hostname(host)
    addresses = await resolve_addresses(host)
    if not addresses:
        raise TargetRejected("目标没有可用地址")
    if any(not address_allowed(item, settings) for item in addresses):
        raise TargetRejected(
            "目标地址不符合安全策略（默认仅允许公网地址；内网目标需 ALLOW_PRIVATE_TARGETS=1）"
        )
    # Prefer IPv4 so an IPv6 shutdown on the target cannot cut our own session.
    ordered = sorted(addresses, key=lambda item: (item.version, int(item)))
    return ResolvedTarget(host, tuple(str(item) for item in ordered), is_ipv6_literal(host))


def csrf_token(secret: str, sid: str) -> str:
    return hmac.new(secret.encode(), f"csrf:{sid}".encode(), hashlib.sha256).hexdigest()


def csrf_valid(secret: str, sid: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(csrf_token(secret, sid), str(supplied))
