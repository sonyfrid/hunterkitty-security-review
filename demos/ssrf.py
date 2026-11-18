"""HK-04: SSRF при скачивании страниц по ссылкам из постов.

Бот открывает ссылку из поста, чтобы дочитать вакансию. Ссылку может написать кто угодно.
vulnerable_*: проверялся только первый адрес и только ip.is_private.
fixed_*: is_global для каждого адреса, IPv4 внутри IPv6 разворачивается, каждый редирект проверяется заново.
В продукте есть ещё проверка адреса в момент соединения, против DNS rebinding.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

MAX_REDIRECTS = 3


def vulnerable_ip_ok(raw: str) -> bool:
    return not ipaddress.ip_address(raw).is_private


def fixed_ip_ok(raw: str) -> bool:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _url_ok(url: str, resolve, ip_ok) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    return all(ip_ok(a) for a in resolve(p.hostname))


def vulnerable_fetch_allowed(chain: list[str], resolve) -> bool:
    """chain: первый адрес и адреса, куда сервер перенаправил. Проверялся только первый."""
    return _url_ok(chain[0], resolve, vulnerable_ip_ok)


def fixed_fetch_allowed(chain: list[str], resolve) -> bool:
    if len(chain) - 1 > MAX_REDIRECTS:
        return False
    return all(_url_ok(u, resolve, fixed_ip_ok) for u in chain)
