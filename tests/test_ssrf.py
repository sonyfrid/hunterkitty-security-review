"""HK-04: SSRF. DNS подменяем словарём, в сеть тесты не ходят."""
import pytest

from demos.ssrf import fixed_fetch_allowed, fixed_ip_ok, vulnerable_fetch_allowed, vulnerable_ip_ok

DNS = {
    "jobs.example.com": ["93.184.216.34"],
    "internal.example.com": ["10.0.0.5"],
    "metadata.example.com": ["169.254.169.254"],
    "cgnat.example.com": ["100.64.0.10"],
    "zero.example.com": ["0.0.0.0"],
    "mapped.example.com": ["::ffff:127.0.0.1"],
    "loop.example.com": ["127.0.0.1"],
}


def resolve(host):
    return DNS[host]


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.10", "0.0.0.0", "::ffff:127.0.0.1", "::1", "224.0.0.1"])
def test_fixed_blocks_non_public(ip):
    assert not fixed_ip_ok(ip)


def test_fixed_allows_public():
    assert fixed_ip_ok("93.184.216.34")


@pytest.mark.parametrize("ip", ["100.64.0.10", "100.127.255.1"])
@pytest.mark.xfail(strict=True, reason="HK-04 до исправления: is_private не считает эти сети внутренними")
def test_vulnerable_misses_special_ranges(ip):
    assert not vulnerable_ip_ok(ip)


def test_fixed_checks_every_redirect():
    chain = ["https://jobs.example.com/vacancy", "http://internal.example.com/admin"]
    assert not fixed_fetch_allowed(chain, resolve)


@pytest.mark.xfail(strict=True, reason="HK-04 до исправления: редирект на внутренний адрес не проверялся")
def test_vulnerable_follows_redirect_inside():
    chain = ["https://jobs.example.com/vacancy", "http://internal.example.com/admin"]
    assert not vulnerable_fetch_allowed(chain, resolve)


def test_fixed_limits_redirects():
    chain = ["https://jobs.example.com/"] * 5
    assert not fixed_fetch_allowed(chain, resolve)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://jobs.example.com/", "ftp://jobs.example.com/"])
def test_fixed_only_http(url):
    assert not fixed_fetch_allowed([url], resolve)


def test_fixed_normal_page_ok():
    assert fixed_fetch_allowed(["https://jobs.example.com/vacancy/1"], resolve)
