"""HK-05: десять одновременных запросов на письмо при лимите 3 в день."""
import asyncio

import pytest

from demos.limits_race import DAILY_LIMIT, Letters


async def burst(method, n=10):
    return await asyncio.gather(*(method(42) for _ in range(n)))


def test_fixed_limit_holds_under_burst():
    letters = Letters()
    results = asyncio.run(burst(letters.fixed))
    assert sum(r is not None for r in results) == DAILY_LIMIT


@pytest.mark.xfail(strict=True, reason="HK-05 до исправления: все 10 запросов проходили проверку лимита разом")
def test_vulnerable_limit_under_burst():
    letters = Letters()
    results = asyncio.run(burst(letters.vulnerable))
    assert sum(r is not None for r in results) == DAILY_LIMIT


def test_fixed_failed_generation_returns_attempt():
    letters = Letters()

    async def boom():
        raise RuntimeError("модель недоступна")

    letters._generate = boom
    with pytest.raises(RuntimeError):
        asyncio.run(letters.fixed(42))
    assert letters.used[42] == 0
