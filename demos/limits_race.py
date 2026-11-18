"""HK-05: гонка на дневном лимите ИИ-писем.

Лимит проверялся до генерации, а засчитывался после. Генерация идёт десятки секунд,
поэтому пять одновременных нажатий проходили проверку все разом.
fixed: попытка резервируется под замком пользователя до вызова модели.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict

DAILY_LIMIT = 3


class Letters:
    def __init__(self) -> None:
        self.used: dict[int, int] = defaultdict(int)
        self.locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def _generate(self) -> str:
        await asyncio.sleep(0.05)  # «модель думает»
        return "письмо"

    async def vulnerable(self, user: int) -> str | None:
        if self.used[user] >= DAILY_LIMIT:
            return None
        text = await self._generate()
        self.used[user] += 1
        return text

    async def fixed(self, user: int) -> str | None:
        async with self.locks[user]:
            if self.used[user] >= DAILY_LIMIT:
                return None
            self.used[user] += 1  # резерв до генерации
        try:
            return await self._generate()
        except Exception:
            async with self.locks[user]:
                self.used[user] -= 1  # не получилось: попытку возвращаем
            raise
