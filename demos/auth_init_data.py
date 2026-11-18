"""HK-02 и HK-03: проверка подписи initData Telegram Mini App.

vulnerable_validate: как было до исправлений.
fixed_validate: как сейчас в продукте.
Алгоритм подписи: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl, urlencode

MAX_AGE_SECONDS = 24 * 3600
CLOCK_SKEW_SECONDS = 5 * 60


def _expected_hash(fields: dict, bot_token: str) -> str:
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    return hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()


def _user(fields: dict) -> dict | None:
    try:
        user = json.loads(fields.get("user", ""))
    except ValueError:
        return None
    return user if isinstance(user, dict) and isinstance(user.get("id"), int) else None


def vulnerable_validate(init_data: str, bot_token: str, max_age: int = MAX_AGE_SECONDS) -> dict | None:
    fields = dict(parse_qsl(init_data, keep_blank_values=True))
    received = fields.pop("hash", "")
    # HK-03: compare_digest на строках падает TypeError, если в hash есть не-ASCII символы, сервер отвечал 500
    if not hmac.compare_digest(_expected_hash(fields, bot_token), received):
        return None
    auth_date = int(fields.get("auth_date", "0"))
    # HK-02: проверка только «не слишком ли старая». Дата из будущего даёт отрицательный возраст и проходит
    if time.time() - auth_date > max_age:
        return None
    return _user(fields)


def fixed_validate(init_data: str, bot_token: str, max_age: int = MAX_AGE_SECONDS) -> dict | None:
    if not init_data:
        return None
    try:
        fields = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        return None
    received = fields.pop("hash", "")
    # байты, а не строки: не-ASCII hash просто не совпадёт, вместо 500 будет 401
    if not hmac.compare_digest(_expected_hash(fields, bot_token).encode(), received.encode("utf-8", "replace")):
        return None
    try:
        auth_date = int(fields.get("auth_date", "0"))
    except ValueError:
        return None
    age = time.time() - auth_date
    if age > max_age or age < -CLOCK_SKEW_SECONDS:  # слишком старая ИЛИ из будущего
        return None
    return _user(fields)


def sign(fields: dict, bot_token: str) -> str:
    """Подписать поля так же, как это делает Telegram (для тестов)."""
    return urlencode({**fields, "hash": _expected_hash(fields, bot_token)})
