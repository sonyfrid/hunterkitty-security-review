"""HK-02 (дата из будущего) и HK-03 (не-ASCII hash даёт 500). Плюс проверки, которые выдержали атаку."""
import json
import time

import pytest

from demos.auth_init_data import fixed_validate, sign, vulnerable_validate

TOKEN = "123456:TEST_TOKEN_not_real"
OTHER = "654321:OTHER_TOKEN"


def fields(uid=111, age=0):
    return {"auth_date": str(int(time.time() - age)), "user": json.dumps({"id": uid, "first_name": "Lab"})}


def test_valid_signature_accepted():
    assert fixed_validate(sign(fields(), TOKEN), TOKEN)["id"] == 111


def test_swapped_user_id_rejected():
    """AUTH-01: подписал за 111, подменил id на 222 после подписи."""
    data = sign(fields(111), TOKEN).replace("%22id%22%3A+111", "%22id%22%3A+222")
    assert "222" in data
    assert fixed_validate(data, TOKEN) is None


def test_signed_with_other_token_rejected():
    assert fixed_validate(sign(fields(), OTHER), TOKEN) is None


def test_expired_rejected():
    assert fixed_validate(sign(fields(age=25 * 3600), TOKEN), TOKEN) is None


def test_future_auth_date_rejected():
    """HK-02: дата выдачи на год вперёд."""
    assert fixed_validate(sign(fields(age=-365 * 24 * 3600), TOKEN), TOKEN) is None


def test_small_clock_skew_still_ok():
    assert fixed_validate(sign(fields(age=-60), TOKEN), TOKEN)["id"] == 111


@pytest.mark.xfail(strict=True, reason="HK-02 до исправления: initData из будущего принималась и жила год")
def test_vulnerable_future_auth_date():
    assert vulnerable_validate(sign(fields(age=-365 * 24 * 3600), TOKEN), TOKEN) is None


def test_non_ascii_hash_is_rejected_not_crash():
    """HK-03: не-ASCII символы в hash должны давать отказ (401), а не исключение (500)."""
    assert fixed_validate("auth_date=1&user=%7B%7D&hash=%D0%B6", TOKEN) is None


@pytest.mark.xfail(strict=True, raises=TypeError, reason="HK-03 до исправления: TypeError в compare_digest, сервер отвечал 500")
def test_vulnerable_non_ascii_hash():
    vulnerable_validate("auth_date=1&user=%7B%7D&hash=%D0%B6", TOKEN)


@pytest.mark.parametrize("junk", ["", "hash=", "garbage", "auth_date=abc&hash=00"])
def test_garbage_rejected(junk):
    assert fixed_validate(junk, TOKEN) is None
