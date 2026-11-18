"""HK-06: чужой человек занял освободившийся ник друга."""
import pytest

from demos.privileges import fixed_is_friend, vulnerable_is_friend

STRANGER = (999999, "friend_one")  # другой tg_id, но ник друга
FRIEND_RENAMED = (1000001, "new_nick")


def test_fixed_stranger_with_friends_nick_gets_nothing():
    assert not fixed_is_friend(*STRANGER)


def test_fixed_friend_keeps_pro_after_rename():
    assert fixed_is_friend(*FRIEND_RENAMED)


@pytest.mark.xfail(strict=True, reason="HK-06 до исправления: PRO получал любой, кто занял ник")
def test_vulnerable_stranger_with_friends_nick():
    assert not vulnerable_is_friend(*STRANGER)
