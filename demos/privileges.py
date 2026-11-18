"""HK-06: бесплатный PRO по @нику.

Друзьям владельца PRO выдавался по списку @ников. Ник в Telegram можно сменить и освободить,
а другой человек может его занять и получить PRO. tg_id не меняется никогда.
Имена и id ниже выдуманные.
"""
FRIEND_USERNAMES = {"friend_one", "friend_two"}
FRIEND_TG_IDS = {1000001, 1000002}


def vulnerable_is_friend(tg_id: int, username: str | None) -> bool:
    return (username or "").lower() in FRIEND_USERNAMES


def fixed_is_friend(tg_id: int, username: str | None) -> bool:
    return tg_id in FRIEND_TG_IDS
