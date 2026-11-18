# HK-03. Не-ASCII символ в подписи даёт 500 вместо 401

| | |
|---|---|
| Категория | OWASP Top 10: A04 Insecure Design (обработка ошибок), API8 Security Misconfiguration |
| Серьёзность | Low, CVSS 3.1 ≈ 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L) |
| Компонент | проверка подписи Mini App, редирект кликов по ссылкам |
| Кто нашёл | аудит 11.11.2026 (QA-06), негативное тестирование на стенде |
| Статус | исправлено |

## Что не так
`hmac.compare_digest` на строках с не-ASCII символами бросает `TypeError`. Запрос с кириллицей в `hash` ронял обработчик, сервер отвечал 500.

## Чем опасно
Данные не утекают, но 500 на мусорный ввод это шум в логах и мониторинге, лишние алерты и подсказка атакующему, что ввод доходит до необработанного места.

## Как исправлено
Сравниваем байты:
```python
hmac.compare_digest(expected.encode(), received.encode("utf-8", "replace"))
```
Плюс `strict_parsing` и проверка `auth_date` на число.

## Проверка
`tests/test_auth_init_data.py::test_non_ascii_hash_is_rejected_not_crash` и `test_garbage_rejected`. Уязвимая версия падает `TypeError` (`xfail`).
