// HK-07: ссылки вакансий открываются через Telegram WebApp openLink.
// Адрес приходит из чужих постов и сайтов, поэтому пропускаем только http(s).

function vulnerableOpenUrl(url, tg) {
  if (!url) return;
  if (/^https?:\/\/(t|telegram)\.me\//i.test(url)) tg.openTelegramLink(url);
  else tg.openLink(url); // javascript:, data:, file: уходили сюда как есть
}

function fixedOpenUrl(url, tg) {
  if (!url || !/^https?:\/\//i.test(url)) return;
  if (/^https?:\/\/(t|telegram)\.me\//i.test(url)) tg.openTelegramLink(url);
  else tg.openLink(url);
}

module.exports = { vulnerableOpenUrl, fixedOpenUrl };
