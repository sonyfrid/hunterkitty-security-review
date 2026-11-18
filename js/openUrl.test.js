const test = require('node:test');
const assert = require('node:assert');
const { vulnerableOpenUrl, fixedOpenUrl } = require('./openUrl');

function fakeTg() {
  const opened = [];
  return { opened, openLink: (u) => opened.push(u), openTelegramLink: (u) => opened.push(u) };
}

const BAD = ['javascript:void(0)', 'JAVASCRIPT:void(0)', 'data:text/html,hi', 'file:///etc/hosts', ' javascript:void(0)'];

for (const url of BAD) {
  test(`fixed: не открывает ${url}`, () => {
    const tg = fakeTg();
    fixedOpenUrl(url, tg);
    assert.deepStrictEqual(tg.opened, []);
  });
}

test('vulnerable: javascript: доходил до openLink (баг до исправления)', () => {
  const tg = fakeTg();
  vulnerableOpenUrl('javascript:void(0)', tg);
  assert.deepStrictEqual(tg.opened, ['javascript:void(0)']);
});

test('fixed: обычные ссылки открываются', () => {
  const tg = fakeTg();
  fixedOpenUrl('https://example.com/job/1', tg);
  fixedOpenUrl('https://t.me/somechannel/5', tg);
  assert.deepStrictEqual(tg.opened, ['https://example.com/job/1', 'https://t.me/somechannel/5']);
});
