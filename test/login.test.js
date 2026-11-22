'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const Login = require('../lib/login');

const publicKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  .publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const callbackUrl = 'https://agent.teleai.com.cn/superCowork/sapi/cowork/auth?code=private-code';
const token = 'eyJhbGciOiJIUzI1NiJ9.' + 'a'.repeat(574) + '.' + 'b'.repeat(44);
const cookieCases = [
  { name: 'scoped cleanup cookies', cookies: [
    `operationToken=${token}; Domain=.teleai.com.cn; Path=/; Secure; SameSite=None`,
    'operationToken=; Domain=agent.teleai.com.cn; Path=/; Max-Age=0',
    'operationToken=; Path=/; Max-Age=0',
  ] },
  { name: 'empty cookie before token', cookies: ['operationToken=', `operationToken=${token}`] },
  { name: 'multiple nonempty cookies', cookies: [`operationToken=${token}`, 'operationToken=later-token'] },
  { name: 'cookie value containing equals', cookies: ['operationToken=first=value', 'operationToken='], expected: 'first=value' },
];

function response(cookies, location) {
  const headers = cookies.map((c) => ['Set-Cookie', c]);
  if (location) headers.push(['Location', location]);
  return new Response('', { status: location ? 302 : 200, headers });
}

function createLogin(t, callbackResponse, data = {}) {
  const messages = [];
  const login = new Login('.', { info: (source, message) => messages.push(message) });
  t.mock.method(login, 'solveCaptcha', async () => 'test-captcha');
  t.mock.method(login, 'req', async (url) => {
    if (url.endsWith('/getRsaPublicKey')) {
      return { json: async () => ({ code: '10980001', data: { publicKey, keyId: 'test-key' } }) };
    }
    if (url.endsWith('/accountNameLogin')) {
      return { json: async () => ({ code: '10980001', data: { redirectUri: callbackUrl, ...data } }) };
    }
    assert.equal(url, callbackUrl);
    return callbackResponse;
  });
  return { login, messages };
}

for (const mode of ['callback', 'redirect']) {
  for (const c of cookieCases) {
    test(`${mode}: ${c.name}`, async (t) => {
      const res = response(c.cookies, 'https://agent.teleai.com.cn/teleagent?ticket=private-ticket');
      const { login, messages } = createLogin(t, res);
      t.mock.method(globalThis, 'fetch', async () => res);
      const actual = mode === 'callback'
        ? (await login.loginByPassword('test@example.com', 'test-password')).operationToken
        : await login.followRedirectForToken(callbackUrl);
      assert.equal(actual, c.expected || token);
      const diagnostics = messages.filter((m) => m.includes('HTTP'));
      assert.deepEqual(diagnostics, [
        `${mode === 'callback' ? '回跳' : '跳转链'}响应：agent.teleai.com.cn，HTTP 302，cookie 名：${c.cookies.map(() => 'operationToken').join(', ')}`,
      ]);
      for (const secret of [token, 'first=value', 'later-token', 'private-code', 'private-ticket']) {
        assert.ok(messages.every((m) => !m.includes(secret)));
      }
    });
  }

  test(`${mode}: empty cookies fail even when data contains tokens`, async (t) => {
    const res = response(['operationToken=; Max-Age=0', 'operToken=website-session']);
    const { login, messages } = createLogin(t, res, { operationToken: token, token, accessToken: token });
    t.mock.method(globalThis, 'fetch', async () => res);
    await assert.rejects(
      mode === 'callback'
        ? login.loginByPassword('test@example.com', 'test-password')
        : login.followRedirectForToken(callbackUrl),
      /未拿到 operationToken/,
    );
    assert.ok(messages.every((m) => !m.includes(token) && !m.includes('website-session')));
  });
}

test('callback follows redirect and accepts the first nonempty operationToken', async (t) => {
  const nextUrl = 'https://agent.teleai.com.cn/next?code=private-code';
  const { login } = createLogin(t, response(['operationToken='], nextUrl));
  const fetchMock = t.mock.method(globalThis, 'fetch', async (url, opts) => {
    assert.equal(url, nextUrl);
    assert.equal(opts.redirect, 'manual');
    return response(cookieCases[0].cookies);
  });
  assert.equal((await login.loginByPassword('test@example.com', 'test-password')).operationToken, token);
  assert.equal(fetchMock.mock.callCount(), 1);
});

test('redirect chain carries the first nonempty cookie across hops', async (t) => {
  const nextUrl = 'https://agent.teleai.com.cn/next';
  const { login } = createLogin(t);
  const fetchMock = t.mock.method(globalThis, 'fetch', async (url, opts) => {
    if (url === callbackUrl) {
      return response(['session=first-session', 'session=', 'operationToken='], nextUrl);
    }
    assert.equal(url, nextUrl);
    assert.equal(opts.headers.Cookie, 'session=first-session');
    return response(cookieCases[0].cookies);
  });
  assert.equal(await login.followRedirectForToken(callbackUrl), token);
  assert.equal(fetchMock.mock.callCount(), 2);
});
