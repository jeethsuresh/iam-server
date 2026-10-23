import test from 'node:test';
import assert from 'node:assert/strict';
import { handleRequest, containerEnvironment } from '../src/routing.ts';

function environment(fetch = async () => new Response('iam')) {
  return {
    IAM_DOMAIN: 'example.com', IAM_PUBLIC_URL: 'https://iam.example.com',
    DATABASE_URL: 'postgres://test:password@db.example.com/iam',
    JWT_SECRET: 'j'.repeat(32), SECRET_KEY_BASE: 's'.repeat(64),
    IAM_ADMIN_PASSWORD: 'test-admin-password',
    IAM_REGISTRATION_KEY: 'test-invitation-key',
    IAM: { getByName(name) { assert.equal(name, 'iam-primary'); return { fetch }; } },
  };
}

test('identity domain redirects discovery to IAM while preserving identity and relation', async () => {
  const env = environment(() => { throw Error('Discovery must not launch the container'); });
  const query = new URLSearchParams({ resource: 'acct:user@example.com', rel: 'https://github.com/jeethsuresh/iam-server#issuer' });
  const response = await handleRequest(new Request(`https://example.com/.well-known/webfinger?${query}`), env);
  assert.equal(response.status, 307);
  assert.equal(response.headers.get('location'), `https://iam.example.com/.well-known/webfinger?${query}`);
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
});

test('other apex paths and unexpected hosts never reach the IAM backend', async () => {
  const env = environment(() => { throw Error('must not proxy'); });
  for (const url of ['https://example.com/', 'https://example.com/login', 'https://evil.example/.well-known/webfinger']) {
    assert.equal((await handleRequest(new Request(url), env)).status, 404);
  }
});

test('login POST preserves body and cookies while replacing spoofed proxy headers', async () => {
  const env = environment(async request => {
    assert.equal(request.url, 'https://iam.example.com/web/login?sessionID=abc');
    assert.equal(request.method, 'POST');
    assert.equal(await request.text(), 'username=%40user%3Aexample.com&password=test');
    assert.equal(request.headers.get('cookie'), 'session=abc');
    assert.equal(request.headers.get('x-forwarded-proto'), 'https');
    assert.equal(request.headers.get('x-forwarded-host'), 'iam.example.com');
    assert.equal(request.headers.get('forwarded'), null);
    return new Response(null, { status: 302, headers: { Location: '/oauth/consent?sessionID=abc', 'Set-Cookie': '__Host-lakehouse=value; Secure; HttpOnly; Path=/' } });
  });
  const response = await handleRequest(new Request('https://iam.example.com/web/login?sessionID=abc', {
    method: 'POST', body: 'username=%40user%3Aexample.com&password=test',
    headers: { Cookie: 'session=abc', Forwarded: 'host=evil.example', 'x-forwarded-host': 'evil.example', 'x-forwarded-proto': 'http' },
  }), env);
  assert.equal(response.status, 302);
  assert.match(response.headers.get('set-cookie'), /Secure; HttpOnly/);
});

test('WebSocket upgrades use the same named container', async () => {
  const result = new Response('upgrade placeholder');
  const env = environment(async request => {
    assert.equal(request.headers.get('upgrade'), 'websocket');
    return result;
  });
  assert.equal(await handleRequest(new Request('https://iam.example.com/socket/websocket?vsn=2.0.0', {
    headers: { Upgrade: 'websocket', Connection: 'Upgrade' },
  }), env), result);
});

test('secrets are runtime environment only with no insecure production defaults', () => {
  assert.throws(() => containerEnvironment({ ...environment(), JWT_SECRET: '' }), /Missing JWT_SECRET/);
  assert.throws(() => containerEnvironment({ ...environment(), SECRET_KEY_BASE: 'short' }), /64/);
  assert.throws(() => containerEnvironment({ ...environment(), IAM_REGISTRATION_KEY: '' }), /Missing IAM_REGISTRATION_KEY/);
  const env = containerEnvironment(environment());
  assert.equal(env.IAM_PUBLIC_URL, 'https://iam.example.com');
  assert.equal(env.IAM_DOMAIN, 'example.com');
  assert.equal(containerEnvironment({ ...environment(), MATRIX_DOMAIN: 'legacy.example' }).MATRIX_DOMAIN, 'legacy.example');
  assert.equal(env.IAM_ADMIN_PASSWORD, 'test-admin-password');
  assert.equal(env.IAM_REGISTRATION_KEY, 'test-invitation-key');
  assert.equal(env.IAM_RELAXED_CALLBACK_URLS, undefined);
});
