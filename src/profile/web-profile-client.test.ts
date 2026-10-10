import { createHash, createVerify, createDecipheriv, createHmac, createPrivateKey, diffieHellman, hkdfSync, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DesktopWebSecureSystemCrypto } from '../anti-bot/desktop-web-secure-crypto.js';
import { NodeProfileDTrait, collectNodeDTraitFeatures } from './node-dtrait.js';
import { NodeWebProfileClient, validateWebProfileSession, webProfileFileStore, WEB_PROFILE_STATE_FILE, type WebProfileSession } from './web-profile-client.js';
import { ProfileEditor } from './profile-editor.js';

const UID = '123456789012345678';
let fixture: WebProfileSession;
beforeAll(async () => {
  const pair = await new DesktopWebSecureSystemCrypto().generateNewKeyPairPEM();
  fixture = { schemaVersion: 1, platformUid: UID, cookies: 'sessionid=fixture-web-session; UIFID=fixture-uifid', userAgent: 'fixture-agent',
    // Unusable cached cert deliberately exercises the supported ECDSA fallback.
    serverCertificate: { pem: '-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----', serial: 'fixture', createdAt: Date.now() },
    ticketGuard: { privateKey: pair.privatePem, publicKey: pair.publicPem, ticket: 'fixture-ticket', tsSign: 'ts.2.fixture-sign',
      sessionHash: createHash('sha256').update('fixture-web-session').digest('hex') } };
});

function harness(responses = [new Response(`{"status_code":0,"user":{"uid":${UID}}}`), new Response('{"status_code":0,"user":{"signature":"fixture bio"}}')]) {
  const state = structuredClone(fixture);
  const save = jest.fn();
  const active = jest.fn();
  const fetcher = jest.fn(async (_url: string | URL | Request, _init?: RequestInit) => {
    const response = responses.shift(); if (!response) throw new Error('Unexpected fetch'); return response;
  });
  const client = new NodeWebProfileClient({ platformUid: UID, store: { load: () => state, save }, assertActive: active, fetcher: fetcher as typeof fetch });
  return { client, fetcher, state, save, active };
}

test('read-only verification uses web identity, guards and exact large UID; never POSTs or saves', async () => {
  const h = harness();
  await expect(h.client.verify()).resolves.toEqual({ status: 200, platformUid: UID });
  expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.save).not.toHaveBeenCalled();
  const [url, init] = h.fetcher.mock.calls[0]!;
  expect(new URL(String(url)).searchParams.get('aid')).toBe('6383');
  expect(init!.method).toBe('GET'); expect(init!.redirect).toBe('manual');
  const headers = new Headers(init!.headers);
  const publicKey = Buffer.from(headers.get('bd-ticket-guard-ree-public-key')!, 'base64');
  expect(publicKey.length).toBe(65); expect(publicKey[0]).toBe(4);
  const envelope = JSON.parse(Buffer.from(headers.get('bd-ticket-guard-client-data')!, 'base64').toString());
  expect(Object.keys(envelope).sort()).toEqual(['req_content', 'req_sign', 'timestamp', 'ts_sign']);
  const verifier = createVerify('SHA256').update(`ticket=fixture-ticket&path=/aweme/v1/web/user/profile/self/&timestamp=${envelope.timestamp}`);
  expect(verifier.verify(fixture.ticketGuard.publicKey, Buffer.from(envelope.req_sign, 'base64'))).toBe(true);
  expect(headers.get('bd-ticket-guard-web-version')).toBe('2');
  expect(headers.get('x-tt-session-dtrait')).toMatch(/^d0_[A-Za-z0-9+/=]+_[A-Za-z0-9+/=]+$/);
});

test('verified preflight and durable auth precede exactly one Unicode form POST', async () => {
  const h = harness(); const text = '中文 & 多行\n简介';
  await h.client.commit('signature', text, AbortSignal.timeout(10000));
  expect(h.fetcher).toHaveBeenCalledTimes(2); expect(h.save).toHaveBeenCalledTimes(1);
  expect(h.save.mock.invocationCallOrder[0]).toBeLessThan(h.fetcher.mock.invocationCallOrder[1]!);
  const [url, init] = h.fetcher.mock.calls[1]!; const target = new URL(String(url));
  expect(target.pathname).toBe('/aweme/v1/web/commit/user/');
  expect(target.searchParams.get('device_platform')).toBe('webapp');
  expect(target.searchParams.has('a_bogus')).toBe(true);
  expect(target.searchParams.has('awemeim_guid')).toBe(false);
  expect([...new URLSearchParams(String(init!.body))]).toEqual([['signature', text]]);
  const headers = new Headers(init!.headers);
  expect(headers.get('Origin')).toBe('https://www.douyin.com');
  expect(headers.get('x-secsdk-csrf-token')).toBe('DOWNGRADE');
  expect(headers.get('uifid')).toBe('fixture-uifid');
  expect(headers.get('cookie')).toBe(fixture.cookies);
});

test.each([
  new Response('{"status_code":8}'),
  new Response('{"status_code":0,"user":{"uid":"different"}}'),
  new Response('', { status: 200 }),
  new Response('', { status: 403 }),
  new Response('', { status: 302, headers: { location: 'https://example.com/' } }),
  new Response(`{"status_code":0,"user":{"uid":"${UID}"}}`, { headers: { 'bd-ticket-guard-result': '1' } }),
  new Response(`{"status_code":0,"user":{"uid":"${UID}"}}`, { headers: { 'set-cookie': 'sessionid=changed-session; Path=/' } }),
])('failed identity/response/Session preflight never dispatches POST or saves', async response => {
  const h = harness([response]);
  await expect(h.client.commit('signature', 'fixture', AbortSignal.timeout(10000))).rejects.toThrow();
  expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.save).not.toHaveBeenCalled();
});

test('retrieves the server certificate once and signs preflight/write with real ECDH/HKDF/HMAC', async () => {
  const server = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = server.publicKey.export({ type: 'spki', format: 'der' });
  const sequence = (...parts: Buffer[]) => {
    const bytes = Buffer.concat(parts);
    return Buffer.concat([Buffer.from(bytes.length < 128 ? [0x30, bytes.length] : [0x30, 0x81, bytes.length]), bytes]);
  };
  // Synthetic unsigned certificate shape: wire/protocol test, not certificate trust evidence.
  const pem = `-----BEGIN CERTIFICATE-----\n${sequence(sequence(...Array.from({ length: 6 }, () => Buffer.from([5, 0])), spki)).toString('base64')}\n-----END CERTIFICATE-----`;
  const h = harness([new Response(JSON.stringify({ message: 'success', data: { server_cert: pem, server_sn: 'fixture-sn' } })),
    new Response(`{"status_code":0,"user":{"uid":"${UID}"}}`), new Response('{"status_code":0}')]);
  delete h.state.serverCertificate;
  await h.client.commit('signature', 'fixture', AbortSignal.timeout(10000));
  expect(h.fetcher).toHaveBeenCalledTimes(3);
  expect(new URL(String(h.fetcher.mock.calls[0]![0])).pathname).toBe('/passport/ticket_guard/get_client_cert/');
  expect(h.fetcher.mock.calls[0]![1]!.body).toBe('server_data=1,aid=6383');
  const key = hkdfSync('sha256', diffieHellman({ privateKey: createPrivateKey(fixture.ticketGuard.privateKey), publicKey: server.publicKey }), '', '', 32);
  for (const [url, init] of h.fetcher.mock.calls.slice(1)) {
    const headers = new Headers(init!.headers);
    expect(headers.get('bd-ticket-guard-web-sign-type')).toBe('1');
    const envelope = JSON.parse(Buffer.from(headers.get('bd-ticket-guard-client-data')!, 'base64').toString());
    expect(envelope.req_sign).toBe(createHmac('sha256', Buffer.from(key)).update(`ticket=fixture-ticket&path=${new URL(String(url)).pathname}&timestamp=${envelope.timestamp}`).digest('base64'));
  }
  expect(h.save.mock.calls[0]![0].serverCertificate.serial).toBe('fixture-sn');
});

test('failed certificate fetch uses signed ECDSA fallback without repeating the certificate request', async () => {
  const h = harness([new Response('', { status: 503 }), new Response(`{"status_code":0,"user":{"uid":"${UID}"}}`), new Response('{"status_code":0}')]);
  delete h.state.serverCertificate;
  await h.client.commit('signature', 'fixture', AbortSignal.timeout(10000));
  expect(h.fetcher).toHaveBeenCalledTimes(3);
  expect(h.fetcher.mock.calls.slice(1).map(([, init]) => new Headers(init!.headers).get('bd-ticket-guard-web-sign-type'))).toEqual(['0', '0']);
});

test('persistence failure and account cancellation stop before business POST', async () => {
  const h = harness(); h.save.mockImplementation(() => { throw new Error('fixture IO failure'); });
  await expect(h.client.commit('signature', 'fixture', AbortSignal.timeout(10000))).rejects.toThrow('fixture IO failure');
  expect(h.fetcher).toHaveBeenCalledTimes(1);
  const second = harness(); second.active.mockImplementation(() => { throw new Error('retired'); });
  await expect(second.client.commit('signature', 'fixture', AbortSignal.timeout(10000))).rejects.toThrow('retired');
  expect(second.fetcher).not.toHaveBeenCalled();
});

test('empty 200 from the write reaches ProfileEditor as empty and never uses Desktop fallback', async () => {
  const h = harness([new Response(`{"status_code":0,"user":{"uid":"${UID}"}}`), new Response('')]);
  const desktop = { requestRaw: jest.fn(), requestSessionTicketWeb: jest.fn(), getUserAgent: () => 'desktop-fixture' };
  const editor = new ProfileEditor(desktop, { platformUid: UID, webCommitClient: h.client });
  await expect(editor.setSignature('fixture bio')).rejects.toMatchObject({ kind: 'empty', status: 200 });
  expect(h.fetcher).toHaveBeenCalledTimes(2);
  expect(desktop.requestRaw).not.toHaveBeenCalled(); expect(desktop.requestSessionTicketWeb).not.toHaveBeenCalled();
});

test('missing/mismatched/unsafe saved state fails closed without leaking credentials', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'web-profile-fixture-'));
  try {
    const store = webProfileFileStore(directory, UID);
    expect(() => store.load()).toThrow('unavailable');
    store.save(fixture); expect(store.load()).toMatchObject({ platformUid: UID });
    expect(JSON.parse(readFileSync(join(directory, WEB_PROFILE_STATE_FILE), 'utf8')).cookies).toBe(fixture.cookies);
    expect(() => validateWebProfileSession(fixture, 'wrong')).toThrow('identity-mismatch');
    expect(() => validateWebProfileSession({ ...fixture, cookies: 'sessionid=other' }, UID)).toThrow('session-changed');
    expect(() => validateWebProfileSession({ ...fixture, cookies: 'fixture\r\nsecret' }, UID)).toThrow('ticket-unavailable');
    chmodSync(join(directory, WEB_PROFILE_STATE_FILE), 0o644);
    expect(() => store.load()).toThrow('unavailable');
    writeFileSync(join(directory, WEB_PROFILE_STATE_FILE), '{"secret-cookie');
    chmodSync(join(directory, WEB_PROFILE_STATE_FILE), 0o600);
    expect(() => store.load()).toThrow('unavailable');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('Node DTrait encrypts fresh path/time/features; does not fabricate browser rendering features', async () => {
  const client = new NodeProfileDTrait(); const header = await client.header('/aweme/v1/web/commit/user/');
  const parts = header.split('_'); expect(Buffer.from(parts[1]!, 'base64')).toHaveLength(256);
  const bytes = Buffer.from(parts[2]!, 'base64');
  const key = (client as unknown as { core: { aesKey: string } }).core.aesKey;
  const decipher = createDecipheriv('aes-128-cbc', Buffer.from(key, 'hex'), bytes.subarray(0, 16));
  const payload = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(16)), decipher.final()]).toString());
  expect(payload.path).toBe('/aweme/v1/web/commit/user/'); expect(payload.sdkVersion).toBe('1.0.31');
  expect(payload.timestamp).toBeGreaterThan(Date.now() / 1000 - 10); expect(payload.dtrait.length).toBeGreaterThan(10);
  expect(Object.keys(collectNodeDTraitFeatures().str!)).toEqual(expect.arrayContaining(['str_11', 'str_12', 'str_27']));
  expect(collectNodeDTraitFeatures().str).not.toHaveProperty('str_1');
  await expect(client.header('/v1/message/send')).rejects.toThrow('allow-listed');
});
