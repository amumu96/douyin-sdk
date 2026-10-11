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
  const save = jest.fn((next: WebProfileSession) => { Object.assign(state, structuredClone(next)); });
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
  expect(h.save.mock.calls[0]![0].serverCertificate!.serial).toBe('fixture-sn');
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

test.each(['/aweme/v1/web/commit/user/', '/passport/web/get_qrcode/', '/passport/web/check_qrconnect/'])('Node DTrait encrypts fresh path/time/features for %s without fabricated browser rendering features', async (path) => {
  const client = new NodeProfileDTrait(); const header = await client.header(path);
  const parts = header.split('_'); expect(Buffer.from(parts[1]!, 'base64')).toHaveLength(256);
  const bytes = Buffer.from(parts[2]!, 'base64');
  const key = (client as unknown as { core: { aesKey: string } }).core.aesKey;
  const decipher = createDecipheriv('aes-128-cbc', Buffer.from(key, 'hex'), bytes.subarray(0, 16));
  const payload = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(16)), decipher.final()]).toString());
  expect(payload.path).toBe(path); expect(payload.sdkVersion).toBe('1.0.31');
  expect(payload.timestamp).toBeGreaterThan(Date.now() / 1000 - 10); expect(payload.dtrait.length).toBeGreaterThan(10);
  expect(Object.keys(collectNodeDTraitFeatures().str!)).toEqual(expect.arrayContaining(['str_11', 'str_12', 'str_27']));
  expect(collectNodeDTraitFeatures().str).not.toHaveProperty('str_1');
  await expect(client.header('/v1/message/send')).rejects.toThrow('allow-listed');
});

test('avatar commit rechecks its source after async crypto and marks dispatch immediately before POST', async () => {
  const h = harness(); const dispatched = jest.fn(); let current = true;
  const original = NodeProfileDTrait.prototype.header;
  let calls = 0;
  const header = jest.spyOn(NodeProfileDTrait.prototype, 'header').mockImplementation(async function(this: NodeProfileDTrait, path: string) {
    const value = await original.call(this, path); if (++calls === 2) current = false; return value;
  });
  try {
    await expect(h.client.commit('avatar_uri', 'fixture-uri', AbortSignal.timeout(10000), {
      assertCurrent() { if (!current) throw new Error('superseded'); }, onCommitDispatch: dispatched,
    })).rejects.toThrow('superseded');
    expect(h.fetcher).toHaveBeenCalledTimes(1); expect(dispatched).not.toHaveBeenCalled();
  } finally { header.mockRestore(); }
  const second = harness();
  await second.client.commit('avatar_uri', 'fixture-uri', AbortSignal.timeout(10000), { onCommitDispatch: dispatched });
  expect(dispatched).toHaveBeenCalledTimes(1);
  expect(dispatched.mock.invocationCallOrder[0]).toBeLessThan(second.fetcher.mock.invocationCallOrder[1]!);
});

test.each([
  [8, 'unauthenticated'], [2166, 'business-rejected'], [null, 'invalid-response'],
])('self business status %s is distinct from an actual identity mismatch', async (status, code) => {
  const h = harness([Response.json({ status_code: status, user: { uid: UID } })]);
  await expect(h.client.prepare()).rejects.toMatchObject({ code, diagnostic: { status: 200 } });
  expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.save).not.toHaveBeenCalled();
});

test.each(['x-vc-bdturing-parameters', 'bdturing-verify', 'x-tt-verify-passport-decision', 'x-whale-throughput-abort-data'])(
  'a matching UID cannot override the %s authentication challenge', async name => {
    const h = harness([Response.json({ status_code: 0, user: { uid: UID } }, { headers: { [name]: 'private-challenge' } })]);
    await expect(h.client.commit('avatar_uri', 'fixture', AbortSignal.timeout(10000))).rejects.toMatchObject({ code: 'verification-required' });
    expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.save).not.toHaveBeenCalled();
  });

test('durable preparation refreshes same-Session cookies, then a fresh client reuses them', async () => {
  let state = structuredClone(fixture);
  const store = { load: () => structuredClone(state), save: (next: WebProfileSession) => { state = structuredClone(next); } };
  const fetcher = jest.fn(async () => Response.json({ status_code: 0, user: { uid: UID } }, { headers: { 'set-cookie': 'msToken=issued-fixture; Path=/' } }));
  await new NodeWebProfileClient({ platformUid: UID, store, assertActive() {}, fetcher }).prepare();
  expect(state.cookies).toContain('msToken=issued-fixture');
  const later = jest.fn(async (url: string | URL | Request, init?: RequestInit) => {
    expect(new URL(String(url)).searchParams.get('msToken')).toBe('issued-fixture');
    expect(new Headers(init!.headers).get('cookie')).toContain('msToken=issued-fixture');
    return Response.json({ status_code: 0, user: { uid: UID } });
  });
  await new NodeWebProfileClient({ platformUid: UID, store, assertActive() {}, fetcher: later }).verify();
  expect(fetcher).toHaveBeenCalledTimes(1); expect(later).toHaveBeenCalledTimes(1);
});

test.each([200, 403])('HTTP %s commit cookies persist without a second POST', async status => {
  let state = structuredClone(fixture), calls = 0;
  const client = new NodeWebProfileClient({ platformUid: UID, assertActive() {},
    store: { load: () => structuredClone(state), save: next => { state = structuredClone(next); } },
    fetcher: async (_url, init) => { calls++; return init?.method === 'GET'
      ? Response.json({ status_code: 0, user: { uid: UID } })
      : new Response('', { status, headers: { 'set-cookie': 'msToken=post-fixture; Path=/' } }); },
  });
  if (status === 403) await expect(client.commit('avatar_uri', 'fixture', AbortSignal.timeout(10000))).rejects.toMatchObject({ kind: 'http', status });
  else await client.commit('avatar_uri', 'fixture', AbortSignal.timeout(10000));
  expect(state.cookies).toContain('msToken=post-fixture'); expect(calls).toBe(2);
});

test('late preflight cannot overwrite explicitly reprovisioned credentials', async () => {
  const h = harness([Response.json({ status_code: 0, user: { uid: UID } })]);
  const original = h.fetcher.getMockImplementation()!;
  h.fetcher.mockImplementation(async (url, init) => { const response = await original(url, init); h.state.cookies += '; fresh_login=fixture'; return response; });
  await expect(h.client.prepare()).rejects.toMatchObject({ code: 'state-changed' });
  expect(h.save).not.toHaveBeenCalled(); expect(h.fetcher).toHaveBeenCalledTimes(1);
});

test('SDK avatar operation checks web auth before requesting even upload credentials', async () => {
  const h = harness([Response.json({ status_code: 8, status_msg: 'private-account-secret' })]);
  const desktop = { requestRaw: jest.fn(), getUserAgent: () => 'fixture' };
  const editor = new ProfileEditor(desktop, { platformUid: UID, webCommitClient: h.client });
  const stages: string[] = [], dispatch = jest.fn();
  await expect(editor.setAvatar(new Uint8Array([1]), { onStage: stage => stages.push(stage), onCommitDispatch: dispatch }))
    .rejects.toMatchObject({ code: 'unauthenticated', diagnostic: { businessCode: 8, status: 200 } });
  expect(stages).toEqual(['web_session_verify']); expect(desktop.requestRaw).not.toHaveBeenCalled(); expect(dispatch).not.toHaveBeenCalled();
});

test('a Session rejected after upload is diagnosed before the avatar POST, without replaying the upload', async () => {
  const h = harness([Response.json({ status_code: 0, user: { uid: UID } }), Response.json({ status_code: 8 })]);
  const editor = new ProfileEditor({ requestRaw: jest.fn(), getUserAgent: () => 'fixture' }, { platformUid: UID, webCommitClient: h.client });
  const upload = jest.spyOn(editor, 'uploadAvatar').mockResolvedValue({ uri: 'fixture-uri', format: 'png' });
  const stages: string[] = [], dispatch = jest.fn();
  await expect(editor.setAvatar(new Uint8Array([1]), { onStage: stage => stages.push(stage), onCommitDispatch: dispatch })).rejects.toMatchObject({ code: 'unauthenticated' });
  expect(stages).toEqual(['web_session_verify', 'sdk_upload', 'profile_commit_preflight']);
  expect(upload).toHaveBeenCalledTimes(1); expect(h.fetcher).toHaveBeenCalledTimes(2); expect(dispatch).not.toHaveBeenCalled();
});

test('a re-provisioned login during commit crypto blocks dispatch and preserves the newer file', async () => {
  const h = harness(); const dispatched = jest.fn();
  const original = NodeProfileDTrait.prototype.header;
  let calls = 0;
  const spy = jest.spyOn(NodeProfileDTrait.prototype, 'header').mockImplementation(async function(this: NodeProfileDTrait, path) {
    const value = await original.call(this, path);
    if (++calls === 2) h.state.cookies += '; externally_refreshed=fixture';
    return value;
  });
  try {
    await expect(h.client.commit('avatar_uri', 'fixture', AbortSignal.timeout(10000), { onCommitDispatch: dispatched })).rejects.toMatchObject({ code: 'state-changed' });
    expect(dispatched).not.toHaveBeenCalled(); expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.state.cookies).toContain('externally_refreshed=fixture');
  } finally { spy.mockRestore(); }
});

test.each([
  ['x-tt-verify-passport-decision', 'passport-decision-header'], ['bdturing-verify', 'bdturing-header'],
  ['x-vc-bdturing-parameters', 'captcha-parameters-header'], ['x-whale-throughput-abort-data', 'account-check-header'],
])('empty preflight challenge %s is typed and never submits bio', async (header, marker) => {
  const h = harness([new Response('', { headers: { [header]: 'private-token' } })]); const dispatch = jest.fn();
  const editor = new ProfileEditor({ getUserAgent: () => 'ua' } as never, { platformUid: UID, webCommitClient: h.client });
  await expect(editor.setSignature('x', { onCommitDispatch: dispatch })).rejects.toMatchObject({ code: 'verification-required', diagnostic: { status: 200, challengeMarkers: [marker] } });
  expect(h.fetcher).toHaveBeenCalledTimes(1); expect(h.save).not.toHaveBeenCalled(); expect(dispatch).not.toHaveBeenCalled();
});
test('bio stage trace covers actual dispatch, response and echo confirmation', async () => {
  const h = harness(); const stages: string[] = []; const dispatch = jest.fn(() => stages.push('profile_commit'));
  const editor = new ProfileEditor({ getUserAgent: () => 'ua' } as never, { platformUid: UID, webCommitClient: h.client });
  await expect(editor.setSignature('fixture bio', { onStage: stage => stages.push(stage), onCommitDispatch: dispatch })).resolves.toMatchObject({ statusCode: 0 });
  expect(stages.filter((stage, index) => stage !== stages[index - 1])).toEqual(['profile_commit_preflight','profile_commit','profile_response','profile_echo_verify']);
  expect(dispatch).toHaveBeenCalledTimes(1); expect(h.fetcher).toHaveBeenCalledTimes(2);
});
