import { createPublicKey, createVerify } from 'node:crypto';
import { buildPassportSignQs, buildPassportAidSign } from '../passport/signQs.js';
import { NodeWebProfileQrLogin } from './web-profile-login.js';

const uid = '123456789012345678';
function harness(mode = 'ok') {
  const paths: string[] = []; let publicKey = '', polls = 0;
  const fetcher = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input)), headers = new Headers(init?.headers); paths.push(url.pathname);
    expect(url.origin).toBe('https://www.douyin.com'); expect(init?.redirect).toBe('manual');
    if (url.pathname.includes('get_qrcode') || url.pathname.includes('check_qrconnect')) {
      const query = Object.fromEntries(url.searchParams); delete query['sign']; delete query['qs']; delete query['a_bogus']; delete query['msToken'];
      expect(url.searchParams.get('a_bogus')).toBeTruthy(); expect(query['device_platform']).toBe('web_app');
      expect(query['passport_jssdk_version']).toBe('2.4.12'); expect(query['passport_jssdk_type']).toBe('normal'); expect(query['request_host']).toBe('https://www.douyin.com');
      expect(headers.get('bd-ticket-guard-web-sign-type')).toBe('0'); expect(headers.get('x-tt-session-dtrait')).toBeTruthy();
      const signed = buildPassportSignQs({ query, body: init?.method === 'POST' ? Object.fromEntries(new URLSearchParams(String(init.body))) : {}, appKey: '163e7ce78d58971a41f5b969996d85c2' });
      expect(url.searchParams.get('sign')).toBe(signed.sign); expect(url.searchParams.get('qs')).toBe(signed.qs);
      expect(headers.get('x-tt-passport-aid-sign')).toBe(buildPassportAidSign({ aid: '6383', path: url.pathname, ts: query['ts']!, appKey: '163e7ce78d58971a41f5b969996d85c2' }));
    }
    expect(url.pathname).not.toBe('/aweme/v1/web/commit/user/'); expect(url.pathname).not.toBe('/aweme/v1/web/image/upload/token');
    if (url.pathname === '/passport/web/get_qrcode/') {
      expect(init?.method).toBe('GET'); expect(url.searchParams.get('aid')).toBe('6383'); expect(url.searchParams.get('next')).toBe('https://www.douyin.com');
      publicKey = headers.get('bd-ticket-guard-ree-public-key')!;
      const cookie = headers.get('cookie')!.split('; ').find(x => x.startsWith('bd_ticket_guard_client_data='))!.slice('bd_ticket_guard_client_data='.length);
      expect(cookie).toBe(encodeURIComponent(decodeURIComponent(cookie)));
      expect(JSON.parse(Buffer.from(decodeURIComponent(cookie), 'base64').toString())['bd-ticket-guard-ree-public-key']).toBe(publicKey);
      return Response.json({ message: 'success', data: { error_code: 0, token: 'fixture-token', qrcode: 'fixture-png-base64', expire_time: 2000000000 } }, { headers: { 'set-cookie': 'passport_csrf_token=fixture-csrf; Path=/', ...(mode === 'early-ticket' ? { 'bd-ticket-guard-server-data': Buffer.from(JSON.stringify({ ticket: 'early', ts_sign: 'ts.2.early' })).toString('base64') } : {}) } });
    }
    if (url.pathname === '/passport/web/check_qrconnect/') {
      polls++; expect(init?.method).toBe('POST'); expect(headers.get('bd-ticket-guard-ree-public-key')).toBe(publicKey);
      expect(headers.get('x-tt-passport-csrf-token')).toBe('fixture-csrf'); expect(new URLSearchParams(String(init?.body)).get('token')).toBe('fixture-token');
      if (mode === 'challenge') return Response.json({ message: 'error', data: { error_code: 1105, private: 'secret' } });
      if (mode === 'redirect') return new Response('', { status: 302, headers: { location: 'https://evil.invalid/secret' } });
      if (mode === 'expired') return Response.json({ message: 'success', data: { error_code: 0, status: 'expired' } });
      if (polls === 1) return Response.json({ message: 'success', data: { error_code: 0, status: 'scanned' } });
      return Response.json({ message: 'success', data: { error_code: 0, status: 'confirmed', user_data: { user_id_str: mode === 'wrong' ? '999' : uid } } }, { headers: {
        'set-cookie': 'sessionid=fixture-web-login-session; Path=/',
        ...(['no-ticket','early-ticket'].includes(mode) ? {} : { 'bd-ticket-guard-server-data': Buffer.from(JSON.stringify({ ticket: 'fixture-ticket', ts_sign: 'ts.2.fixture' })).toString('base64') }),
      } });
    }
    if (url.pathname === '/passport/ticket_guard/get_client_cert/') return new Response('', { status: 503 });
    if (url.pathname === '/aweme/v1/web/user/profile/self/') {
      expect(init?.method).toBe('GET'); expect(headers.get('cookie')).toContain('sessionid=fixture-web-login-session');
      expect(headers.get('bd-ticket-guard-ree-public-key')).toBe(publicKey);
      const point = Buffer.from(publicKey, 'base64'), envelope = JSON.parse(Buffer.from(headers.get('bd-ticket-guard-client-data')!, 'base64').toString());
      const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
      expect(createVerify('SHA256').update(`ticket=fixture-ticket&path=${url.pathname}&timestamp=${envelope.timestamp}`).verify(key, Buffer.from(envelope.req_sign, 'base64'))).toBe(true);
      return Response.json({ status_code: mode === 'rejected-self' ? 8 : 0, user: { uid } });
    }
    throw new Error('Unexpected fixture HTTP');
  });
  const active = jest.fn();
  return { login: new NodeWebProfileQrLogin({ platformUid: uid, userAgent: 'fixture', assertActive: active, fetcher }), paths, fetcher, active };
}

test('explicit QR flow keeps one fresh key owner, Passport CSRF, ticket and independent self identity; never writes a profile', async () => {
  const h = harness(); await expect(h.login.getQrcode()).resolves.toMatchObject({ qrcodeBase64: 'fixture-png-base64' });
  await expect(h.login.getQrcode()).rejects.toThrow();
  await expect(h.login.poll()).resolves.toEqual({ status: 'scanned' });
  const result = await h.login.poll(); expect(result.status).toBe('confirmed');
  if (result.status === 'confirmed') { expect(result.session.platformUid).toBe(uid); expect(result.session.ticketGuard.tsSign).toBe('ts.2.fixture'); expect(result.session.cookies).not.toContain('bd_ticket_guard_server_data'); }
  expect(h.paths).toEqual(['/passport/web/get_qrcode/', '/passport/web/check_qrconnect/', '/passport/web/check_qrconnect/', '/passport/ticket_guard/get_client_cert/', '/aweme/v1/web/user/profile/self/']);
  await expect(h.login.poll()).rejects.toThrow(); expect(h.fetcher).toHaveBeenCalledTimes(5);
});

test.each([['wrong', 'identity-mismatch'], ['no-ticket', 'ticket-unavailable'], ['early-ticket', 'ticket-unavailable'], ['rejected-self', 'unauthenticated']])('confirmed login %s cannot be promoted or polled again', async (mode, code) => {
  const h = harness(mode); await h.login.getQrcode(); await h.login.poll(); await expect(h.login.poll()).rejects.toMatchObject({ code });
  const calls = h.fetcher.mock.calls.length; await expect(h.login.poll()).rejects.toThrow(); expect(h.fetcher).toHaveBeenCalledTimes(calls);
});

test.each([['challenge', 'verification-required'], ['redirect', undefined], ['expired', 'unauthenticated']])('QR %s stops without following a redirect or automatic replacement', async (mode, code) => {
  const h = harness(mode); await h.login.getQrcode();
  if (code) await expect(h.login.poll()).rejects.toMatchObject({ code }); else await expect(h.login.poll()).rejects.toMatchObject({ kind: 'http', status: 302 });
  expect(h.fetcher).toHaveBeenCalledTimes(2);
  await expect(h.login.poll()).rejects.toThrow(); expect(h.fetcher).toHaveBeenCalledTimes(2);
});

test('cancelled explicit login never dispatches even a QR or pending poll', async () => {
  const h = harness(), controller = new AbortController(); controller.abort(); await expect(h.login.getQrcode(controller.signal)).rejects.toThrow(); expect(h.fetcher).not.toHaveBeenCalled();
  const second = harness(); await second.login.getQrcode(); second.active.mockImplementation(() => { throw Error('retired'); });
  await expect(second.login.poll()).rejects.toThrow('retired'); expect(second.fetcher).toHaveBeenCalledTimes(1);
});
