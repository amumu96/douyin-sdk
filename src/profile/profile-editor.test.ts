import { ActionChallengeError } from '../http/action-challenge.js';
import { DouyinResponseError } from '../http/response.js';
import type { HttpResponse } from '../http/types.js';
import { crc32Hex } from '../services/im/upload.js';
import {
  AVATAR_IMAGEX_SERVICE_ID,
  PROFILE_RATE_LIMITED,
  PROFILE_UNCONFIRMED,
  ProfileEditor,
  parseRetryAt,
  type ProfileClient,
} from './profile-editor.js';

const UID = '10001';
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
const STORE_URI = `tos-cn-i-${AVATAR_IMAGEX_SERVICE_ID}/0123456789abcdef0123456789abcdef`;
const SECRET = 'fixture-secret-access-key';

function raw(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): HttpResponse<string> {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const status = init.status ?? 200;
  return { ok: status >= 200 && status < 300, status, headers: new Headers(init.headers ?? {}), data: text, rawText: text };
}

function harness(responses: HttpResponse<string>[], fetches: Response[] = []) {
  const requestRaw = jest.fn<Promise<HttpResponse<string>>, [string, RequestInit]>(async () => {
    const next = responses.shift();
    if (!next) throw new Error('unexpected Douyin request');
    return next;
  });
  const fetcher = jest.fn<Promise<Response>, [string | URL | Request, RequestInit?]>(async () => {
    const next = fetches.shift();
    if (!next) throw new Error('unexpected ImageX/storage request');
    return next;
  });
  const client: ProfileClient = {
    requestRaw, getUserAgent: () => 'fixture-agent', getDeviceId: () => '3240000001',
    getInstallId: () => '0', getGuid: () => 'fixture-guid', getScreenSize: () => ({ width: 1512, height: 982 }),
  };
  const editor = new ProfileEditor(client, { platformUid: UID, fetcher: fetcher as unknown as typeof fetch });
  return { editor, requestRaw, fetcher };
}

const committed = (user: Record<string, unknown>) => raw({ status_code: 0, status_msg: '',
  toast_back_info: { back: true, commit_status: 0, toast_msg: '修改成功' }, user });
const token = () => raw({ access_key_id: 'AKFIXTURE', secret_access_key: SECRET, session_token: 'fixture-session-token',
  expired_time: '2026-10-09T15:00:00+08:00', current_time: '2026-10-09T14:00:00+08:00', status_code: 0, status_msg: '' });
const apply = (storeUri = STORE_URI) => Response.json({
  ResponseMetadata: { RequestId: 'r1', Action: 'ApplyImageUpload', Version: '2018-08-01', Service: 'imagex', Region: 'cn-north-1' },
  Result: { UploadAddress: { StoreInfos: [{ StoreUri: storeUri, Auth: 'fixture-store-auth', UploadID: 'u1' }],
    UploadHosts: ['tos-fixture.bytedancevod.com'], UploadHeader: null, SessionKey: 'fixture-session-key' } },
});
const stored = (success = 0) => Response.json({ Version: 'v1', success, error: { code: success === 0 ? 200 : 500, error: '', error_code: 0, message: success === 0 ? 'Success' : 'fixture failure' }, payload: { hash: 'h', key: 'k' } });
const commitUpload = (status = 2000, uri = STORE_URI) => Response.json({
  ResponseMetadata: { RequestId: 'r2', Action: 'CommitImageUpload', Version: '2018-08-01', Service: 'imagex', Region: 'cn-north-1' },
  Result: { Results: [{ Uri: uri, UriStatus: status }], PluginResult: [{ ImageWidth: 1, ImageHeight: 1, ImageFormat: 'png' }] },
});

describe('ProfileEditor text fields', () => {
  it('commits only the bio to the desktop endpoint and confirms the echoed value', async () => {
    const { editor, requestRaw } = harness([committed({ signature: '新的简介', nickname: 'n' })]);
    await expect(editor.setSignature('新的简介')).resolves.toMatchObject({ statusCode: 0, user: { signature: '新的简介' } });
    const [url, init] = requestRaw.mock.calls[0]!;
    const target = new URL(url);
    expect(target.origin + target.pathname).toBe('https://imdesktop.douyin.com/aweme/v1/web/commit/user/');
    expect(target.searchParams.get('device_id')).toBe('3240000001');
    expect(target.searchParams.get('aid')).not.toBeNull();
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect([...new URLSearchParams(String(init.body))]).toEqual([['signature', '新的简介']]);
  });

  it('never reports an unechoed or different value as applied', async () => {
    for (const user of [{}, { signature: 'something else' }]) {
      const { editor } = harness([committed(user)]);
      await expect(editor.setSignature('requested')).resolves.toMatchObject({ statusCode: PROFILE_UNCONFIRMED });
    }
    const { editor } = harness([raw({ status_code: 0 })]);
    await expect(editor.setSignature('requested')).resolves.toMatchObject({ statusCode: PROFILE_UNCONFIRMED });
  });

  it('surfaces the daily limit with the stated retry time and does not retry', async () => {
    const { editor, requestRaw } = harness([raw({ status_code: PROFILE_RATE_LIMITED,
      status_msg: '简介1天内已修改5次，请在2026-10-10 22:39再次尝试修改' })]);
    const result = await editor.setSignature('x');
    expect(result.statusCode).toBe(PROFILE_RATE_LIMITED);
    expect(result.retryAt?.toISOString()).toBe('2026-10-10T14:39:00.000Z');
    expect(requestRaw).toHaveBeenCalledTimes(1);
  });

  it('turns challenges and HTTP failures into errors without a second request', async () => {
    const cases: [HttpResponse<string>, unknown][] = [
      [raw({ status_code: 0 }, { headers: { 'x-tt-verify-passport-decision': '{"decision":"verify"}' } }), ActionChallengeError],
      [raw({ status_code: 0 }, { headers: { 'bdturing-verify': 'fixture-challenge' } }), ActionChallengeError],
      [raw({ status_code: 0, verifyData: 'fixture-verify' }), ActionChallengeError],
      [raw('upstream down', { status: 503 }), DouyinResponseError],
    ];
    for (const [response, type] of cases) {
      const { editor, requestRaw } = harness([response]);
      await expect(editor.setSignature('x')).rejects.toBeInstanceOf(type);
      expect(requestRaw).toHaveBeenCalledTimes(1);
    }
  });

  it('validates nicknames locally and confirms the echo', async () => {
    const { editor, requestRaw } = harness([committed({ nickname: '流'.repeat(20) })]);
    await expect(editor.setNickname('   ')).rejects.toThrow('blank');
    await expect(editor.setNickname('流'.repeat(21))).rejects.toThrow(RangeError);
    expect(requestRaw).not.toHaveBeenCalled();
    await expect(editor.setNickname('流'.repeat(20))).resolves.toMatchObject({ statusCode: 0 });
    expect([...new URLSearchParams(String(requestRaw.mock.calls[0]![1].body))]).toEqual([['nickname', '流'.repeat(20)]]);
  });
});

describe('ProfileEditor avatar', () => {
  it('uploads through ImageX with the imagex signing scope and never edits the profile', async () => {
    const { editor, requestRaw, fetcher } = harness([token()], [apply(), stored(), commitUpload()]);
    await expect(editor.uploadAvatar(PNG)).resolves.toEqual({ uri: STORE_URI, format: 'png', width: 1, height: 1 });
    expect(requestRaw).toHaveBeenCalledTimes(1);
    expect(new URL(requestRaw.mock.calls[0]![0]).pathname).toBe('/aweme/v1/web/image/upload/token');

    const [applyUrl, applyInit] = fetcher.mock.calls[0]!;
    const applyTarget = new URL(String(applyUrl));
    expect(applyTarget.origin).toBe('https://imagex.bytedanceapi.com');
    expect(applyTarget.searchParams.get('Action')).toBe('ApplyImageUpload');
    expect(applyTarget.searchParams.get('Version')).toBe('2018-08-01');
    expect(applyTarget.searchParams.get('ServiceId')).toBe(AVATAR_IMAGEX_SERVICE_ID);
    const applyHeaders = applyInit!.headers as Record<string, string>;
    expect(applyHeaders['Authorization']).toMatch(/^AWS4-HMAC-SHA256 Credential=AKFIXTURE\/\d{8}\/cn-north-1\/imagex\/aws4_request, /);
    expect(applyHeaders['x-amz-security-token']).toBe('fixture-session-token');
    expect(applyHeaders['Cookie']).toBeUndefined();

    const [putUrl, putInit] = fetcher.mock.calls[1]!;
    expect(String(putUrl)).toBe(`https://tos-fixture.bytedancevod.com/${STORE_URI}`);
    expect(putInit!.method).toBe('PUT');
    const putHeaders = putInit!.headers as Record<string, string>;
    expect(putHeaders['Authorization']).toBe('fixture-store-auth');
    expect(putHeaders['Content-CRC32']).toBe(crc32Hex(PNG));
    expect(putHeaders['X-Storage-U']).toBe(UID);

    const [commitUrl, commitInit] = fetcher.mock.calls[2]!;
    const commitTarget = new URL(String(commitUrl));
    expect(commitTarget.searchParams.get('Action')).toBe('CommitImageUpload');
    expect(commitTarget.searchParams.get('SessionKey')).toBe('fixture-session-key');
    expect(commitInit!.method).toBe('POST');
  });

  it('sets the avatar only after a confirmed upload and confirms the echoed URI', async () => {
    const { editor, requestRaw } = harness([token(), committed({ avatar_larger: { uri: STORE_URI, url_list: [] } })],
      [apply(), stored(), commitUpload()]);
    await expect(editor.setAvatar(PNG)).resolves.toMatchObject({ statusCode: 0, avatarUri: STORE_URI });
    expect([...new URLSearchParams(String(requestRaw.mock.calls[1]![1].body))]).toEqual([['avatar_uri', STORE_URI]]);

    const unconfirmed = harness([token(), committed({ avatar_larger: { uri: 'tos-cn-i-other/zzz' } })], [apply(), stored(), commitUpload()]);
    await expect(unconfirmed.editor.setAvatar(PNG)).resolves.toMatchObject({ statusCode: PROFILE_UNCONFIRMED, avatarUri: STORE_URI });
  });

  it('stops before the profile change when any upload step fails', async () => {
    const failures: [HttpResponse<string>[], Response[]][] = [
      [[raw({ status_code: 8, status_msg: 'denied' })], []],
      [[token()], [apply('tos-cn-i-someoneelse/abc')]],
      [[token()], [apply(), stored(1)]],
      [[token()], [apply(), stored(), commitUpload(4001)]],
      [[token()], [apply(), stored(), commitUpload(2000, `${STORE_URI}x`)]],
      [[token()], [Response.json({ ResponseMetadata: { Error: { Code: 'InvalidAuthorization' } } }, { status: 403 })]],
    ];
    for (const [responses, fetches] of failures) {
      const { editor, requestRaw } = harness(responses, fetches);
      const error = await editor.setAvatar(PNG).then(() => undefined, (reason: unknown) => reason as Error);
      expect(error).toBeInstanceOf(Error);
      expect(error!.message).not.toContain(SECRET);
      expect(requestRaw.mock.calls.some(([url]) => url.includes('/commit/user/'))).toBe(false);
    }
  });

  it('rejects empty, oversized and unsupported images without any request', async () => {
    const { editor, requestRaw, fetcher } = harness([]);
    await expect(editor.uploadAvatar(new Uint8Array())).rejects.toThrow('empty');
    await expect(editor.uploadAvatar(new Uint8Array(20 * 1024 * 1024 + 1))).rejects.toThrow(RangeError);
    await expect(editor.uploadAvatar(Buffer.from('not an image'))).rejects.toThrow('unsupported');
    expect(requestRaw).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('requires a canonical platform UID for ImageX storage', () => {
    const client = { requestRaw: jest.fn(), getUserAgent: () => 'ua' } as unknown as ProfileClient;
    expect(() => new ProfileEditor(client, { platformUid: '' })).toThrow('platformUid');
  });
});

describe('parseRetryAt', () => {
  it('reads the China Standard Time stated by Douyin', () => {
    expect(parseRetryAt('请在2026-10-10 22:39再次尝试修改')?.toISOString()).toBe('2026-10-10T14:39:00.000Z');
    expect(parseRetryAt('请在2026-10-10 22:39:05再试')?.toISOString()).toBe('2026-10-10T14:39:05.000Z');
    expect(parseRetryAt('稍后再试')).toBeUndefined();
  });
});
