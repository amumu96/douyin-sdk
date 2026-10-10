import { randomBytes } from 'node:crypto';
import { ActionChallengeError } from '../http/action-challenge.js';
import { DouyinResponseError, parseJsonResponse } from '../http/response.js';
import type { HttpResponse } from '../http/types.js';
import { desktopFingerprintParams, type DesktopScreenSize } from '../services/im/desktop.js';
import { sniffImageFormat, type ImageFormat } from '../services/im/media.js';
import { crc32Hex, signVodRequest, type UploadCredentials } from '../services/im/upload.js';
import type { WebProfileCommitClient, WebProfileOperation } from './web-profile-client.js';

// Profile endpoints exist only on the web origin; the desktop origin answers 404
// (live check 2026-10-09). Common params follow the IM upload config request.
const WEB_ORIGIN = 'https://www.douyin.com';
const WEB_REFERER = 'https://www.douyin.com/';
const COMMIT_USER_PATH = '/aweme/v1/web/commit/user/';
const IMAGE_TOKEN_PATH = '/aweme/v1/web/image/upload/token';
const IMAGEX_URL = 'https://imagex.bytedanceapi.com/';
const IMAGEX_SERVICE = 'imagex';
const IMAGEX_REGION = 'cn-north-1';
const IMAGEX_VERSION = '2018-08-01';
/** Avatar ImageX service; the store URIs it issues are prefixed `tos-cn-i-<id>`. */
export const AVATAR_IMAGEX_SERVICE_ID = 'c9aec8xkvj';
/** Douyin's profile editor counts at most 20 characters for a name. */
export const NICKNAME_MAX_LENGTH = 20;
const AVATAR_MAX_BYTES = 20 * 1024 * 1024;
const AVATAR_FORMATS: ReadonlySet<ImageFormat> = new Set(['jpeg', 'png', 'webp', 'gif']);
/** Business code returned when a field's daily change quota is used up. */
export const PROFILE_RATE_LIMITED = 2166;
/** Local code: the server answered 0 but did not echo the requested value. */
export const PROFILE_UNCONFIRMED = -3;

export interface ProfileClient {
  requestRaw(url: string, init: RequestInit, passportHeaders?: boolean): Promise<HttpResponse<string>>;
  /** The guarded web commit; the desktop ApiConnection signs it with the Session's REE ticket. */
  requestSessionTicketWeb?(url: string, init: RequestInit & { body: string }): Promise<HttpResponse<string>>;
  getUserAgent(): string;
  getDeviceId?(): string;
  getInstallId?(): string;
  getGuid?(): string;
  getScreenSize?(): DesktopScreenSize;
}

export interface ProfileEditorOptions {
  /** Platform UID of the signed-in account; ImageX storage requires it. */
  platformUid: string;
  deviceId?: string;
  avatarServiceId?: string;
  fetcher?: typeof fetch;
  /** Account-owned verified web authentication; Desktop IM cookies never enter this transport. */
  webCommitClient?: WebProfileCommitClient;
}

export interface ProfileUser {
  nickname?: string;
  signature?: string;
  /** Avatar store URIs echoed by the server (larger/medium/thumb), when present. */
  avatarUris: readonly string[];
}

export interface ProfileUpdateResult {
  /** 0 only when the server confirmed (echoed) the requested value. */
  statusCode: number;
  statusMsg: string;
  /** For PROFILE_RATE_LIMITED: the earliest retry time the server stated. */
  retryAt?: Date;
  user?: ProfileUser;
}

export interface UploadedAvatar {
  uri: string;
  format: ImageFormat;
  width?: number;
  height?: number;
}

export interface AvatarUpdateResult extends ProfileUpdateResult {
  avatarUri: string;
}

export interface ProfileOperationOptions extends WebProfileOperation { signal?: AbortSignal }

function active(operation: ProfileOperationOptions): void {
  operation.signal?.throwIfAborted(); operation.assertCurrent?.();
}

function deadline(milliseconds: number, operation: ProfileOperationOptions): AbortSignal {
  return operation.signal ? AbortSignal.any([operation.signal, AbortSignal.timeout(milliseconds)]) : AbortSignal.timeout(milliseconds);
}

/**
 * 资料编辑：简介、昵称、头像。
 *
 * 每次调用只提交一个字段，与抖音资料编辑框一致。修改受平台限频（例如简介每天 5 次），
 * 结果未知或未确认时不要自动重试：一次成功提交已经生效且计入额度。
 */
export class ProfileEditor {
  private readonly fetcher: typeof fetch;
  private readonly avatarServiceId: string;

  constructor(private readonly client: ProfileClient, private readonly options: ProfileEditorOptions) {
    if (!/^[1-9]\d{0,18}$/.test(options.platformUid)) throw new Error('platformUid is required for profile editing');
    this.fetcher = options.fetcher ?? globalThis.fetch;
    this.avatarServiceId = options.avatarServiceId ?? AVATAR_IMAGEX_SERVICE_ID;
  }

  /** 修改简介；空字符串清空简介。 */
  async setSignature(signature: string): Promise<ProfileUpdateResult> {
    if (typeof signature !== 'string') throw new TypeError('signature must be a string');
    const result = await this.commit('signature', signature);
    return confirm(result, user => user.signature === signature, 'signature');
  }

  /** 修改昵称；不能为空，最多 20 个字符。 */
  async setNickname(nickname: string): Promise<ProfileUpdateResult> {
    if (typeof nickname !== 'string') throw new TypeError('nickname must be a string');
    if (!nickname.trim()) throw new Error('nickname must not be blank');
    if (Array.from(nickname).length > NICKNAME_MAX_LENGTH) throw new RangeError(`nickname must not exceed ${NICKNAME_MAX_LENGTH} characters`);
    const result = await this.commit('nickname', nickname);
    return confirm(result, user => user.nickname === nickname, 'nickname');
  }

  /**
   * 上传头像图片到 ImageX 但不修改资料；返回可提交的 avatar URI。
   * 只消耗上传凭证，不计入资料修改额度。
   */
  async uploadAvatar(image: Uint8Array, operation: ProfileOperationOptions = {}): Promise<UploadedAvatar> {
    active(operation);
    if (!(image instanceof Uint8Array) || image.length === 0) throw new Error('avatar image is empty');
    if (image.length > AVATAR_MAX_BYTES) throw new RangeError('avatar image exceeds 20 MiB');
    const format = sniffImageFormat(image);
    if (!AVATAR_FORMATS.has(format)) throw new Error(`unsupported avatar image format: ${format}`);
    const credentials = await this.uploadCredentials(operation);
    const address = await this.applyUpload(credentials, operation);
    await this.putImage(address, image, operation);
    return { ...await this.commitUpload(credentials, address, operation), format };
  }

  /** 上传并设为头像。只有服务端回显新头像时才视为成功。 */
  async setAvatar(image: Uint8Array, operation: ProfileOperationOptions = {}): Promise<AvatarUpdateResult> {
    const uploaded = await this.uploadAvatar(image, operation);
    const result = await this.commit('avatar_uri', uploaded.uri, operation);
    const key = uploaded.uri.slice(uploaded.uri.indexOf('/') + 1);
    return { ...confirm(result, user => user.avatarUris.some(uri => uri === uploaded.uri || uri.endsWith(`/${key}`)), 'avatar'),
      avatarUri: uploaded.uri };
  }

  private commonParams(): URLSearchParams {
    const deviceId = this.client.getDeviceId?.() ?? this.options.deviceId ?? '0';
    const params = desktopFingerprintParams(deviceId || '0', this.client.getGuid?.() || '0',
      this.client.getScreenSize?.() ?? { width: 1728, height: 1117 }, this.client.getUserAgent());
    params.set('iid', this.client.getInstallId?.() || '0');
    return params;
  }

  private async commit(field: 'signature' | 'nickname' | 'avatar_uri', value: string, operation: ProfileOperationOptions = {}): Promise<ProfileUpdateResult> {
    active(operation);
    const url = `${WEB_ORIGIN}${COMMIT_USER_PATH}?${this.commonParams()}`;
    const init = {
      method: 'POST',
      // The web runtime's csrfWebToken rewrite supplies this public fallback
      // marker directly (macOS Chrome observation 2026-10-10), without a token
      // preflight. It is not the Passport CSRF cookie or an account secret.
      headers: { Accept: 'application/json, text/plain, */*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-secsdk-csrf-token': 'DOWNGRADE', Referer: WEB_REFERER, 'User-Agent': this.client.getUserAgent() },
      body: new URLSearchParams({ [field]: value }).toString(),
      signal: deadline(15_000, operation),
    };
    // An unsigned web commit returned HTTP 403 with ticket-guard result headers
    // (live check 2026-10-10). The signed request also returned 403; absence of
    // those headers does not prove acceptance. Keep the single-attempt boundary.
    if (!this.options.webCommitClient) operation.onCommitDispatch?.();
    const response = this.options.webCommitClient
      ? await this.options.webCommitClient.commit(field, value, init.signal, operation)
      : this.client.requestSessionTicketWeb
      ? await this.client.requestSessionTicketWeb(url, init)
      : await this.client.requestRaw(url, init, false);
    // A rejected HTTP status never reaches challenge handling or a retry.
    if (!response.ok) throw new DouyinResponseError('http', response.status, url, response.headers);
    if (response.headers.get('x-tt-verify-passport-decision')) {
      throw new ActionChallengeError('passport-decision', response.headers.get('x-tt-verify-passport-decision')!);
    }
    const bdturing = response.headers.get('bdturing-verify');
    if (bdturing) throw new ActionChallengeError('bdturing', bdturing);
    if (response.headers.get('x-vc-bdturing-parameters')) {
      throw new DouyinResponseError('captcha', response.status, url, response.headers);
    }
    const body = parseJsonResponse<Record<string, unknown>>(response, url);
    if (typeof body['verifyData'] === 'string' && body['verifyData']) throw new ActionChallengeError('bdturing', body['verifyData']);
    const statusCode = typeof body['status_code'] === 'number' && Number.isSafeInteger(body['status_code'])
      ? body['status_code'] : -1;
    const statusMsg = typeof body['status_msg'] === 'string' ? body['status_msg'] : '';
    const result: ProfileUpdateResult = { statusCode, statusMsg };
    if (statusCode === PROFILE_RATE_LIMITED) {
      const retryAt = parseRetryAt(statusMsg);
      if (retryAt) result.retryAt = retryAt;
    }
    const user = mapUser(body['user']);
    if (user) result.user = user;
    return result;
  }

  private async uploadCredentials(operation: ProfileOperationOptions): Promise<UploadCredentials> {
    active(operation);
    const url = `${WEB_ORIGIN}${IMAGE_TOKEN_PATH}?${this.commonParams()}`;
    const response = await this.client.requestRaw(url, {
      method: 'GET',
      headers: { Accept: 'application/json, text/plain, */*', Referer: WEB_REFERER, 'User-Agent': this.client.getUserAgent() },
      signal: deadline(15_000, operation),
    }, false);
    active(operation);
    if (!response.ok) throw new DouyinResponseError('http', response.status, url, response.headers);
    const body = parseJsonResponse<Record<string, unknown>>(response, url);
    const field = (name: string) => typeof body[name] === 'string' ? body[name] as string : '';
    const credentials = { accessKeyId: field('access_key_id'), secretAccessKey: field('secret_access_key'),
      sessionToken: field('session_token'), spaceName: this.avatarServiceId };
    if (body['status_code'] !== 0 || !credentials.accessKeyId || !credentials.secretAccessKey || !credentials.sessionToken) {
      // Never echo the token response: it can carry partial credentials.
      throw new Error(`image upload credentials unavailable (status ${String(body['status_code'])})`);
    }
    return credentials;
  }

  private async imagex(method: 'GET' | 'POST', query: Record<string, string>, credentials: UploadCredentials, operation: ProfileOperationOptions): Promise<Record<string, unknown>> {
    active(operation);
    const body = method === 'POST' ? new Uint8Array() : undefined;
    const signed = signVodRequest({ method, query, ...(body ? { body } : {}), credentials, date: new Date(),
      service: IMAGEX_SERVICE, region: IMAGEX_REGION });
    const response = await this.fetcher(`${IMAGEX_URL}?${signed.canonicalQuery}`, {
      method, redirect: 'error', signal: deadline(15_000, operation),
      headers: { ...signed.headers, Authorization: signed.authorization, 'User-Agent': this.client.getUserAgent() },
      ...(body ? { body } : {}),
    });
    let json: Record<string, unknown>;
    try { json = asRecord(await response.json()); } catch { throw new Error(`ImageX ${query['Action']} returned invalid JSON (HTTP ${response.status})`); }
    active(operation);
    const error = asRecord(asRecord(json['ResponseMetadata'])['Error']);
    if (!response.ok || error['Code'] || error['CodeN']) {
      throw new Error(`ImageX ${query['Action']} failed: ${String(error['Code'] ?? error['CodeN'] ?? response.status)}`);
    }
    return asRecord(json['Result']);
  }

  private async applyUpload(credentials: UploadCredentials, operation: ProfileOperationOptions): Promise<{ host: string; storeUri: string; authorization: string; sessionKey: string }> {
    const result = await this.imagex('GET', { Action: 'ApplyImageUpload', Version: IMAGEX_VERSION,
      ServiceId: this.avatarServiceId, s: randomBytes(8).toString('hex').slice(0, 11) }, credentials, operation);
    const address = asRecord(result['UploadAddress']);
    const store = asRecord((address['StoreInfos'] as unknown[] | undefined)?.[0]);
    const host = (address['UploadHosts'] as unknown[] | undefined)?.[0];
    const upload = {
      host: typeof host === 'string' ? host : '',
      storeUri: typeof store['StoreUri'] === 'string' ? store['StoreUri'] : '',
      authorization: typeof store['Auth'] === 'string' ? store['Auth'] : '',
      sessionKey: typeof address['SessionKey'] === 'string' ? address['SessionKey'] : '',
    };
    if (!/^[a-z0-9.-]+$/i.test(upload.host) || !upload.storeUri.startsWith(`tos-cn-i-${this.avatarServiceId}/`)
      || !upload.authorization || !upload.sessionKey) {
      throw new Error('ImageX apply response did not contain a usable upload address');
    }
    return upload;
  }

  private async putImage(address: { host: string; storeUri: string; authorization: string }, image: Uint8Array, operation: ProfileOperationOptions): Promise<void> {
    active(operation);
    const response = await this.fetcher(`https://${address.host}/${address.storeUri}`, {
      method: 'PUT', redirect: 'error', signal: deadline(60_000, operation), body: image,
      headers: { Authorization: address.authorization, 'Content-CRC32': crc32Hex(image), 'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="undefined"', 'X-Storage-U': this.options.platformUid,
        'User-Agent': this.client.getUserAgent() },
    });
    let json: Record<string, unknown> = {};
    try { json = asRecord(await response.json()); } catch { /* reported below */ }
    active(operation);
    if (!response.ok || json['success'] !== 0) {
      const error = asRecord(json['error']);
      throw new Error(`avatar storage upload failed: ${String(error['message'] ?? error['code'] ?? response.status)}`);
    }
  }

  private async commitUpload(credentials: UploadCredentials, address: { storeUri: string; sessionKey: string }, operation: ProfileOperationOptions): Promise<Omit<UploadedAvatar, 'format'>> {
    const result = await this.imagex('POST', { Action: 'CommitImageUpload', Version: IMAGEX_VERSION,
      SessionKey: address.sessionKey, ServiceId: this.avatarServiceId }, credentials, operation);
    const committed = asRecord((result['Results'] as unknown[] | undefined)?.[0]);
    if (committed['Uri'] !== address.storeUri || committed['UriStatus'] !== 2000) {
      throw new Error('ImageX commit did not confirm the uploaded avatar');
    }
    const plugin = asRecord((result['PluginResult'] as unknown[] | undefined)?.[0]);
    const uploaded: Omit<UploadedAvatar, 'format'> = { uri: address.storeUri };
    if (Number.isSafeInteger(plugin['ImageWidth']) && (plugin['ImageWidth'] as number) > 0) uploaded.width = plugin['ImageWidth'] as number;
    if (Number.isSafeInteger(plugin['ImageHeight']) && (plugin['ImageHeight'] as number) > 0) uploaded.height = plugin['ImageHeight'] as number;
    return uploaded;
  }
}

function confirm(result: ProfileUpdateResult, echoed: (user: ProfileUser) => boolean, field: string): ProfileUpdateResult {
  if (result.statusCode !== 0) return result;
  // Success needs the server's echo; an absent or different value is never published as applied.
  if (!result.user || !echoed(result.user)) {
    return { ...result, statusCode: PROFILE_UNCONFIRMED, statusMsg: `Douyin response did not confirm the requested ${field}` };
  }
  return result;
}

function mapUser(value: unknown): ProfileUser | undefined {
  const user = asRecord(value);
  if (!Object.keys(user).length) return undefined;
  const avatarUris = ['avatar_larger', 'avatar_medium', 'avatar_thumb']
    .map(key => asRecord(user[key])['uri'])
    .filter((uri): uri is string => typeof uri === 'string' && !!uri);
  return {
    ...(typeof user['nickname'] === 'string' ? { nickname: user['nickname'] } : {}),
    ...(typeof user['signature'] === 'string' ? { signature: user['signature'] } : {}),
    avatarUris,
  };
}

/** "…请在2026-10-10 22:39再次尝试修改" is stated in China Standard Time. */
export function parseRetryAt(message: string): Date | undefined {
  const match = /(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})(?::(\d{2}))?/.exec(message);
  if (!match) return undefined;
  const date = new Date(`${match[1]}T${match[2]}:${match[3] ?? '00'}+08:00`);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
