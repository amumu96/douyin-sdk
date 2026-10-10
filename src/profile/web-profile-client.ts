import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, renameSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { DesktopWebSecureSystemCrypto } from '../anti-bot/desktop-web-secure-crypto.js';
import { generateJumpbyteABogus } from '../anti-bot/aBogus.js';
import { CookieJar } from '../http/cookie-jar.js';
import { DouyinResponseError, parseJsonResponse } from '../http/response.js';
import type { HttpResponse } from '../http/types.js';
import { NodeProfileDTrait } from './node-dtrait.js';

const ORIGIN = 'https://www.douyin.com';
const SELF = '/aweme/v1/web/user/profile/self/';
const COMMIT = '/aweme/v1/web/commit/user/';
export const WEB_PROFILE_STATE_FILE = 'web-profile-session.json';

export interface WebProfileSession {
  schemaVersion: 1;
  platformUid: string;
  cookies: string;
  userAgent: string;
  verifiedAt?: string;
  serverCertificate?: { pem: string; serial: string; createdAt: number };
  ticketGuard: { privateKey: string; publicKey: string; ticket: string; tsSign: string; sessionHash: string };
}
export type WebProfileSessionCode = 'unavailable' | 'identity-mismatch' | 'ticket-unavailable' | 'session-changed'
  | 'unauthenticated' | 'business-rejected' | 'invalid-response' | 'verification-required' | 'state-changed';

/** Fixed metadata only: never attach response text, tokens, identities or URLs. */
export interface WebProfileSessionDiagnostic {
  status?: number; businessCode?: number; hasGuardResult?: boolean; hasGuardServerData?: boolean;
  hasCaptcha?: boolean; hasPassportDecision?: boolean; hasAccountCheck?: boolean;
}
export class WebProfileSessionError extends Error {
  override readonly name = 'WebProfileSessionError';
  constructor(readonly code: WebProfileSessionCode, readonly diagnostic: WebProfileSessionDiagnostic = {}) {
    super(`Web profile session ${code}`);
  }
}
function sessionHash(cookies: string): string {
  const jar = new CookieJar(cookies), id = jar.get('sessionid') || jar.get('sessionid_ss');
  if (!id) throw new WebProfileSessionError('unavailable');
  return createHash('sha256').update(id).digest('hex');
}
export function validateWebProfileSession(value: unknown, uid: string): WebProfileSession {
  const state = value as WebProfileSession | undefined;
  const guard = state?.ticketGuard;
  if (!/^\d{1,19}$/.test(uid) || state?.schemaVersion !== 1 || state.platformUid !== uid) {
    throw new WebProfileSessionError('identity-mismatch');
  }
  const bounded = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
  if (!bounded(state.cookies, 65536) || /[\r\n]/.test(state.cookies)
    || !bounded(state.userAgent, 1024) || /[\r\n]/.test(state.userAgent)
    || !guard || !bounded(guard.privateKey, 8192) || !bounded(guard.publicKey, 8192)
    || !bounded(guard.ticket, 16384) || !bounded(guard.tsSign, 16384) || !guard.tsSign.startsWith('ts.2')) {
    throw new WebProfileSessionError('ticket-unavailable');
  }
  if (guard.sessionHash !== sessionHash(state.cookies)) throw new WebProfileSessionError('session-changed');
  if (state.serverCertificate && (!bounded(state.serverCertificate.pem, 16384)
    || !bounded(state.serverCertificate.serial, 1024) || !Number.isSafeInteger(state.serverCertificate.createdAt))) {
    throw new WebProfileSessionError('ticket-unavailable');
  }
  return structuredClone(state);
}

export interface WebProfileStateStore { load(): unknown; save(state: WebProfileSession): void }
/** Account-owned private state only; no automatic browser cookie discovery/import. */
export function webProfileFileStore(directory: string, uid: string): WebProfileStateStore {
  const file = join(directory, WEB_PROFILE_STATE_FILE);
  return {
    load() {
      if (!existsSync(file)) throw new WebProfileSessionError('unavailable');
      const stat = lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072
        || process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new WebProfileSessionError('unavailable');
      try { return validateWebProfileSession(JSON.parse(readFileSync(file, 'utf8')), uid); }
      catch (error) { if (error instanceof WebProfileSessionError) throw error; throw new WebProfileSessionError('unavailable'); }
    },
    save(state) {
      const text = JSON.stringify(validateWebProfileSession(state, uid));
      const temp = `${file}.${randomUUID()}.tmp`;
      try { writeFileSync(temp, text, { mode: 0o600, flag: 'wx' }); renameSync(temp, file); }
      finally { if (existsSync(temp)) unlinkSync(temp); }
    },
  };
}

export interface WebProfileCommitClient {
  prepare?(signal: AbortSignal, operation?: WebProfileOperation): Promise<{ status: number; platformUid: string }>;
  commit(field: 'signature' | 'nickname' | 'avatar_uri', value: string, signal: AbortSignal, operation?: WebProfileOperation): Promise<HttpResponse<string>>;
}

/** Caller-owned cancellation and source fence, checked immediately before dispatch. */
export interface WebProfileOperation {
  assertCurrent?(): void;
  onCommitDispatch?(): void;
  onStage?(stage: 'web_session_verify' | 'sdk_upload' | 'profile_commit_preflight'): void;
}

/** Web authentication and crypto are isolated from the Desktop IM connection and its cookie jar. */
export class NodeWebProfileClient implements WebProfileCommitClient {
  private readonly crypto = new DesktopWebSecureSystemCrypto();
  private readonly dtrait = new NodeProfileDTrait();
  private busy = false;
  private certificate: WebProfileSession['serverCertificate'];
  private nextCertificateAttemptAfter = 0;
  constructor(private readonly options: {
    platformUid: string; store: WebProfileStateStore; assertActive(): void; fetcher?: typeof fetch;
  }) {}

  private async serverCertificate(state: WebProfileSession, signal: AbortSignal): Promise<WebProfileSession['serverCertificate']> {
    const cached = this.certificate ?? state.serverCertificate;
    if (cached && cached.createdAt <= Date.now() && cached.createdAt + 86400000 > Date.now()) return cached;
    if (Date.now() < this.nextCertificateAttemptAfter) return undefined;
    this.nextCertificateAttemptAfter = Date.now() + 60000;
    try {
      this.options.assertActive(); signal.throwIfAborted();
      // Public server-certificate retrieval, not a profile write/client CSR issuance.
      // The official loader sends comma-separated form pairs; retain that wire format.
      const response = await (this.options.fetcher ?? globalThis.fetch)(`${ORIGIN}/passport/ticket_guard/get_client_cert/?aid=6383&is_from_ttaccountsdk=1`, {
        method: 'POST', redirect: 'manual', signal: AbortSignal.any([signal, AbortSignal.timeout(3000)]),
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', Cookie: state.cookies, 'User-Agent': state.userAgent },
        body: 'server_data=1,aid=6383',
      });
      if (!response.ok) return undefined;
      const json = await response.json() as { message?: unknown; data?: { server_cert?: unknown; server_sn?: unknown } };
      const data = json.data;
      if (json.message !== 'success' || typeof data?.server_cert !== 'string' || typeof data.server_sn !== 'string'
        || !data.server_cert || data.server_cert.length > 16384 || !data.server_sn || data.server_sn.length > 1024) return undefined;
      this.certificate = { pem: data.server_cert, serial: data.server_sn, createdAt: Date.now() };
      return this.certificate;
    } catch {
      // Official keys owner falls back to ECDSA if server certificate/ECDH is unavailable.
      return undefined;
    }
  }

  private async securityHeaders(state: WebProfileSession, path: string, signal: AbortSignal): Promise<Record<string, string>> {
    const guard = state.ticketGuard;
    if (!await this.crypto.validateKeyPair(guard.privateKey, guard.publicKey)) throw new WebProfileSessionError('ticket-unavailable');
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = `ticket=${guard.ticket}&path=${path}&timestamp=${timestamp}`;
    let reqSign: string | undefined, hmac = false;
    const certificate = await this.serverCertificate(state, signal);
    if (certificate) try {
      const key = await this.crypto.deriveEcdhKey(guard.privateKey, certificate.pem);
      reqSign = await this.crypto.hmacSha256(key.bytes, payload); hmac = true;
    } catch { /* Exact supported ECDSA fallback; never skip the ticket signature. */ }
    if (!reqSign) reqSign = Buffer.from((await this.crypto.signWithECDSA(guard.privateKey, payload)).hex, 'hex').toString('base64');
    const publicKey = await this.crypto.extractPublicKeyHexFromPem(guard.publicKey);
    return {
      'bd-ticket-guard-version': '2', 'bd-ticket-guard-iteration-version': '1',
      'bd-ticket-guard-web-version': '2', 'bd-ticket-guard-web-sign-type': hmac ? '1' : '0',
      'bd-ticket-guard-ree-public-key': Buffer.from(publicKey.rawHex, 'hex').toString('base64'),
      'bd-ticket-guard-client-data': Buffer.from(JSON.stringify({ ts_sign: guard.tsSign,
        req_content: 'ticket,path,timestamp', req_sign: reqSign, timestamp })).toString('base64'),
      'x-tt-session-dtrait': await this.dtrait.header(path),
    };
  }

  private async request(state: WebProfileSession, jar: CookieJar, path: string, method: 'GET' | 'POST', body: string, signal: AbortSignal, operation: WebProfileOperation = {}): Promise<HttpResponse<string>> {
    this.options.assertActive(); signal.throwIfAborted(); operation.assertCurrent?.();
    const params = new URLSearchParams({ aid: '6383', device_platform: 'webapp', channel: 'channel_pc_web',
      version_code: '170400', version_name: '17.4.0' });
    if (method === 'GET') { params.set('source', 'channel_pc_web'); params.set('personal_center_strategy', '1'); params.set('publish_video_strategy_type', '2'); }
    const uifid = jar.get('UIFID') || jar.get('UIFID_TEMP');
    if (uifid) params.set('uifid', uifid);
    params.set('msToken', jar.get('msToken') || randomBytes(96).toString('base64url'));
    params.append('a_bogus', generateJumpbyteABogus({ userAgent: state.userAgent, query: params.toString(), body }));
    const headers = { Accept: 'application/json, text/plain, */*', Referer: `${ORIGIN}/`,
      'User-Agent': state.userAgent, Cookie: jar.toHeader(), ...await this.securityHeaders(state, path, signal),
      ...(uifid ? { uifid } : {}),
      ...(method === 'POST' ? { Origin: ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-secsdk-csrf-token': 'DOWNGRADE' } : {}),
    };
    // Recheck after crypto/collection and before the only business POST.
    this.options.assertActive(); signal.throwIfAborted(); operation.assertCurrent?.();
    const url = `${ORIGIN}${path}?${params}`;
    if (method === 'POST' && path === COMMIT && JSON.stringify(this.options.store.load()) !== JSON.stringify(state)) {
      throw new WebProfileSessionError('state-changed');
    }
    if (method === 'POST' && path === COMMIT) operation.onCommitDispatch?.();
    const res = await (this.options.fetcher ?? globalThis.fetch)(url, { method, headers, redirect: 'manual', signal,
      ...(method === 'POST' ? { body } : {}) });
    const rawText = await res.text(); signal.throwIfAborted(); this.options.assertActive(); operation.assertCurrent?.();
    for (const cookie of res.headers.getSetCookie()) jar.mergeSetCookie(cookie);
    return { ok: res.ok, status: res.status, headers: res.headers, rawText, data: rawText };
  }

  private async verifyState(state: WebProfileSession, jar: CookieJar, signal: AbortSignal, operation: WebProfileOperation = {}): Promise<HttpResponse<string>> {
    const response = await this.request(state, jar, SELF, 'GET', '', signal, operation);
    const body = parseJsonResponse<Record<string, unknown>>(response, ORIGIN + SELF, { preserveLargeIntegers: true });
    const status = body['status_code'];
    const diagnostic: WebProfileSessionDiagnostic = {
      status: response.status,
      ...(typeof status === 'number' && Number.isSafeInteger(status) && Math.abs(status) <= 1000000 ? { businessCode: status } : {}),
      hasGuardResult: response.headers.has('bd-ticket-guard-result'),
      hasGuardServerData: response.headers.has('bd-ticket-guard-server-data'),
      hasCaptcha: response.headers.has('x-vc-bdturing-parameters') || response.headers.has('bdturing-verify'),
      hasPassportDecision: response.headers.has('x-tt-verify-passport-decision'),
      hasAccountCheck: response.headers.has('x-whale-throughput-abort-data'),
    };
    if (diagnostic.hasCaptcha || diagnostic.hasPassportDecision || diagnostic.hasAccountCheck) {
      throw new WebProfileSessionError('verification-required', diagnostic);
    }
    const guardResult = response.headers.get('bd-ticket-guard-result');
    if (guardResult !== null && guardResult !== '0') throw new WebProfileSessionError('ticket-unavailable', diagnostic);
    if (status === 8) throw new WebProfileSessionError('unauthenticated', diagnostic);
    if (typeof status !== 'number' || !Number.isSafeInteger(status)) throw new WebProfileSessionError('invalid-response', diagnostic);
    if (status !== 0) throw new WebProfileSessionError('business-rejected', diagnostic);
    const user = body['user'] as { uid?: unknown } | undefined;
    if (!user || !/^[1-9]\d{0,18}$/.test(String(user.uid))) throw new WebProfileSessionError('invalid-response', diagnostic);
    if (String(user.uid) !== this.options.platformUid) throw new WebProfileSessionError('identity-mismatch', diagnostic);
    // A changed Session cannot inherit an old ticket merely because its UID matches.
    if (state.ticketGuard.sessionHash !== sessionHash(jar.toHeader())) throw new WebProfileSessionError('session-changed', diagnostic);
    return response;
  }

  /** Read-only identity/security preflight. Never calls the commit endpoint. */
  async verify(signal = AbortSignal.timeout(15000)): Promise<{ status: number; platformUid: string }> {
    const state = validateWebProfileSession(this.options.store.load(), this.options.platformUid);
    const jar = new CookieJar(state.cookies);
    const response = await this.verifyState(state, jar, signal);
    return { status: response.status, platformUid: state.platformUid };
  }

  private persist(state: WebProfileSession, jar: CookieJar, expected: unknown, signal: AbortSignal, operation: WebProfileOperation): WebProfileSession {
    this.options.assertActive(); signal.throwIfAborted(); operation.assertCurrent?.();
    // A separately provisioned login must never be overwritten by a late response.
    if (JSON.stringify(this.options.store.load()) !== JSON.stringify(expected)) throw new WebProfileSessionError('state-changed');
    const next = validateWebProfileSession({ ...state, cookies: jar.toHeader(),
      ...(this.certificate ? { serverCertificate: this.certificate } : {}) }, this.options.platformUid);
    this.options.store.save(next);
    return next;
  }

  /** Auth-only preflight with durable same-Session Cookie/certificate refresh. No avatar upload or commit. */
  async prepare(signal = AbortSignal.timeout(15000), operation: WebProfileOperation = {}): Promise<{ status: number; platformUid: string }> {
    if (this.busy) throw new Error('Web profile operation already active');
    this.busy = true;
    try {
      const original = structuredClone(this.options.store.load()), state = validateWebProfileSession(original, this.options.platformUid);
      const jar = new CookieJar(state.cookies);
      const response = await this.verifyState(state, jar, signal, operation);
      state.verifiedAt = new Date().toISOString();
      this.persist(state, jar, original, signal, operation);
      return { status: response.status, platformUid: state.platformUid };
    } finally { this.busy = false; }
  }

  async commit(field: 'signature' | 'nickname' | 'avatar_uri', value: string, signal: AbortSignal, operation: WebProfileOperation = {}): Promise<HttpResponse<string>> {
    if (!['signature', 'nickname', 'avatar_uri'].includes(field) || typeof value !== 'string') throw new Error('Invalid web profile field');
    if (this.busy) throw new Error('Web profile operation already active');
    this.busy = true;
    try {
      const original = structuredClone(this.options.store.load());
      let state = validateWebProfileSession(original, this.options.platformUid);
      const jar = new CookieJar(state.cookies);
      operation.onStage?.('profile_commit_preflight');
      await this.verifyState(state, jar, signal, operation);
      state.verifiedAt = new Date().toISOString();
      // Save refreshed authentication before any write. A failed save prevents dispatch.
      state = this.persist(state, jar, original, signal, operation);
      const response = await this.request(state, jar, COMMIT, 'POST', new URLSearchParams({ [field]: value }).toString(), signal, operation);
      // Response Cookie rotation belongs to this same verified Session, including HTTP failures.
      // Never attach a previous ticket to a changed Session or resend the business POST.
      if (jar.toHeader() !== state.cookies) this.persist(state, jar, state, signal, operation);
      if (!response.ok) throw new DouyinResponseError('http', response.status, ORIGIN + COMMIT, response.headers);
      return response;
    } finally { this.busy = false; }
  }
}
