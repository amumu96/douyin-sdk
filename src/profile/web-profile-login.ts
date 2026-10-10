import { createHash } from 'node:crypto';
import { DesktopWebSecureSystemCrypto } from '../anti-bot/desktop-web-secure-crypto.js';
import { buildPassportAidSign, buildPassportSignQs, passportNoonUtcTs } from '../passport/signQs.js';
import { generateJumpbyteABogus } from '../anti-bot/aBogus.js';
import { NodeProfileDTrait } from './node-dtrait.js';
import { CookieJar } from '../http/cookie-jar.js';
import { parseJsonResponse } from '../http/response.js';
import { NodeWebProfileClient, validateWebProfileSession, WebProfileSessionError, type WebProfileSession } from './web-profile-client.js';

const ORIGIN = 'https://www.douyin.com';
const QR = '/passport/web/get_qrcode/';
const POLL = '/passport/web/check_qrconnect/';
const NEXT = ORIGIN;
// Public aid=6383 WebInterfaceSdk configuration in the official web client (2026-10-10).
const WEB_APP_KEY = '163e7ce78d58971a41f5b969996d85c2';
const record = (value: unknown): Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};

/** Explicit owner-driven web QR login; no IM login, browser runtime, profile writes or automatic retry. */
export class NodeWebProfileQrLogin {
  private readonly dtrait = new NodeProfileDTrait();
  private readonly crypto = new DesktopWebSecureSystemCrypto();
  private readonly jar = new CookieJar();
  private pair: { privatePem: string; publicPem: string } | undefined;
  private publicKey = '';
  private token = '';
  private serverData: { ticket: string; tsSign: string; sessionHash?: string } | undefined;
  private busy = false;
  private finished = false;
  constructor(private readonly options: { platformUid: string; userAgent: string; assertActive(): void; fetcher?: typeof fetch }) {
    if (!/^[1-9]\d{0,18}$/.test(options.platformUid) || !options.userAgent || options.userAgent.length > 1024 || /[\r\n]/.test(options.userAgent)) throw new WebProfileSessionError('unavailable');
  }

  private active(signal: AbortSignal): void { signal.throwIfAborted(); this.options.assertActive(); }
  private async request(path: typeof QR | typeof POLL, signal: AbortSignal): Promise<Record<string, unknown>> {
    this.active(signal);
    const post = path === POLL, ts = passportNoonUtcTs();
    const params = new URLSearchParams({ passport_jssdk_version: '2.4.12', passport_jssdk_type: 'normal', language: 'zh',
      aid: '6383', device_platform: 'web_app', is_from_ttaccountsdk: '1',
      is_new_login: '1', is_from_iesaccountsaas: '1', request_host: ORIGIN,
      account_sdk_source: 'web', p_js_v: '2.4.12', p_js_t: 'pro',
      ...(!post ? { next: NEXT, need_logo: 'false', need_short_url: 'false' } : {}) });
    params.set('ts', ts);
    const headers: Record<string, string> = { Accept: 'application/json', 'User-Agent': this.options.userAgent, Referer: ORIGIN + '/', Cookie: this.jar.toHeader(),
      'bd-ticket-guard-version': '2', 'bd-ticket-guard-iteration-version': '1', 'bd-ticket-guard-ree-public-key': this.publicKey, 'bd-ticket-guard-web-version': '2',
      'bd-ticket-guard-web-sign-type': '0', 'x-tt-session-dtrait': await this.dtrait.header(path) };
    this.active(signal);
    const bodyFields = { need_logo: 'false', need_short_url: 'false', is_frontier: 'false', token: this.token, is_new_login: '1', next: NEXT };
    const body = new URLSearchParams(bodyFields).toString();
    const signed = buildPassportSignQs({ query: Object.fromEntries(params), body: post ? bodyFields : {}, appKey: WEB_APP_KEY });
    params.set('sign', signed.sign); params.set('qs', signed.qs);
    const msToken = this.jar.get('msToken'); if (msToken) params.set('msToken', msToken);
    params.set('a_bogus', generateJumpbyteABogus({ query: params.toString(), body: post ? body : '', userAgent: this.options.userAgent }));
    headers['x-tt-passport-aid-sign'] = buildPassportAidSign({ aid: '6383', path, ts, appKey: WEB_APP_KEY });
    if (post) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'; headers['Origin'] = ORIGIN;
      headers['x-tt-passport-csrf-token'] = this.jar.get('passport_csrf_token') || this.jar.get('passport_csrf_token_default') || '';
    }
    const response = await (this.options.fetcher ?? globalThis.fetch)(ORIGIN + path + '?' + params, {
      method: post ? 'POST' : 'GET', redirect: 'manual', headers, signal, ...(post ? { body } : {}),
    });
    const rawText = await response.text(); this.active(signal);
    const json = parseJsonResponse<Record<string, unknown>>({ ok: response.ok, status: response.status, headers: response.headers, data: rawText, rawText }, ORIGIN + path, { preserveLargeIntegers: true });
    if (response.headers.has('x-vc-bdturing-parameters') || response.headers.has('x-tt-verify-passport-decision') || response.headers.has('x-whale-throughput-abort-data')) throw new WebProfileSessionError('verification-required');
    if (response.headers.has('bd-ticket-guard-result') && response.headers.get('bd-ticket-guard-result') !== '0') throw new WebProfileSessionError('ticket-unavailable');
    const data = record(json['data']);
    if (json['message'] !== 'success' || data['error_code'] !== 0) {
      throw new WebProfileSessionError(data['error_code'] === 1105 || data['error_code'] === 2046 ? 'verification-required' : 'business-rejected', {
        status: response.status, ...(typeof data['error_code'] === 'number' && Number.isSafeInteger(data['error_code']) && Math.abs(data['error_code']) <= 1000000 ? { businessCode: data['error_code'] } : {}),
      });
    }
    for (const cookie of response.headers.getSetCookie()) this.jar.mergeSetCookie(cookie);
    // Only this login's TLS response can provide the ticket. Never borrow an existing account's ticket.
    const encoded = response.headers.get('bd-ticket-guard-server-data') || this.jar.get('bd_ticket_guard_server_data');
    if (encoded) {
      try {
        if (encoded.length > 65536) throw new Error();
        const sign = record(JSON.parse(Buffer.from(decodeURIComponent(encoded), 'base64').toString('utf8')));
        if (typeof sign['ticket'] !== 'string' || !sign['ticket'] || sign['ticket'].length > 16384 || typeof sign['ts_sign'] !== 'string' || !sign['ts_sign'].startsWith('ts.2') || sign['ts_sign'].length > 16384) throw new Error();
        const sessionId = this.jar.get('sessionid') || this.jar.get('sessionid_ss');
        this.serverData = { ticket: sign['ticket'], tsSign: sign['ts_sign'],
          ...(sessionId ? { sessionHash: createHash('sha256').update(sessionId).digest('hex') } : {}) };
        this.jar.delete('bd_ticket_guard_server_data');
      } catch { throw new WebProfileSessionError('ticket-unavailable'); }
    }
    return data;
  }

  async getQrcode(signal = AbortSignal.timeout(15000)): Promise<{ qrcodeBase64: string; expireTime: number }> {
    if (this.busy || this.token || this.finished) throw new WebProfileSessionError('unavailable');
    this.busy = true;
    try {
      this.pair = await this.crypto.generateNewKeyPairPEM(); this.active(signal);
      this.publicKey = Buffer.from((await this.crypto.extractPublicKeyHexFromPem(this.pair.publicPem)).rawHex, 'hex').toString('base64');
      this.jar.set('bd_ticket_guard_client_data', encodeURIComponent(Buffer.from(JSON.stringify({ 'bd-ticket-guard-version': 2, 'bd-ticket-guard-iteration-version': 1,
        'bd-ticket-guard-ree-public-key': this.publicKey, 'bd-ticket-guard-web-version': 2 })).toString('base64')));
      this.jar.set('bd_ticket_guard_client_web_domain', '2');
      const data = await this.request(QR, signal);
      if (typeof data['token'] !== 'string' || !data['token'] || data['token'].length > 16384 || typeof data['qrcode'] !== 'string' || !data['qrcode'] || data['qrcode'].length > 1048576
        || typeof data['expire_time'] !== 'number' || !Number.isSafeInteger(data['expire_time'])) throw new WebProfileSessionError('invalid-response');
      this.token = data['token'];
      return { qrcodeBase64: data['qrcode'], expireTime: data['expire_time'] };
    } finally { this.busy = false; }
  }

  /** Each caller-authorized poll makes one authentication request. Does not save/promote account state. */
  async poll(signal = AbortSignal.timeout(15000)): Promise<{ status: 'new' | 'scanned' } | { status: 'confirmed'; session: WebProfileSession }> {
    if (this.busy || !this.token || !this.pair || this.finished) throw new WebProfileSessionError('unavailable');
    this.busy = true;
    try {
      const data = await this.request(POLL, signal), status = data['status'];
      if (status === 'new' || status === '1') return { status: 'new' };
      if (status === 'scanned' || status === '2') return { status: 'scanned' };
      if (status !== 'confirmed' && status !== '3') { this.finished = true; throw new WebProfileSessionError('unauthenticated'); }
      // Confirmation is terminal even if validation fails; there is no automatic auth/write replay.
      this.finished = true;
      const uid = record(data['user_data'])['user_id_str'];
      if (uid !== undefined && String(uid) !== this.options.platformUid) throw new WebProfileSessionError('identity-mismatch');
      const sessionId = this.jar.get('sessionid') || this.jar.get('sessionid_ss');
      if (!sessionId || !this.serverData || this.serverData.sessionHash !== createHash('sha256').update(sessionId).digest('hex')) throw new WebProfileSessionError('ticket-unavailable');
      this.jar.delete('bd_ticket_guard_server_data');
      const session = validateWebProfileSession({ schemaVersion: 1, platformUid: this.options.platformUid, userAgent: this.options.userAgent, cookies: this.jar.toHeader(),
        ticketGuard: { privateKey: this.pair.privatePem, publicKey: this.pair.publicPem, ticket: this.serverData.ticket, tsSign: this.serverData.tsSign,
          sessionHash: createHash('sha256').update(sessionId).digest('hex') } }, this.options.platformUid);
      const web = new NodeWebProfileClient({ platformUid: this.options.platformUid, assertActive: this.options.assertActive,
        ...(this.options.fetcher ? { fetcher: this.options.fetcher } : {}), store: { load: () => session, save() { throw new Error('QR validation is read-only'); } } });
      await web.verify(signal); this.active(signal);
      return { status: 'confirmed', session: { ...session, verifiedAt: new Date().toISOString() } };
    } catch (error) { this.finished = true; throw error; } finally { this.busy = false; }
  }
}
