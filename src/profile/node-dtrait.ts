import { createCipheriv, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { DESKTOP_DTRAIT_BUILTIN_PARAMETERS } from '../anti-bot/desktop-dtrait-bootstrap.js';
import { DesktopDTraitRequestCore, type DesktopDTraitFeatureValues } from '../anti-bot/desktop-dtrait-request-core.js';
import { DesktopDTraitFeatures, createDesktopDTraitHash } from '../anti-bot/desktop-dtrait-features.js';
import { createDesktopDTraitMathCollector } from '../anti-bot/desktop-dtrait-math.js';

/** Actual Node features only. No Window/DOM shim, Chrome constants, or borrowed device fingerprints. */
export function collectNodeDTraitFeatures(): DesktopDTraitFeatureValues {
  const hash = createDesktopDTraitHash({ encoder: new TextEncoder(), onDiagnostic() {} });
  const str: Record<string, unknown> = createDesktopDTraitMathCollector({ Math, hash })();
  const navigator = (globalThis as typeof globalThis & { navigator?: {
    userAgent?: string; language?: string; languages?: readonly string[];
  } }).navigator;
  if (navigator?.userAgent) str['str_19'] = hash(navigator.userAgent);
  if (navigator?.language && navigator.languages) str['str_15'] = hash(`${navigator.language},${navigator.languages.join(',')}`);
  const { locale, timeZone } = Intl.DateTimeFormat().resolvedOptions();
  str['str_27'] = hash(`${locale}+${timeZone}`);
  return { bool: {}, num: {}, str };
}

/** One account-owned crypto/feature core, with explicit readiness and no global transport hooks. */
export class NodeProfileDTrait {
  private readonly core: DesktopDTraitRequestCore;
  constructor() {
    const hash = createDesktopDTraitHash({ encoder: new TextEncoder(), onDiagnostic() {} });
    const util = {
      uint8ArrayToHex: (bytes: Uint8Array) => Buffer.from(bytes).toString('hex'),
      bufferConcat: (parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts)),
    };
    this.core = new DesktopDTraitRequestCore({
      Date, performance, atob,
      crypto: {
        util,
        aes: {
          getAesKey: () => new Uint8Array(randomBytes(16)),
          async encryptData(hexKey, text) {
            const iv = randomBytes(16);
            const cipher = createCipheriv('aes-128-cbc', Buffer.from(hexKey, 'hex'), iv);
            const bytes = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
            return { cipherText: Buffer.concat([iv, bytes]).toString('base64'), encryptedData: bytes.toString('base64'), iv: iv.toString('base64') };
          },
        },
        rsa: {
          async encryptData(key, text) {
            return publicEncrypt({ key, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(text)).toString('base64');
          },
        },
      },
      featureProtocol: new DesktopDTraitFeatures({ hash, getCryptoUtil: () => util, btoa }, {}),
      collect: async () => collectNodeDTraitFeatures(),
      // Explicit signing entry; this owner never patches fetch/XHR or another account's runtime.
      installHooks() {},
    }, { ...DESKTOP_DTRAIT_BUILTIN_PARAMETERS });
    this.core.setSource();
  }

  async header(path: string): Promise<string> {
    if (path !== '/aweme/v1/web/commit/user/' && path !== '/aweme/v1/web/user/profile/self/') {
      throw new Error('Profile DTrait path is not allow-listed');
    }
    await Promise.all([this.core.cryptoInitialization, this.core.initPromise]);
    const headers = await this.core.getDTraitHeader({ path });
    const result = headers?.['x-tt-session-dtrait'];
    if (!result || result.includes('undefined') || !this.core.collectStatus) throw new Error('Node DTrait unavailable');
    return result;
  }
}
