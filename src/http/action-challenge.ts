export const ACTION_CHALLENGE_MARKERS = ['passport-decision-header', 'bdturing-header', 'captcha-parameters-header', 'account-check-header', 'verify-data-body'] as const;
export type ActionChallengeMarker = typeof ACTION_CHALLENGE_MARKERS[number];
export interface ActionChallengeDiagnostic { status?: number; businessCode?: number; markers?: readonly ActionChallengeMarker[] }
/** Public marker names only; never return header values. */
export function actionChallengeMarkers(headers: Headers): ActionChallengeMarker[] {
  return ([['x-tt-verify-passport-decision', 'passport-decision-header'], ['bdturing-verify', 'bdturing-header'],
    ['x-vc-bdturing-parameters', 'captcha-parameters-header'], ['x-whale-throughput-abort-data', 'account-check-header']] as const)
    .filter(([header]) => headers.has(header)).map(([, marker]) => marker);
}

/** A rejected business request requiring human verification, not a transport retry. */
export class ActionChallengeError extends Error {
  override readonly name = 'ActionChallengeError';
  readonly #raw: string;
  readonly diagnostic: Readonly<ActionChallengeDiagnostic>;

  constructor(readonly source: 'passport-decision' | 'bdturing', raw: string, diagnostic: ActionChallengeDiagnostic = {}) {
    super(source === 'passport-decision' ? '业务操作需要身份二次验证' : '业务操作需要验证码验证');
    if (!raw || raw.length > 65_536) throw new Error('平台业务验证数据无效');
    if (source === 'passport-decision') {
      let value: unknown;
      try { value = JSON.parse(raw); } catch { throw new Error('平台二次验证数据不是有效 JSON'); }
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('平台二次验证数据不是对象');
    }
    this.#raw = raw;
    this.diagnostic = Object.freeze({
      ...(Number.isSafeInteger(diagnostic.status) && diagnostic.status! >= 100 && diagnostic.status! <= 599 ? { status: diagnostic.status } : {}),
      ...(Number.isSafeInteger(diagnostic.businessCode) && Math.abs(diagnostic.businessCode!) <= 1000000 ? { businessCode: diagnostic.businessCode } : {}),
      markers: Object.freeze(ACTION_CHALLENGE_MARKERS.filter(marker => diagnostic.markers?.includes(marker))),
    });
  }

  /** Sensitive platform input: only pass to the verification UI, never log. */
  get raw(): string { return this.#raw; }
}
