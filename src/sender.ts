// 送り口（全レーン共通）。規格書 第12章。
// 番号・時刻・既定の機密度を付け、極秘の本文は暗号化し、署名してから、
// 自分で検査を通す。規格に合わない封筒は送る前に止める。

import { type Envelope, checkEnvelope } from "./envelope.ts";
import { type Classification, type LaneName, LANES, SPEC_VERSION } from "./lanes.ts";
import { sealBody, signEnvelope, toBase64Url } from "./crypto.ts";

export interface SenderOptions {
  /** 会社 ID */
  co: string;
  /** 送り手の ID */
  by: string;
  /** 土台の時計（ミリ秒） */
  now: () => number;
  /** 署名用の鍵。あれば必ず署名する（機密以上は必須） */
  signingKey?: CryptoKey;
  /** 暗号化用の鍵。極秘の本文を送るときは必須 */
  sealKey?: CryptoKey;
  /** 一意の番号の作り方（既定：乱数 16 バイト） */
  newId?: () => string;
}

export interface SendInput {
  /** 本文。極秘のときは JSON にして暗号化する */
  b?: unknown;
  ref?: string;
  len?: number;
  h?: string;
  c?: Classification;
  dl?: number;
  ap?: boolean;
  ret?: number;
  sq?: number;
  bv?: number;
  /** 番号を自分で決めるとき（分割の送信など） */
  id?: string;
}

export class SendError extends Error {
  readonly code: string;
  readonly field: string;
  constructor(code: string, field: string, message: string) {
    super(message);
    this.name = "SendError";
    this.code = code;
    this.field = field;
  }
}

export function randomId(): string {
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

export interface Sender {
  /** 封筒を作る。返した封筒は、そのまま送ってよい */
  make(lane: LaneName, f: string, input?: SendInput): Promise<Envelope>;
}

export function createSender(opts: SenderOptions): Sender {
  const newId = opts.newId ?? randomId;
  return {
    async make(lane, f, input = {}) {
      const c = input.c ?? LANES[lane].minClass;
      let env: Envelope = { v: SPEC_VERSION, l: lane, f, id: input.id ?? newId(), co: opts.co, by: opts.by, at: opts.now(), c };
      for (const k of ["dl", "ap", "ret", "sq", "bv", "ref", "len", "h"] as const) {
        if (input[k] !== undefined) (env as unknown as Record<string, unknown>)[k] = input[k];
      }
      if (input.b !== undefined) {
        if (c === 3) {
          if (!opts.sealKey) throw new SendError("NO_SEAL_KEY", "e", "極秘の本文を送るには暗号化用の鍵が必要です");
          env.e = "A256GCM";
          env.b = await sealBody(env, JSON.stringify(input.b), opts.sealKey);
        } else {
          env.b = input.b;
        }
      }
      if (opts.signingKey) env = await signEnvelope(env, opts.signingKey);
      else if (c >= 2) throw new SendError("NO_SIGNING_KEY", "sig", "機密以上を送るには署名用の鍵が必要です");
      const r = checkEnvelope(env);
      if (!r.ok) throw new SendError(r.code, r.field, r.message);
      return env;
    },
  };
}
