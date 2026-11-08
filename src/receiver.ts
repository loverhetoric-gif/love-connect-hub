// 受け口（全レーン共通）。規格書 第12章。
// 検査は安い順：長さ → 形 → 締め切り → 時刻 → 署名 → 重複。
// 重複の記録は署名を確かめた後にだけ残す（偽の番号で、正しい封筒が弾かれないように）。

import { type CheckOptions, type Envelope, type ErrorCode, checkEnvelope, isExpired } from "./envelope.ts";
import { HEADER_MAX_BYTES, LANES, type LaneName } from "./lanes.ts";
import { openBodyText, verifyEnvelope } from "./crypto.ts";
import { type Dedupe, createDedupe } from "./dedupe.ts";

export type ReceiveCode =
  | ErrorCode
  | "TOO_LARGE"
  | "BAD_JSON"
  | "EXPIRED"
  | "FUTURE_TIME"
  | "NO_KEY"
  | "BAD_SIGNATURE"
  | "DUPLICATE";

export type Received =
  | { ok: true; env: Envelope }
  | { ok: false; code: ReceiveCode; field: string; message: string };

export interface ReceiverOptions {
  /** レーンごとに許す形式。ここに無い形式はすべて拒否する（必須） */
  formats: NonNullable<CheckOptions["formats"]>;
  /** 土台の時計（ミリ秒） */
  now: () => number;
  /** 会社ごとの署名用の鍵。無い会社の署名付き封筒は拒否する */
  signingKey: (co: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** 重複防止（既定：24 時間・1 万件） */
  dedupe?: Dedupe;
  /** 未来の時刻を許す幅（ミリ秒、既定 60 秒）。時計のずれの分 */
  skewMs?: number;
}

/** 受け取ってよい全体の長さの上限（見出し＋最大の本文＋暗号化と JSON の余白） */
export const RAW_MAX_BYTES =
  HEADER_MAX_BYTES + Math.ceil((Math.max(...Object.values(LANES).map((p) => p.inlineMax)) * 4) / 3) + 1024;

function no(code: ReceiveCode, field: string, message: string): Received {
  return { ok: false, code, field, message };
}

export interface Receiver {
  /** 受け取った文字列（または解析済みの値）を検査する */
  receive(raw: string | unknown): Promise<Received>;
}

export function createReceiver(opts: ReceiverOptions): Receiver {
  const dedupe = opts.dedupe ?? createDedupe({ windowMs: 86_400_000, capacity: 10_000 });
  const skew = opts.skewMs ?? 60_000;
  const encoder = new TextEncoder();

  return {
    async receive(raw) {
      // 1. 長さ（文字数は必ずバイト数以下なので、まず文字数で安く弾く）
      let input: unknown = raw;
      if (typeof raw === "string") {
        if (raw.length > RAW_MAX_BYTES || encoder.encode(raw).byteLength > RAW_MAX_BYTES) {
          return no("TOO_LARGE", "", "受け取れる大きさを超えています");
        }
        try {
          input = JSON.parse(raw);
        } catch {
          return no("BAD_JSON", "", "JSON として読めません");
        }
      }

      // 2. 形（許可表は必須）
      const r = checkEnvelope(input, { formats: opts.formats });
      if (!r.ok) return r;
      const env = r.env;

      // 3. 時刻
      const now = opts.now();
      if (env.at > now + skew) return no("FUTURE_TIME", "at", "時刻が未来になっています");
      if (isExpired(env, now)) return no("EXPIRED", "dl", "締め切りを過ぎています");

      // 4. 署名（付いていれば必ず確かめる。機密以上は必須なので検査済み）
      if (env.sig !== undefined) {
        const key = await opts.signingKey(env.co);
        if (!key) return no("NO_KEY", "sig", "この会社の署名用の鍵がありません");
        if (!(await verifyEnvelope(env, key))) return no("BAD_SIGNATURE", "sig", "署名が一致しません");
      }

      // 5. 重複（署名を確かめた後にだけ記録する）
      if (!dedupe.first(env.co, env.id, now)) return no("DUPLICATE", "id", "同じ番号の封筒を受け取り済みです");

      return { ok: true, env };
    },
  };
}

/** 本文を取り出す。暗号化されていれば開いて JSON に戻す */
export async function readBody(env: Envelope, sealKey?: CryptoKey): Promise<unknown> {
  if (env.e === undefined) return env.b;
  if (!sealKey) throw new Error("暗号化用の鍵がありません");
  return JSON.parse(await openBodyText(env, sealKey));
}

/** レーンごとの許可表を短く書くための補助 */
export function formatTable(t: Partial<Record<LaneName, readonly string[]>>): NonNullable<CheckOptions["formats"]> {
  const out: Partial<Record<LaneName, ReadonlySet<string>>> = {};
  for (const [lane, list] of Object.entries(t) as [LaneName, readonly string[]][]) {
    for (const f of list) {
      if (!f.startsWith(`${lane}.`)) throw new Error(`形式の名前は「レーン名.」で始めてください：${f}`);
    }
    out[lane] = new Set(list);
  }
  return out;
}
