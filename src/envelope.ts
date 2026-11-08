// 封筒（全レーン共通の入れ物）の形と検査。規格書 第4章・第5章。
// 検査は安い順に行い、本文は最後にだけ触る（速度の原則）。

import {
  type Classification,
  HEADER_MAX_BYTES,
  type LaneName,
  LANES,
  SPEC_VERSION,
  isLane,
} from "./lanes.ts";

export interface Envelope {
  /** 規格版 */
  v: number;
  /** レーン */
  l: LaneName;
  /** 形式（例：media.image.webp、record.nsc.attendance） */
  f: string;
  /** 一意の番号。重複防止に使う */
  id: string;
  /** 会社 ID */
  co: string;
  /** 送り手（利用者・ハブ・機器の ID） */
  by: string;
  /** 土台が付けた時刻（ミリ秒） */
  at: number;
  /** 機密度 0:公開 1:社内 2:機密 3:極秘 */
  c: Classification;
  /** 締め切り（at からのミリ秒）。過ぎたら捨てる */
  dl?: number;
  /** 承認が要る */
  ap?: boolean;
  /** 保存期間（秒）。0 は保存しない */
  ret?: number;
  /** 順番 */
  sq?: number;
  /** 元の版（同期・更新のとき） */
  bv?: number;
  /** 本文の置き場所 */
  ref?: string;
  /** 本文の大きさ（バイト） */
  len?: number;
  /** 本文の SHA-256（16 進・小文字） */
  h?: string;
  /** 本文の暗号方式（今は A256GCM のみ） */
  e?: "A256GCM";
  /** 本文（小さいときだけ） */
  b?: unknown;
  /** 署名（HMAC-SHA256、base64url） */
  sig?: string;
}

export type CheckResult =
  | { ok: true; env: Envelope }
  | { ok: false; code: ErrorCode; field: string; message: string };

export type ErrorCode =
  | "NOT_OBJECT"
  | "UNKNOWN_FIELD"
  | "BAD_VERSION"
  | "BAD_LANE"
  | "BAD_FIELD"
  | "MISSING_FIELD"
  | "FORMAT_NOT_ALLOWED"
  | "CLASS_TOO_LOW"
  | "BODY_FORBIDDEN"
  | "BODY_AND_REF"
  | "BODY_TOO_LARGE"
  | "HEADER_TOO_LARGE"
  | "ENCRYPTION_REQUIRED"
  | "SIGNATURE_REQUIRED";

export interface CheckOptions {
  /**
   * レーンごとに許す形式。渡したときは、ここに無い形式をすべて拒否する。
   * 本番では必ず渡す（許可の書いていないものは禁止）。
   */
  formats?: Partial<Record<LaneName, ReadonlySet<string>>>;
}

const FIELDS: ReadonlySet<string> = new Set([
  "v", "l", "f", "id", "co", "by", "at", "c",
  "dl", "ap", "ret", "sq", "bv", "ref", "len", "h", "e", "b", "sig",
]);

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MSG_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const FORMAT_RE = /^[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9_-]*){1,7}$/;
const REF_RE = /^[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,512}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{43}$/;
const DEADLINE_MAX_MS = 600_000;
const RETENTION_MAX_SEC = 10 * 365 * 86400;

const encoder = new TextEncoder();

function fail(code: ErrorCode, field: string, message: string): CheckResult {
  return { ok: false, code, field, message };
}

function isUint(x: unknown, max = Number.MAX_SAFE_INTEGER): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= max;
}

/** 本文の大きさ（バイト）。文字列はそのまま、ほかは JSON にして数える */
export function bodyBytes(b: unknown): number {
  if (b === undefined) return 0;
  if (typeof b === "string") return encoder.encode(b).byteLength;
  if (b instanceof Uint8Array) return b.byteLength;
  return encoder.encode(JSON.stringify(b) ?? "").byteLength;
}

/**
 * 封筒を検査する。通れば同じ封筒を返す（書き換えない）。
 * 受け口は、これより前に「受け取った全体の長さ」で上限を確かめておく。
 */
export function checkEnvelope(input: unknown, opts: CheckOptions = {}): CheckResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return fail("NOT_OBJECT", "", "封筒の形ではありません");
  }
  const o = input as Record<string, unknown>;

  // 1. 書いていない項目は拒否（__proto__ なども、ここで弾かれる）
  for (const k of Object.keys(o)) {
    if (!FIELDS.has(k)) return fail("UNKNOWN_FIELD", k, `規格に無い項目です：${k}`);
  }

  // 2. 版とレーン
  if (o.v !== SPEC_VERSION) return fail("BAD_VERSION", "v", "対応していない規格版です");
  if (!isLane(o.l)) return fail("BAD_LANE", "l", "規格に無いレーンです");
  const lane = LANES[o.l];

  // 3. 見出しの必須項目
  if (typeof o.f !== "string" || !FORMAT_RE.test(o.f) || !o.f.startsWith(`${o.l}.`)) {
    return fail("BAD_FIELD", "f", "形式の名前が正しくありません（レーン名.分類.名前）");
  }
  if (typeof o.id !== "string" || !MSG_ID_RE.test(o.id)) return fail("BAD_FIELD", "id", "一意の番号が正しくありません");
  if (typeof o.co !== "string" || !ID_RE.test(o.co)) return fail("BAD_FIELD", "co", "会社 ID が正しくありません");
  if (typeof o.by !== "string" || !ID_RE.test(o.by)) return fail("BAD_FIELD", "by", "送り手の ID が正しくありません");
  if (!isUint(o.at) || o.at === 0) return fail("BAD_FIELD", "at", "時刻が正しくありません");
  if (!isUint(o.c, 3)) return fail("BAD_FIELD", "c", "機密度は 0〜3 です");

  // 4. 形式の許可（渡されたときは、無いものをすべて拒否）
  if (opts.formats) {
    const allowed = opts.formats[o.l];
    if (!allowed || !allowed.has(o.f)) return fail("FORMAT_NOT_ALLOWED", "f", "許可されていない形式です");
  }

  // 5. 任意の項目の形
  if (o.dl !== undefined && !isUint(o.dl, DEADLINE_MAX_MS)) return fail("BAD_FIELD", "dl", "締め切りが正しくありません");
  if (o.ap !== undefined && typeof o.ap !== "boolean") return fail("BAD_FIELD", "ap", "承認の指定が正しくありません");
  if (o.ret !== undefined && !isUint(o.ret, RETENTION_MAX_SEC)) return fail("BAD_FIELD", "ret", "保存期間が正しくありません");
  if (o.sq !== undefined && !isUint(o.sq)) return fail("BAD_FIELD", "sq", "順番が正しくありません");
  if (o.bv !== undefined && !isUint(o.bv)) return fail("BAD_FIELD", "bv", "元の版が正しくありません");
  if (o.ref !== undefined && (typeof o.ref !== "string" || !REF_RE.test(o.ref))) return fail("BAD_FIELD", "ref", "置き場所が正しくありません");
  if (o.len !== undefined && !isUint(o.len)) return fail("BAD_FIELD", "len", "大きさが正しくありません");
  if (o.h !== undefined && (typeof o.h !== "string" || !HASH_RE.test(o.h))) return fail("BAD_FIELD", "h", "ハッシュが正しくありません");
  if (o.e !== undefined && o.e !== "A256GCM") return fail("BAD_FIELD", "e", "対応していない暗号方式です");
  if (o.sig !== undefined && (typeof o.sig !== "string" || !SIG_RE.test(o.sig))) return fail("BAD_FIELD", "sig", "署名の形が正しくありません");

  // 6. レーンごとの必須項目
  for (const k of lane.required) {
    if (o[k] === undefined) return fail("MISSING_FIELD", k, `このレーンでは必須の項目です：${k}`);
  }

  // 7. 機密性
  const c = o.c as Classification;
  if (c < lane.minClass) return fail("CLASS_TOO_LOW", "c", "このレーンの機密度の下限を下回っています");
  if (o.l === "key" && o.ret !== undefined && o.ret !== 0) return fail("BAD_FIELD", "ret", "鍵レーンは保存できません");
  if (c >= 2 && o.sig === undefined) return fail("SIGNATURE_REQUIRED", "sig", "機密以上は署名が必須です");

  // 8. 見出しの大きさ（本文を除く）
  const hasBody = o.b !== undefined;
  const headerBytes = encoder.encode(JSON.stringify(o, (k, val) => (k === "b" ? undefined : val))).byteLength;
  if (headerBytes > HEADER_MAX_BYTES) return fail("HEADER_TOO_LARGE", "", "見出しが大きすぎます");

  // 9. 本文（最後にだけ触る）
  if (hasBody) {
    if (lane.inlineMax === 0) return fail("BODY_FORBIDDEN", "b", "このレーンでは本文を直接運べません");
    if (o.ref !== undefined) return fail("BODY_AND_REF", "b", "本文と置き場所は、どちらか一方だけです");
    if (c === 3 && o.e === undefined) return fail("ENCRYPTION_REQUIRED", "e", "極秘の本文は暗号化が必須です");
    if (o.e !== undefined && typeof o.b !== "string") return fail("BAD_FIELD", "b", "暗号化した本文は文字列です");
    if (bodyBytes(o.b) > lane.inlineMax) return fail("BODY_TOO_LARGE", "b", "本文が大きすぎます。置き場所（ref）で渡してください");
  } else if (o.e !== undefined) {
    return fail("BAD_FIELD", "e", "本文が無いのに暗号方式があります");
  }

  return { ok: true, env: o as unknown as Envelope };
}

/** 締め切りを過ぎたか。時刻は外から渡す（土台の時計） */
export function isExpired(env: Envelope, now: number): boolean {
  const dl = env.dl ?? LANES[env.l].deadlineMs;
  return dl > 0 && now > env.at + dl;
}

/** 実際に使う保存期間（秒）。null は保存先の決まりに従う */
export function retentionOf(env: Envelope): number | null {
  if (env.l === "key") return 0;
  return env.ret ?? LANES[env.l].retentionSec;
}

/** 記録に残してよい形にする。社内以上の本文と署名は残さない */
export function redact(env: Envelope): Omit<Envelope, "b" | "sig"> & { b?: unknown } {
  const { b, sig: _sig, ...rest } = env;
  if (b === undefined) return rest;
  if (env.c === 0) return { ...rest, b };
  return { ...rest, len: rest.len ?? bodyBytes(b) };
}
