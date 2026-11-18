// 端末の鍵。規格書 第21章。
// WARPHOLE.（iPhone から Mac を操作するアプリ）の「端末の中の取り出せない鍵」を、利用者の口に取り入れたもの。
// ログインのトークンが盗まれても、登録した端末の鍵が無ければ送れない。承認（ap）も、本人の端末の鍵の署名で示す。
// 端末の鍵は「端末であることの証明」だけに使う。封筒の署名・暗号化には使わない（第18章のとおり、アプリに土台の鍵は持たせない）。

import { type Envelope, type ErrorCode } from "./envelope.ts";
import { canonicalJson, fromBase64Url, sha256Hex, toBase64Url } from "./crypto.ts";
import { type AnyDedupe, createDedupe } from "./dedupe.ts";
import { type TokenClaims, type TokenCode, type TokenVerifier, bearerToken } from "./token.ts";
import { SECURITY_HEADERS, readLimited } from "./http.ts";
import type { UserIdentity } from "./user.ts";

/** 送るたびの証明を入れる見出しの名前 */
export const DEVICE_HEADER = "lch-device";
/** 登録の入口の既定のパス */
export const DEVICE_PATH = "/lch/v1/device";
/** 証明の時刻のずれの上限（前後 2 分） */
export const DEVICE_SKEW_MS = 120_000;
/** 使い捨ての番号を覚えておく時間（5 分） */
export const DEVICE_NONCE_MS = 300_000;
/** 合言葉の有効期間（5 分） */
export const PAIRING_TTL_MS = 300_000;
/** 承認の時刻のずれの上限（前後 5 分） */
export const APPROVAL_SKEW_MS = 300_000;

export type DeviceUse = "device" | "approve";

/** 登録した端末の鍵 */
export interface DeviceKey {
  /** 非圧縮形式 65 バイトの公開鍵の base64url */
  pub: string;
  use: DeviceUse;
}

/** 本人の端末の一覧（置き場所は各アプリが決める） */
export interface DeviceDirectory {
  keys(co: string, by: string): readonly DeviceKey[] | Promise<readonly DeviceKey[]>;
}

/** 合言葉と端末の一覧の置き場所（登録の入口が使う） */
export interface PairingStore extends DeviceDirectory {
  /** 会社・本人に結び付いた合言葉のハッシュが、失効しておらず未使用なら消して true。1 回だけ通す */
  take(co: string, by: string, codeHash: string, now: number): boolean | Promise<boolean>;
  /** 本人の端末の一覧に加える */
  add(co: string, by: string, key: DeviceKey): void | Promise<void>;
}

export type DeviceCode = "DEVICE_MISSING" | "DEVICE_BAD_PROOF" | "DEVICE_CLOCK" | "DEVICE_UNKNOWN" | "DEVICE_REPLAY";
export type PairCode = "PAIR_BAD_REQUEST" | "PAIR_BAD_PROOF" | "PAIR_CODE" | "PAIR_ATTEST";

export const DEVICE_HTTP_STATUS: Readonly<Record<DeviceCode | PairCode, number>> = Object.freeze({
  DEVICE_MISSING: 401,
  DEVICE_BAD_PROOF: 401,
  DEVICE_CLOCK: 401,
  DEVICE_UNKNOWN: 403,
  DEVICE_REPLAY: 401,
  PAIR_BAD_REQUEST: 400,
  PAIR_BAD_PROOF: 401,
  PAIR_CODE: 403,
  PAIR_ATTEST: 403,
});

const enc = new TextEncoder();
const PUB_RE = /^[A-Za-z0-9_-]{87}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const CODE_RE = /^[A-Za-z0-9_-]{43}$/;
const TS_RE = /^[0-9]{1,16}$/;
const ECDSA = { name: "ECDSA", hash: "SHA-256" } as const;
// TypeScript 5.9 の型は Uint8Array の元の領域を厳しく区別するため、crypto.ts と同じく、使う関数だけ型を揃えて扱う（動きは標準のまま）
type Bytes = Uint8Array;
interface Subtle {
  importKey(f: "raw", k: Bytes, a: EcKeyImportParams, x: boolean, u: KeyUsage[]): Promise<CryptoKey>;
  verify(a: EcdsaParams, k: CryptoKey, s: Bytes, d: Bytes): Promise<boolean>;
  sign(a: EcdsaParams, k: CryptoKey, d: Bytes): Promise<ArrayBuffer>;
}
const subtle = globalThis.crypto.subtle as unknown as Subtle;

/** 公開鍵（65 バイトの非圧縮形式）を取り込む。形が違えば undefined */
async function importDevicePublicKey(pub: string): Promise<CryptoKey | undefined> {
  if (!PUB_RE.test(pub)) return undefined;
  const raw = fromBase64Url(pub);
  if (raw.length !== 65 || raw[0] !== 0x04) return undefined;
  try {
    return await subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return undefined;
  }
}

/** 端末の鍵の署名（r||s の 64 バイト）を確かめる */
export async function verifyDeviceSignature(pub: string, sig: string, message: string): Promise<boolean> {
  if (!SIG_RE.test(sig)) return false;
  const key = await importDevicePublicKey(pub);
  if (!key) return false;
  const s = fromBase64Url(sig);
  if (s.length !== 64) return false;
  return subtle.verify(ECDSA, key, s, enc.encode(message));
}

/** 送るたびの証明の文 */
export function deviceProofMessage(p: { method: string; path: string; ts: number; nonce: string; tokenHash: string; bodyHash: string; pub: string }): string {
  return ["lch-device-v1", p.method.toUpperCase(), p.path, String(p.ts), p.nonce, p.tokenHash, p.bodyHash, p.pub].join("\n");
}

/** 登録の文 */
export function pairingMessage(p: { co: string; by: string; use: DeviceUse; pub: string; codeHash: string }): string {
  return ["lch-pair-v1", p.co, p.by, p.use, p.pub, p.codeHash].join("\n");
}

/** 承認の文。封筒（sig を除く）の中身に結び付ける */
export async function approvalMessage(env: Envelope, ts: number): Promise<string> {
  const { sig: _sig, ...rest } = env;
  return ["lch-approve-v1", env.co, env.id, await sha256Hex(canonicalJson(rest)), String(ts)].join("\n");
}

// ---- 端末の鍵（アプリ側） ----

/** 端末の鍵。秘密の部分は外へ出さず、署名だけを頼む */
export interface DeviceSigner {
  /** 非圧縮形式 65 バイトの公開鍵の base64url */
  readonly pub: string;
  /** r||s の 64 バイトの署名を返す */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/**
 * Web 用の端末の鍵。秘密の部分は取り出せない CryptoKey（extractable: false）で作る。
 * 鍵の組は IndexedDB にそのまま入れて持ち越せる（取り出せないまま保存される）。
 */
export async function createWebDeviceKey(pair?: CryptoKeyPair): Promise<DeviceSigner & { pair: CryptoKeyPair }> {
  const kp = pair ?? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair);
  if (kp.privateKey.extractable) throw new Error("端末の鍵は取り出せない形（extractable: false）で作ってください");
  const pub = toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  return {
    pub,
    pair: kp,
    async sign(message) {
      return new Uint8Array(await subtle.sign(ECDSA, kp.privateKey, message));
    },
  };
}

/** 送るたびの証明の見出しの値を作る。送り直しのたびに作り直す（時刻と番号が変わる） */
export async function deviceProofHeader(
  signer: DeviceSigner,
  p: { method: string; path: string; token: string; body: string; now: number },
): Promise<string> {
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const msg = deviceProofMessage({
    method: p.method,
    path: p.path,
    ts: p.now,
    nonce,
    tokenHash: await sha256Hex(p.token),
    bodyHash: await sha256Hex(p.body),
    pub: signer.pub,
  });
  const sig = toBase64Url(await signer.sign(enc.encode(msg)));
  return `v1.${signer.pub}.${p.now}.${nonce}.${sig}`;
}

/** 登録の本文を作る（code は別の画面の QR などで受け取った合言葉） */
export async function pairingRequest(signer: DeviceSigner, p: { co: string; by: string; use: DeviceUse; code: string }) {
  const msg = pairingMessage({ co: p.co, by: p.by, use: p.use, pub: signer.pub, codeHash: await sha256Hex(p.code) });
  return { pub: signer.pub, use: p.use, code: p.code, sig: toBase64Url(await signer.sign(enc.encode(msg))) };
}

/** 承認の署名を作る（承認の鍵は、署名のたびに生体認証を求める作り方にする） */
export async function signApproval(signer: DeviceSigner, env: Envelope, now: number) {
  return { pub: signer.pub, ts: now, sig: toBase64Url(await signer.sign(enc.encode(await approvalMessage(env, now)))) };
}

// ---- 土台の側 ----

export type DeviceCheck = { ok: true; pub: string } | { ok: false; code: DeviceCode; message: string };

export interface DeviceVerifier {
  /** 送るたびの証明を確かめる。body は受け取った本文の文字のまま */
  verify(p: { header: string | null; method: string; path: string; token: string; body: string; who: UserIdentity }): Promise<DeviceCheck>;
}

export interface DeviceVerifierOptions {
  directory: DeviceDirectory;
  now: () => number;
  /** 時刻のずれの上限（既定 2 分） */
  skewMs?: number;
  /** 使い捨ての番号の記憶（既定：5 分・10 万件）。台数をまたぐときは Durable Objects などに置く */
  nonces?: AnyDedupe;
}

/** 端末の確認。利用者の口（createUserGateway の device）に渡す */
export function createDeviceVerifier(opts: DeviceVerifierOptions): DeviceVerifier {
  const skew = opts.skewMs ?? DEVICE_SKEW_MS;
  const nonces = opts.nonces ?? createDedupe({ windowMs: DEVICE_NONCE_MS, capacity: 100_000 });
  const fail = (code: DeviceCode, message: string): DeviceCheck => ({ ok: false, code, message });
  return {
    async verify({ header, method, path, token, body, who }) {
      // 1. 形（安い検査から）
      if (!header) return fail("DEVICE_MISSING", "端末の証明がありません");
      const parts = header.split(".");
      if (parts.length !== 5 || parts[0] !== "v1") return fail("DEVICE_BAD_PROOF", "端末の証明の形が違います");
      const [, pub, tsText, nonce, sig] = parts as [string, string, string, string, string];
      if (!PUB_RE.test(pub) || !TS_RE.test(tsText) || !NONCE_RE.test(nonce) || !SIG_RE.test(sig)) {
        return fail("DEVICE_BAD_PROOF", "端末の証明の形が違います");
      }
      // 2. 時刻
      const ts = Number(tsText), now = opts.now();
      if (Math.abs(now - ts) > skew) return fail("DEVICE_CLOCK", "端末の時計がずれています");
      // 3. 本人の端末の一覧にあるか
      const keys = await opts.directory.keys(who.co, who.by);
      if (!keys.some((k) => k.use === "device" && k.pub === pub)) return fail("DEVICE_UNKNOWN", "登録されていない端末です");
      // 4. 署名（トークンと本文に結び付く）
      const msg = deviceProofMessage({ method, path, ts, nonce, tokenHash: await sha256Hex(token), bodyHash: await sha256Hex(body), pub });
      if (!(await verifyDeviceSignature(pub, sig, msg))) return fail("DEVICE_BAD_PROOF", "端末の証明が合いません");
      // 5. 使い捨ての番号（署名が合ったものだけ覚える。他人に番号を潰させない）
      if (!(await nonces.first(who.co, `${who.by}\u0000${pub}\u0000${nonce}`, now))) return fail("DEVICE_REPLAY", "同じ証明が使い回されました");
      return { ok: true, pub };
    },
  };
}

/** 合言葉を作る。code は QR などで端末に渡し、土台には hash と期限だけを保存する */
export async function issuePairingCode(now: number, ttlMs = PAIRING_TTL_MS): Promise<{ code: string; hash: string; expiresAt: number }> {
  const code = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  return { code, hash: await sha256Hex(code), expiresAt: now + ttlMs };
}

export interface DeviceEnrollmentOptions {
  verifier: TokenVerifier;
  identify: (claims: TokenClaims) => UserIdentity | undefined | Promise<UserIdentity | undefined>;
  store: PairingStore;
  now: () => number;
  /** 入口のパス（既定 /lch/v1/device） */
  path?: string;
  onError?: (info: { error: unknown }) => void;
  /**
   * 鍵の証明（規格書 第21章）。渡すと、登録の本文の att（端末の鍵の証明書の鎖など）を確かめ、ok でなければ登録しない。
   * どの端末・どの種類の鍵に求めるか（例：Android の承認の鍵には必須）は、アプリが決める。Android は verifyAndroidAttestation を使う
   */
  attest?: (p: { who: UserIdentity; pub: string; use: DeviceUse; att: unknown }) => Promise<{ ok: true } | { ok: false; code: string; message: string }>;
}

type EnrollCode = DeviceCode | PairCode | TokenCode | ErrorCode | "USER_FORBIDDEN" | "NOT_FOUND" | "CONTENT_TYPE" | "TOO_LARGE" | "BAD_JSON" | "HANDLER";

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

function reply(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...SECURITY_HEADERS, ...extra } });
}
function refuse(code: EnrollCode, message: string): Response {
  const status =
    (DEVICE_HTTP_STATUS as Record<string, number>)[code] ??
    ({ TOKEN_MISSING: 401, TOKEN_INVALID: 401, TOKEN_EXPIRED: 401, USER_FORBIDDEN: 403, NOT_FOUND: 404, CONTENT_TYPE: 415, TOO_LARGE: 413, BAD_JSON: 400, HANDLER: 500 } as Record<string, number>)[code] ??
    400;
  const extra = status === 401 && code.startsWith("TOKEN_") ? { "www-authenticate": `Bearer error="${code === "TOKEN_MISSING" ? "invalid_request" : "invalid_token"}"` } : undefined;
  return reply(status, { ok: false, code, message }, extra);
}

/** 端末の登録の入口（HTTP）。ログインのトークン ＋ 使い捨ての合言葉 ＋ 鍵を持っている証明 */
export function createDeviceEnrollment(opts: DeviceEnrollmentOptions): (req: Request) => Promise<Response> {
  const path = opts.path ?? DEVICE_PATH;
  return async (req) => {
    const url = new URL(req.url);
    if (url.pathname !== path) return refuse("NOT_FOUND", "入口が違います");
    if (req.method !== "POST") return new Response(null, { status: 405, headers: { ...SECURITY_HEADERS, allow: "POST" } });
    const type = (req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") return refuse("CONTENT_TYPE", "application/json で送ってください");
    // 本人確認（本文を読む前に）
    const t = await opts.verifier.verify(bearerToken(req.headers.get("authorization")));
    if (!t.ok) return refuse(t.code, t.message);
    let who: UserIdentity | undefined;
    try {
      who = await opts.identify(t.claims);
    } catch (error) {
      opts.onError?.({ error });
      return refuse("HANDLER", "処理中に問題が起きました");
    }
    if (!who || !ID_RE.test(who.co) || !ID_RE.test(who.by)) return refuse("USER_FORBIDDEN", "この利用者は使えません");
    const raw = await readLimited(req, 4096);
    if (raw === undefined) return refuse("TOO_LARGE", "受け取れる大きさを超えています");
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return refuse("BAD_JSON", "JSON として読めません");
    }
    if (typeof o !== "object" || o === null || Array.isArray(o) || Object.keys(o).some((k) => !["pub", "use", "code", "sig", "att"].includes(k))) {
      return refuse("PAIR_BAD_REQUEST", "登録の形が違います");
    }
    const { pub, use, code, sig, att } = o;
    if (typeof pub !== "string" || !PUB_RE.test(pub) || (use !== "device" && use !== "approve") || typeof code !== "string" || !CODE_RE.test(code) || typeof sig !== "string") {
      return refuse("PAIR_BAD_REQUEST", "登録の形が違います");
    }
    // 鍵を持っている証明（合言葉を使う前に。誤った登録で合言葉を潰させない）
    const codeHash = await sha256Hex(code);
    if (!(await verifyDeviceSignature(pub, sig, pairingMessage({ co: who.co, by: who.by, use, pub, codeHash })))) {
      return refuse("PAIR_BAD_PROOF", "鍵を持っている証明が合いません");
    }
    // 鍵の証明（金庫の部品で作った・生体認証の作り方。合言葉を使う前に）
    if (opts.attest) {
      let a: { ok: true } | { ok: false; code: string; message: string };
      try {
        a = await opts.attest({ who, pub, use, att });
      } catch (error) {
        opts.onError?.({ error });
        return refuse("HANDLER", "処理中に問題が起きました");
      }
      if (!a.ok) return reply(403, { ok: false, code: "PAIR_ATTEST", reason: a.code, message: a.message });
    }
    try {
      if (!(await opts.store.take(who.co, who.by, codeHash, opts.now()))) return refuse("PAIR_CODE", "合言葉が違うか、期限が切れています");
      await opts.store.add(who.co, who.by, { pub, use });
    } catch (error) {
      opts.onError?.({ error });
      return refuse("HANDLER", "処理中に問題が起きました");
    }
    return reply(200, { ok: true, pub, use });
  };
}

export type ApprovalCheck = { ok: true } | { ok: false; code: "APPROVAL_BAD" | "APPROVAL_UNKNOWN" | "APPROVAL_CLOCK"; message: string };

/** 承認（ap）の確かめ。承認する本人の approve の鍵で、この封筒の中身に署名してあること */
export async function verifyApproval(p: {
  env: Envelope;
  approval: { pub: string; ts: number; sig: string };
  approver: UserIdentity;
  directory: DeviceDirectory;
  now: number;
  skewMs?: number;
}): Promise<ApprovalCheck> {
  const a = p.approval;
  if (!a || typeof a.pub !== "string" || typeof a.sig !== "string" || !Number.isSafeInteger(a.ts)) return { ok: false, code: "APPROVAL_BAD", message: "承認の形が違います" };
  if (p.approver.co !== p.env.co) return { ok: false, code: "APPROVAL_UNKNOWN", message: "別の会社の承認です" };
  if (Math.abs(p.now - a.ts) > (p.skewMs ?? APPROVAL_SKEW_MS)) return { ok: false, code: "APPROVAL_CLOCK", message: "承認の時刻がずれています" };
  const keys = await p.directory.keys(p.approver.co, p.approver.by);
  if (!keys.some((k) => k.use === "approve" && k.pub === a.pub)) return { ok: false, code: "APPROVAL_UNKNOWN", message: "登録されていない承認の鍵です" };
  if (!(await verifyDeviceSignature(a.pub, a.sig, await approvalMessage(p.env, a.ts)))) return { ok: false, code: "APPROVAL_BAD", message: "承認の署名が合いません" };
  return { ok: true };
}
