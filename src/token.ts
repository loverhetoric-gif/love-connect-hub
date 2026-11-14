// 利用者のトークン（JWT）の検査。規格書 第18章。
// アプリはログインした本人のトークンだけを持ち、署名用・暗号化用の鍵は持たない。
// 土台はトークンの署名・期限・発行元・宛先を確かめ、本人の ID（sub）を取り出す。
// 標準の Web Crypto だけを使う（外部部品なし）。

import { fromBase64Url } from "./crypto.ts";

/** 受け付ける署名方式。これ以外（none を含む）はすべて拒否する */
export type TokenAlg = "ES256" | "RS256" | "HS256";

export interface TokenClaims {
  /** 本人の ID */
  sub: string;
  /** 発行元 */
  iss: string;
  /** 期限（秒） */
  exp: number;
  /** 発行時刻（秒） */
  iat?: number;
  /** これより前は無効（秒） */
  nbf?: number;
  /** 宛先 */
  aud?: string | string[];
  /** そのほかの中身（会社・役割など）。何に使うかは各アプリが決める */
  [name: string]: unknown;
}

export type TokenCode = "TOKEN_MISSING" | "TOKEN_INVALID" | "TOKEN_EXPIRED";

export type TokenResult =
  | { ok: true; claims: TokenClaims }
  | { ok: false; code: TokenCode; message: string };

/** 公開鍵の一覧（JWKS）の 1 件。値はすべて公開してよいもの */
export interface PublicJwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
}

export interface TokenVerifierOptions {
  /** 発行元（iss）。一致しないトークンは拒否する */
  issuer: string;
  /** 宛先（aud）。トークンの aud に含まれていなければ拒否する */
  audience: string;
  /** 土台の時計（ミリ秒） */
  now: () => number;
  /** 公開鍵の一覧を取る（ES256・RS256）。kid の分からない鍵が来たときだけ取り直す */
  jwks?: () => Promise<{ keys: PublicJwk[] }>;
  /** 共通鍵（HS256）。鍵の値は土台（鍵レーン）からだけ受け取る */
  hsKey?: CryptoKey;
  /** 時計のずれを許す幅（秒、既定 30） */
  skewSec?: number;
  /** トークンの有効期間の上限（秒、既定 3600）。長すぎるトークンは受け付けない */
  maxLifetimeSec?: number;
  /** 公開鍵の一覧を取り直す最短の間隔（ミリ秒、既定 60 秒） */
  refreshMs?: number;
}

export interface TokenVerifier {
  verify(token: string | undefined): Promise<TokenResult>;
}

/** トークンの長さの上限（文字）。これを超えるものは中を読まずに拒否する */
export const TOKEN_MAX_CHARS = 8192;

type Bytes = Uint8Array;
interface Subtle {
  importKey(f: "jwk", k: JsonWebKey, a: EcKeyImportParams | RsaHashedImportParams, x: boolean, u: KeyUsage[]): Promise<CryptoKey>;
  verify(a: AlgorithmIdentifier | EcdsaParams, k: CryptoKey, s: Bytes, d: Bytes): Promise<boolean>;
}
const subtle = globalThis.crypto.subtle as unknown as Subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const TOKEN_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function bad(message: string): TokenResult {
  return { ok: false, code: "TOKEN_INVALID", message };
}

function readJson(part: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(decoder.decode(fromBase64Url(part)));
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** Authorization 見出しから Bearer トークンを取り出す。形が違えば undefined */
export function bearerToken(header: string | null): string | undefined {
  if (!header) return undefined;
  const m = /^Bearer[ ]+([A-Za-z0-9_.-]+)$/i.exec(header.trim());
  return m?.[1];
}

/** 公開鍵を読み込む。方式と鍵の種類が合わないもの（取り違えの攻撃）は拒否する */
async function importPublic(jwk: PublicJwk, alg: "ES256" | "RS256"): Promise<CryptoKey | undefined> {
  if (jwk.alg !== undefined && jwk.alg !== alg) return undefined;
  if (jwk.use !== undefined && jwk.use !== "sig") return undefined;
  try {
    if (alg === "ES256") {
      if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) return undefined;
      const k: JsonWebKey = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
      return await subtle.importKey("jwk", k, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    }
    if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) return undefined;
    if (fromBase64Url(jwk.n).byteLength < 256) return undefined; // 2048 ビット未満は使わない
    const k: JsonWebKey = { kty: "RSA", n: jwk.n, e: jwk.e };
    return await subtle.importKey("jwk", k, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  } catch {
    return undefined;
  }
}

export function createTokenVerifier(opts: TokenVerifierOptions): TokenVerifier {
  if (!opts.jwks && !opts.hsKey) throw new Error("公開鍵の一覧（jwks）か共通鍵（hsKey）のどちらかが必要です");
  if (!opts.issuer || !opts.audience) throw new Error("発行元（issuer）と宛先（audience）は必須です");
  const skew = opts.skewSec ?? 30;
  const maxLife = opts.maxLifetimeSec ?? 3600;
  const refreshMs = opts.refreshMs ?? 60_000;

  // kid と方式ごとに、読み込んだ公開鍵を覚えておく
  const keys = new Map<string, CryptoKey>();
  let lastFetch = Number.NEGATIVE_INFINITY;
  let loading: Promise<void> | undefined;

  async function load(): Promise<void> {
    if (!opts.jwks) return;
    const set = await opts.jwks();
    keys.clear();
    for (const jwk of set.keys ?? []) {
      if (typeof jwk.kid !== "string" || jwk.kid === "") continue;
      for (const alg of ["ES256", "RS256"] as const) {
        const k = await importPublic(jwk, alg);
        if (k) keys.set(`${alg}|${jwk.kid}`, k);
      }
    }
  }

  async function publicKey(alg: "ES256" | "RS256", kid: string): Promise<CryptoKey | undefined> {
    const name = `${alg}|${kid}`;
    const hit = keys.get(name);
    if (hit) return hit;
    // 知らない kid のときだけ取り直す。取り直しは間隔を空ける（偽の kid で一覧を叩かせない）
    const t = opts.now();
    if (t - lastFetch < refreshMs) {
      if (loading) await loading.catch(() => {});
      return keys.get(name);
    }
    lastFetch = t;
    loading = load();
    try {
      await loading;
    } catch {
      return undefined;
    } finally {
      loading = undefined;
    }
    return keys.get(name);
  }

  return {
    async verify(token) {
      // 1. 形（安い順）
      if (token === undefined || token === "") return { ok: false, code: "TOKEN_MISSING", message: "ログインのトークンがありません" };
      if (token.length > TOKEN_MAX_CHARS || !TOKEN_RE.test(token)) return bad("トークンの形が正しくありません");
      const [h64, p64, s64] = token.split(".") as [string, string, string];
      const header = readJson(h64);
      if (!header) return bad("トークンの見出しが読めません");
      const alg = header.alg;
      if (alg !== "ES256" && alg !== "RS256" && alg !== "HS256") return bad("受け付けない署名方式です");
      if (header.crit !== undefined) return bad("理解できない必須の拡張があります");

      // 2. 署名（中身を信じる前に確かめる）
      let sig: Uint8Array;
      try {
        sig = fromBase64Url(s64);
      } catch {
        return bad("署名が読めません");
      }
      const data = encoder.encode(`${h64}.${p64}`);
      let valid = false;
      if (alg === "HS256") {
        if (!opts.hsKey) return bad("受け付けない署名方式です");
        valid = sig.byteLength === 32 && (await subtle.verify("HMAC", opts.hsKey, sig, data));
      } else {
        if (!opts.jwks) return bad("受け付けない署名方式です");
        const kid = header.kid;
        if (typeof kid !== "string" || kid === "" || kid.length > 256) return bad("鍵の番号（kid）がありません");
        const key = await publicKey(alg, kid);
        if (!key) return bad("知らない鍵で署名されています");
        valid =
          alg === "ES256"
            ? sig.byteLength === 64 && (await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data))
            : await subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
      }
      if (!valid) return bad("署名が一致しません");

      // 3. 中身
      const c = readJson(p64);
      if (!c) return bad("トークンの中身が読めません");
      if (typeof c.sub !== "string" || c.sub === "") return bad("本人の ID（sub）がありません");
      if (c.iss !== opts.issuer) return bad("発行元が違います");
      const aud = c.aud;
      const auds = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud : [];
      if (!auds.includes(opts.audience)) return bad("宛先が違います");
      if (typeof c.exp !== "number" || !Number.isFinite(c.exp)) return bad("期限がありません");
      if (c.iat !== undefined && (typeof c.iat !== "number" || !Number.isFinite(c.iat))) return bad("発行時刻が正しくありません");
      if (c.nbf !== undefined && (typeof c.nbf !== "number" || !Number.isFinite(c.nbf))) return bad("開始時刻が正しくありません");

      // 4. 時刻（土台の時計だけを使う）
      const nowSec = opts.now() / 1000;
      if (nowSec > c.exp + skew) return { ok: false, code: "TOKEN_EXPIRED", message: "ログインの期限が切れています" };
      if (typeof c.nbf === "number" && nowSec + skew < c.nbf) return bad("まだ使えないトークンです");
      if (typeof c.iat === "number" && nowSec + skew < c.iat) return bad("発行時刻が未来になっています");
      const start = typeof c.iat === "number" ? c.iat : nowSec;
      if (c.exp - start > maxLife) return bad("有効期間が長すぎるトークンです");

      return { ok: true, claims: c as TokenClaims };
    },
  };
}
