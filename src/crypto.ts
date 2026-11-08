// 署名・暗号化・ハッシュ。標準の Web Crypto だけを使う（外部部品なし）。
// Cloudflare Workers・Node.js 20 以上・ブラウザで同じように動く。

import type { Envelope } from "./envelope.ts";

// TypeScript 5.9 の型は Uint8Array の元の領域を厳しく区別するため、
// ここで使う関数だけ、受け取る型を Uint8Array に揃えて扱う（動きは標準のまま）。
type Bytes = Uint8Array;
interface Subtle {
  importKey(f: "raw", k: Bytes, a: HmacImportParams | AlgorithmIdentifier, x: boolean, u: KeyUsage[]): Promise<CryptoKey>;
  sign(a: "HMAC", k: CryptoKey, d: Bytes): Promise<ArrayBuffer>;
  verify(a: "HMAC", k: CryptoKey, s: Bytes, d: Bytes): Promise<boolean>;
  digest(a: "SHA-256", d: Bytes): Promise<ArrayBuffer>;
  encrypt(a: { name: "AES-GCM"; iv: Bytes; additionalData: Bytes }, k: CryptoKey, d: Bytes): Promise<ArrayBuffer>;
  decrypt(a: { name: "AES-GCM"; iv: Bytes; additionalData: Bytes }, k: CryptoKey, d: Bytes): Promise<ArrayBuffer>;
}
const subtle = globalThis.crypto.subtle as unknown as Subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---- base64url ----

export function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("base64url の形ではありません");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? encoder.encode(data) : data;
}

// ---- 決まった並びの JSON（署名の対象） ----

/** 項目名を並べ替えた JSON。同じ中身なら必ず同じ文字列になる */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    if (s === undefined) throw new Error("署名できない値が含まれています");
    return s;
  }
  if (value instanceof Uint8Array) return JSON.stringify(toBase64Url(value));
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function signingBytes(env: Envelope): Uint8Array {
  const { sig: _sig, ...rest } = env;
  return encoder.encode(canonicalJson(rest));
}

// ---- 署名（HMAC-SHA256） ----

/** 署名用の鍵を読み込む。鍵の値は土台（鍵レーン）からだけ受け取る */
export function importSigningKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength < 32) throw new Error("署名用の鍵は 32 バイト以上にしてください");
  return subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

/** 署名を付けた新しい封筒を返す（元の封筒は書き換えない） */
export async function signEnvelope(env: Envelope, key: CryptoKey): Promise<Envelope> {
  const mac = new Uint8Array(await subtle.sign("HMAC", key, signingBytes(env)));
  return { ...env, sig: toBase64Url(mac) };
}

/** 署名を確かめる。比較は一定時間で行われる（Web Crypto の verify） */
export async function verifyEnvelope(env: Envelope, key: CryptoKey): Promise<boolean> {
  if (typeof env.sig !== "string") return false;
  let mac: Uint8Array;
  try {
    mac = fromBase64Url(env.sig);
  } catch {
    return false;
  }
  if (mac.byteLength !== 32) return false;
  return subtle.verify("HMAC", key, mac, signingBytes(env));
}

// ---- ハッシュ（SHA-256） ----

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const d = new Uint8Array(await subtle.digest("SHA-256", toBytes(data)));
  let s = "";
  for (const x of d) s += x.toString(16).padStart(2, "0");
  return s;
}

/** 受け取った本文が、封筒の大きさ（len）とハッシュ（h）に一致するか */
export async function matchesBody(env: Pick<Envelope, "len" | "h">, data: Uint8Array): Promise<boolean> {
  if (env.len !== undefined && env.len !== data.byteLength) return false;
  if (env.h === undefined) return false;
  return (await sha256Hex(data)) === env.h;
}

// ---- 暗号化（AES-256-GCM） ----

/** 暗号化用の鍵を読み込む（32 バイト） */
export function importSealKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== 32) throw new Error("暗号化用の鍵は 32 バイトです");
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** 暗号文を、その封筒（会社・番号）にだけ結び付ける。別の封筒へ移すと開けない */
function aadOf(env: Pick<Envelope, "co" | "id">): Uint8Array {
  return encoder.encode(`lch1|${env.co}|${env.id}`);
}

/** 本文を暗号化して、封筒に入れられる文字列（b）にする */
export async function sealBody(
  env: Pick<Envelope, "co" | "id">,
  data: Uint8Array | string,
  key: CryptoKey,
): Promise<string> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadOf(env) }, key, toBytes(data)),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toBase64Url(out);
}

/** 暗号化された本文を開く。改ざん・別の封筒への付け替えは失敗する */
export async function openBody(env: Pick<Envelope, "co" | "id" | "b">, key: CryptoKey): Promise<Uint8Array> {
  if (typeof env.b !== "string") throw new Error("暗号化された本文がありません");
  const raw = fromBase64Url(env.b);
  if (raw.byteLength < 12 + 16) throw new Error("暗号文が短すぎます");
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv: raw.subarray(0, 12), additionalData: aadOf(env) },
    key,
    raw.subarray(12),
  );
  return new Uint8Array(pt);
}

export function openBodyText(env: Pick<Envelope, "co" | "id" | "b">, key: CryptoKey): Promise<string> {
  return openBody(env, key).then((b) => decoder.decode(b));
}
