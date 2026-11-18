// Apple の App Attest（iPhone・iPad・Mac）を確かめる。規格書 第21章。
// App Attest は、端末の金庫の部品（Secure Enclave）で作った「アプリの鍵」に、Apple が証明書を出す仕組み。
// 土台はこれを確かめ、「Apple の本物の端末の上の、許したアプリ（チーム ID・バンドル ID）が、この端末の鍵を登録している」ことを、
// アプリの申告を信じずに確かめる。外部部品は入れず、Web Crypto だけで確かめる。
//
// 注意：App Attest が証明するのは「アプリと端末が本物であること」。登録する端末の鍵（pub）そのものが Secure Enclave の中にあることや、
// 生体認証の作り方までは証明しない（Apple は鍵ごとの証明を出さない）。pub は clientDataHash に入れて、この証明と結び付ける。

import { CborError, type CborValue, decodeCbor } from "./cbor.ts";
import { DerError, derChildren, expectTag, parseDer } from "./asn1.ts";
import { type Cert, p256PublicKeyOf, parseCert, signedBy } from "./x509.ts";
import { fromBase64Url, sha256Hex } from "./crypto.ts";
import type { DeviceUse } from "./device.ts";

/**
 * Apple App Attestation Root CA（ECDSA P-384、2020-03-18〜2045-03-15）。
 * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem（2026-11-18 に取得）
 * x5c には根が入らないので、根の証明書そのものを持つ。公開鍵の SHA-256 は APPLE_APP_ATTEST_ROOT_SPKI_SHA256
 */
export const APPLE_APP_ATTEST_ROOT =
  "MIICITCCAaegAwIBAgIQC_O-DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs_Ii2FdCgAHGbpphY3-d8qjuDngIN3WVhQUBHAoMeQ_cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H-xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH_MB0GA1UdDgQWBBSskRBTM72-aEH_pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4-sQmTvb7vn53O5-FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd_dganmrduC1bmTBGwD";
export const APPLE_APP_ATTEST_ROOT_SPKI_SHA256 = "1ae751fd29896d0f1f13fe226c063f445d40d8938acc6245c251ecc0679330bd";

const NONCE_OID = "1.2.840.113635.100.8.2";
const enc = new TextEncoder();
const AAGUID_PROD = Uint8Array.from([..."appattest"].map((c) => c.charCodeAt(0)).concat([0, 0, 0, 0, 0, 0, 0]));
const AAGUID_DEV = enc.encode("appattestdevelop");

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16));
const sha256 = async (d: Uint8Array | string) => hexBytes(await sha256Hex(d));
const concat = (a: Uint8Array, b: Uint8Array) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
};

/** App Attest の attestKey に渡す clientDataHash。会社・本人・使い道・登録する端末の鍵に結び付ける */
export function appAttestClientDataHash(p: { co: string; by: string; use: DeviceUse; pub: string }): Promise<Uint8Array> {
  return sha256(`lch-appattest-v1\n${p.co}\n${p.by}\n${p.use}\n${p.pub}`);
}

export type AppAttestCode = "APPATTEST_BAD" | "APPATTEST_CHAIN" | "APPATTEST_ROOT" | "APPATTEST_NONCE" | "APPATTEST_KEY" | "APPATTEST_APP" | "APPATTEST_ENV";

export type AppAttestResult =
  | { ok: true; environment: "production" | "development"; appId: string; keyId: string; receipt: Uint8Array }
  | { ok: false; code: AppAttestCode; message: string };

export interface AppAttestOptions {
  /** DCAppAttestService.attestKey が返した attestation object（base64 か base64url） */
  attestation: string;
  /** DCAppAttestService.generateKey が返した鍵の ID（base64 か base64url） */
  keyId: string;
  /** attestKey に渡した clientDataHash（appAttestClientDataHash） */
  clientDataHash: Uint8Array;
  /** 許すアプリ（「チーム ID.バンドル ID」） */
  appIds: readonly string[];
  now: number;
  /** 開発用の証明（appattestdevelop）も許す（既定 false：本番の証明だけ） */
  allowDevelopment?: boolean;
  /** 根の証明書（base64url の DER。既定 APPLE_APP_ATTEST_ROOT）。試験のときだけ差し替える */
  root?: string;
  /** 根の公開鍵の SHA-256（既定 APPLE_APP_ATTEST_ROOT_SPKI_SHA256） */
  rootSpkiSha256?: string;
}

const fail = (code: AppAttestCode, message: string): AppAttestResult => ({ ok: false, code, message });

function decodeB64(s: string): Uint8Array {
  return fromBase64Url(s.replace(/\s+/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

/** 証明書の拡張（1.2.840.113635.100.8.2）から nonce を取り出す：SEQUENCE { [1] EXPLICIT OCTET STRING } */
function nonceOf(ext: Uint8Array): Uint8Array {
  for (const f of derChildren(expectTag(parseDer(ext), 16))) {
    if (f.cls === 2 && f.tag === 1) return expectTag(derChildren(f)[0], 4).value;
  }
  throw new DerError("nonce がありません");
}

/** authenticatorData を読む（rpIdHash 32・flags 1・signCount 4・aaguid 16・credentialId の長さ 2・credentialId・公開鍵） */
function parseAuthData(a: Uint8Array): { rpIdHash: Uint8Array; signCount: number; aaguid: Uint8Array; credentialId: Uint8Array } {
  if (a.length < 55 || (a[32]! & 0x40) === 0) throw new CborError("authenticatorData の形が違います");
  const signCount = ((a[33]! << 24) >>> 0) + (a[34]! << 16) + (a[35]! << 8) + a[36]!;
  const len = (a[53]! << 8) + a[54]!;
  if (55 + len > a.length) throw new CborError("authenticatorData の形が違います");
  return { rpIdHash: a.subarray(0, 32), signCount, aaguid: a.subarray(37, 53), credentialId: a.subarray(55, 55 + len) };
}

/**
 * App Attest の証明を確かめる（Apple の手順どおり）。順番：
 * 形 → 証明書の鎖（Apple の根まで・有効期間）→ nonce（authData と clientDataHash）→ 鍵の ID → アプリ（rpIdHash）
 * → 使った回数 0 → 本番・開発の別 → credentialId
 */
export async function verifyAppleAppAttest(o: AppAttestOptions): Promise<AppAttestResult> {
  let x5c: Uint8Array[];
  let authData: Uint8Array;
  let receipt: Uint8Array;
  let keyId: Uint8Array;
  try {
    keyId = decodeB64(o.keyId);
    const obj = decodeCbor(decodeB64(o.attestation));
    if (!(obj instanceof Map) || obj.get("fmt") !== "apple-appattest") return fail("APPATTEST_BAD", "App Attest の証明ではありません");
    const st = obj.get("attStmt");
    const ad = obj.get("authData");
    if (!(st instanceof Map) || !(ad instanceof Uint8Array)) return fail("APPATTEST_BAD", "証明の形が違います");
    const chain = st.get("x5c");
    const rc = st.get("receipt");
    if (!Array.isArray(chain) || chain.length < 2 || chain.length > 5 || !chain.every((c: CborValue) => c instanceof Uint8Array) || !(rc instanceof Uint8Array)) {
      return fail("APPATTEST_BAD", "証明の形が違います");
    }
    x5c = chain as Uint8Array[];
    authData = ad;
    receipt = rc;
  } catch {
    return fail("APPATTEST_BAD", "証明を読めません");
  }
  if (keyId.length !== 32) return fail("APPATTEST_BAD", "鍵の ID の形が違います");
  // 1. 証明書の鎖：x5c（葉から順に）＋ 持っている根
  let certs: Cert[];
  let root: Cert;
  try {
    certs = x5c.map(parseCert);
    root = parseCert(decodeB64(o.root ?? APPLE_APP_ATTEST_ROOT));
  } catch {
    return fail("APPATTEST_BAD", "証明書を読めません");
  }
  if ((await sha256Hex(root.spki)) !== (o.rootSpkiSha256 ?? APPLE_APP_ATTEST_ROOT_SPKI_SHA256)) return fail("APPATTEST_ROOT", "Apple の根の証明書ではありません");
  const all = [...certs, root];
  for (let i = 0; i < all.length; i++) {
    const c = all[i]!;
    if (o.now < c.notBefore || o.now > c.notAfter) return fail("APPATTEST_CHAIN", "有効期間の外の証明書があります");
    if (i < all.length - 1 && !(await signedBy(c, all[i + 1]!))) return fail("APPATTEST_CHAIN", "Apple の根の証明書につながっていません");
  }
  const leaf = certs[0]!;
  // 2〜4. nonce = SHA-256(authData ‖ clientDataHash) が、葉の拡張と同じ
  const ext = leaf.extensions.get(NONCE_OID);
  let nonce: Uint8Array;
  try {
    if (!ext) throw new DerError("nonce がありません");
    nonce = nonceOf(ext);
  } catch {
    return fail("APPATTEST_BAD", "nonce を読めません");
  }
  if (!eq(nonce, await sha256(concat(authData, o.clientDataHash)))) return fail("APPATTEST_NONCE", "nonce が合いません（別の登録の証明です）");
  // 5. 鍵の ID = SHA-256(葉の公開鍵)
  const pub = p256PublicKeyOf(leaf);
  if (!pub || !eq(await sha256(pub), keyId)) return fail("APPATTEST_KEY", "鍵の ID が証明書の鍵と違います");
  let a: ReturnType<typeof parseAuthData>;
  try {
    a = parseAuthData(authData);
  } catch {
    return fail("APPATTEST_BAD", "authenticatorData を読めません");
  }
  // 6. アプリ：rpIdHash = SHA-256(チーム ID.バンドル ID)
  let appId: string | undefined;
  for (const id of o.appIds) if (eq(a.rpIdHash, await sha256(id))) appId = id;
  if (!appId) return fail("APPATTEST_APP", "許可していないアプリの証明です");
  // 7. 新しく作った鍵（使った回数 0）
  if (a.signCount !== 0) return fail("APPATTEST_BAD", "新しく作った鍵の証明ではありません");
  // 8. 本番・開発の別
  const environment = eq(a.aaguid, AAGUID_PROD) ? "production" : eq(a.aaguid, AAGUID_DEV) ? "development" : undefined;
  if (!environment) return fail("APPATTEST_BAD", "証明の種類が違います");
  if (environment === "development" && !o.allowDevelopment) return fail("APPATTEST_ENV", "開発用の証明は受け付けていません");
  // 9. credentialId = 鍵の ID
  if (!eq(a.credentialId, keyId)) return fail("APPATTEST_KEY", "credentialId が鍵の ID と違います");
  return { ok: true, environment, appId, keyId: Array.from(keyId, (b) => b.toString(16).padStart(2, "0")).join(""), receipt };
}
