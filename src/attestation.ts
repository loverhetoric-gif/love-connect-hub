// Android の鍵の証明書（Key Attestation）を確かめる。規格書 第21章。
// 端末の鍵を作るとき、Android Keystore は Google の根まで続く証明書の鎖を出す。その中の鍵の記述（KeyDescription）は、
// 端末の金庫の部品（TEE・StrongBox）が書き込む。土台はこれを確かめ、「鍵が金庫の中で作られ、使うたびに強い生体認証を求める」ことを、
// アプリの申告を信じずに確かめる。外部部品は入れず、Web Crypto だけで確かめる。

import { type Der, DerError, derBool, derChildren, derInt, expectTag, parseDer } from "./asn1.ts";
import { type Cert, parseCert, verifyChain } from "./x509.ts";
import { fromBase64Url, sha256Hex, toBase64Url } from "./crypto.ts";
import type { DeviceUse } from "./device.ts";

/**
 * Google の鍵の証明書の根（公開鍵 SubjectPublicKeyInfo の SHA-256）。https://android.googleapis.com/attestation/root（2026-11-18 に取得）
 * - RSA 4096 ビット（serialNumber=f92009e853b6b045、2042-03-15 まで）
 * - ECDSA P-384「Key Attestation CA1」（2035-07-15 まで）
 * 根が増えたら、Google の公開している一覧から足す（版を上げる変更にしない。足すだけ）
 */
export const GOOGLE_ATTESTATION_ROOTS: readonly string[] = Object.freeze([
  "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
  "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
]);

const KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
const enc = new TextEncoder();

/** 鍵の証明書に入れる問いかけ（challenge）。会社と本人に結び付ける。アプリは鍵を作るときにこれを渡す */
export async function attestationChallenge(co: string, by: string): Promise<Uint8Array> {
  const hex = await sha256Hex(`lch-attest-v1\n${co}\n${by}`);
  return Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16));
}

// ---- 鍵の記述（KeyDescription）----

/** 鍵の性質の一覧（AuthorizationList のうち、確かめるものだけ） */
export interface KeyAuthorizations {
  purpose: number[];
  algorithm?: number;
  ecCurve?: number;
  noAuthRequired: boolean;
  userAuthType?: number;
  authTimeout?: number;
  unlockedDeviceRequired: boolean;
  origin?: number;
  rootOfTrust?: { deviceLocked: boolean; verifiedBootState: number };
  attestationApplicationId?: Uint8Array;
}

export interface KeyDescription {
  attestationVersion: number;
  /** 0 ソフトウェア・1 TEE（信頼できる実行環境）・2 StrongBox */
  attestationSecurityLevel: number;
  keyMintSecurityLevel: number;
  challenge: Uint8Array;
  software: KeyAuthorizations;
  hardware: KeyAuthorizations;
}

function authorizations(d: Der): KeyAuthorizations {
  const out: KeyAuthorizations = { purpose: [], noAuthRequired: false, unlockedDeviceRequired: false };
  for (const f of derChildren(expectTag(d, 16))) {
    if (f.cls !== 2) throw new DerError("鍵の性質の形が違います");
    const inner = derChildren(f)[0]!;
    switch (f.tag) {
      case 1: out.purpose = derChildren(expectTag(inner, 17)).map(derInt); break;
      case 2: out.algorithm = derInt(inner); break;
      case 10: out.ecCurve = derInt(inner); break;
      case 503: out.noAuthRequired = true; break;
      case 504: out.userAuthType = derInt(inner); break;
      case 505: out.authTimeout = derInt(inner); break;
      case 509: out.unlockedDeviceRequired = true; break;
      case 702: out.origin = derInt(inner); break;
      case 704: {
        const r = derChildren(expectTag(inner, 16));
        out.rootOfTrust = { deviceLocked: derBool(r[1]!), verifiedBootState: derInt(r[2]!) };
        break;
      }
      case 709: out.attestationApplicationId = expectTag(inner, 4).value; break;
      default: break; // ほかの性質は確かめない（読み飛ばす）
    }
  }
  return out;
}

export function parseKeyDescription(ext: Uint8Array): KeyDescription {
  const f = derChildren(expectTag(parseDer(ext), 16));
  if (f.length < 8) throw new DerError("鍵の記述の形が違います");
  return {
    attestationVersion: derInt(f[0]!),
    attestationSecurityLevel: derInt(f[1]!),
    keyMintSecurityLevel: derInt(f[3]!),
    challenge: expectTag(f[4], 4).value,
    software: authorizations(f[6]!),
    hardware: authorizations(f[7]!),
  };
}

/** アプリの識別（attestationApplicationId）：パッケージ名と、署名の証明書の SHA-256（16 進） */
export function parseApplicationId(raw: Uint8Array): { packages: string[]; signatureDigests: string[] } {
  const [infos, digests] = derChildren(expectTag(parseDer(raw), 16));
  const packages = derChildren(expectTag(infos, 17)).map((p) => new TextDecoder().decode(expectTag(derChildren(expectTag(p, 16))[0], 4).value));
  const signatureDigests = derChildren(expectTag(digests, 17)).map((d) => Array.from(expectTag(d, 4).value, (b) => b.toString(16).padStart(2, "0")).join(""));
  return { packages, signatureDigests };
}

// ---- 確かめる ----

export type AttestationCode =
  | "ATTEST_BAD"
  | "ATTEST_CHAIN"
  | "ATTEST_ROOT"
  | "ATTEST_REVOKED"
  | "ATTEST_KEY"
  | "ATTEST_LEVEL"
  | "ATTEST_CHALLENGE"
  | "ATTEST_POLICY"
  | "ATTEST_BOOT"
  | "ATTEST_APP";

export type AttestationResult =
  | { ok: true; securityLevel: "tee" | "strongbox"; packages: string[] }
  | { ok: false; code: AttestationCode; message: string };

export interface AndroidAttestationOptions {
  /** 証明書の鎖（base64 か base64url の DER。鍵の証明書が先頭、根が最後） */
  chain: readonly string[];
  /** 登録する公開鍵（65 バイトの base64url）。鎖の先頭の公開鍵と同じでなければならない */
  pub: string;
  use: DeviceUse;
  /** 鍵を作るときに渡した問いかけ（attestationChallenge） */
  challenge: Uint8Array;
  now: number;
  /** 根の公開鍵の SHA-256（既定 GOOGLE_ATTESTATION_ROOTS） */
  roots?: readonly string[];
  /** 取り消された証明書か（https://android.googleapis.com/attestation/status の entries を、土台が 1 日 1 回ほど取って渡す） */
  revoked?: (serialHex: string) => boolean | Promise<boolean>;
  /** 許すアプリ（パッケージ名と、署名の証明書の SHA-256）。渡したときだけ確かめる */
  apps?: readonly { packageName: string; signatureDigests: readonly string[] }[];
  /** StrongBox だけを許す（既定 false：TEE 以上） */
  requireStrongBox?: boolean;
  /** 起動の検査が通った（改造されていない）端末だけを許す（既定 true） */
  requireVerifiedBoot?: boolean;
}

const fail = (code: AttestationCode, message: string): AttestationResult => ({ ok: false, code, message });

function decodeDer(s: string): Uint8Array {
  return fromBase64Url(s.replace(/\s+/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

/** 65 バイトの非圧縮形式の公開鍵を、SubjectPublicKeyInfo（P-256）の形にする */
function p256Spki(pubRaw: Uint8Array): Uint8Array {
  const head = Uint8Array.from([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]);
  const out = new Uint8Array(head.length + pubRaw.length);
  out.set(head);
  out.set(pubRaw, head.length);
  return out;
}

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Android の鍵の証明書を確かめる。順番：
 * 鎖の形 → 有効期間 → 各証明書の署名（Google の根まで）→ 取り消し → 公開鍵が登録するものと同じ → 鍵の記述
 * （金庫の部品で作った・問いかけ・使い道・作り方・使う種類ごとの本人確認・起動の検査・アプリ）
 */
export async function verifyAndroidAttestation(o: AndroidAttestationOptions): Promise<AttestationResult> {
  let certs: Cert[];
  try {
    if (!Array.isArray(o.chain) || o.chain.length < 2 || o.chain.length > 10) return fail("ATTEST_BAD", "証明書の鎖の形が違います");
    certs = o.chain.map((c) => parseCert(decodeDer(c)));
  } catch {
    return fail("ATTEST_BAD", "証明書を読めません");
  }
  // 有効期間と署名（根は自分で署名している）
  const chainCheck = await verifyChain(certs, o.now);
  if (chainCheck === "time") return fail("ATTEST_CHAIN", "有効期間の外の証明書があります");
  if (chainCheck === "signature") return fail("ATTEST_CHAIN", "証明書の署名が合いません");
  const root = certs[certs.length - 1]!;
  if (!(o.roots ?? GOOGLE_ATTESTATION_ROOTS).includes(await sha256Hex(root.spki))) return fail("ATTEST_ROOT", "Google の根の証明書につながっていません");
  if (o.revoked) for (const c of certs) if (await o.revoked(c.serial)) return fail("ATTEST_REVOKED", "取り消された証明書があります");
  // 鍵：鎖の先頭が、登録する公開鍵の証明書
  const leaf = certs[0]!;
  let pubRaw: Uint8Array;
  try {
    pubRaw = fromBase64Url(o.pub);
  } catch {
    return fail("ATTEST_KEY", "公開鍵の形が違います");
  }
  if (pubRaw.length !== 65 || !eq(leaf.spki, p256Spki(pubRaw))) return fail("ATTEST_KEY", "証明書の鍵が、登録する鍵と違います");
  const ext = leaf.extensions.get(KEY_DESCRIPTION_OID);
  if (!ext) return fail("ATTEST_BAD", "鍵の記述がありません");
  let kd: KeyDescription;
  try {
    kd = parseKeyDescription(ext);
  } catch {
    return fail("ATTEST_BAD", "鍵の記述を読めません");
  }
  // 金庫の部品で作った（ソフトウェアの鍵は通さない）
  const level = Math.min(kd.attestationSecurityLevel, kd.keyMintSecurityLevel);
  if (level < (o.requireStrongBox ? 2 : 1)) return fail("ATTEST_LEVEL", o.requireStrongBox ? "StrongBox で作られた鍵ではありません" : "端末の金庫の部品で作られた鍵ではありません");
  if (!eq(kd.challenge, o.challenge)) return fail("ATTEST_CHALLENGE", "問いかけが違います");
  // 性質は、金庫の部品が守るもの（hardware）だけを信じる
  const hw = kd.hardware;
  if (!hw.purpose.includes(2) || hw.algorithm !== 3 || hw.ecCurve !== 1) return fail("ATTEST_POLICY", "署名用の P-256 の鍵ではありません");
  if (hw.origin !== 0) return fail("ATTEST_POLICY", "端末の中で作られた鍵ではありません");
  if (o.use === "approve") {
    // 使うたびに強い生体認証（userAuthType に生体 2 があり、パスワード・PIN 1 が無い。時間で許す作り方ではない）
    if (hw.noAuthRequired || hw.userAuthType === undefined || (hw.userAuthType & 2) === 0 || (hw.userAuthType & 1) !== 0 || (hw.authTimeout !== undefined && hw.authTimeout !== 0)) {
      return fail("ATTEST_POLICY", "承認の鍵が、使うたびに生体認証を求める作り方になっていません");
    }
  }
  if (o.requireVerifiedBoot !== false) {
    const rot = hw.rootOfTrust;
    if (!rot || !rot.deviceLocked || rot.verifiedBootState !== 0) return fail("ATTEST_BOOT", "起動の検査が通っていない端末です（改造・開発用の可能性）");
  }
  let packages: string[] = [];
  const appId = kd.software.attestationApplicationId ?? hw.attestationApplicationId;
  if (appId) {
    try {
      const a = parseApplicationId(appId);
      packages = a.packages;
      if (o.apps && !o.apps.some((x) => a.packages.includes(x.packageName) && a.signatureDigests.some((d) => x.signatureDigests.includes(d)))) {
        return fail("ATTEST_APP", "許可していないアプリで作られた鍵です");
      }
    } catch {
      return fail("ATTEST_BAD", "アプリの識別を読めません");
    }
  } else if (o.apps) {
    return fail("ATTEST_APP", "アプリの識別がありません");
  }
  return { ok: true, securityLevel: level >= 2 ? "strongbox" : "tee", packages };
}

/** 証明書を base64url にする（アプリから送るときの形） */
export const certToBase64Url = (der: Uint8Array): string => toBase64Url(der);
