// X.509 の証明書を読み、署名を確かめる小さな部品（鍵の証明書のため。規格書 第21章）。外部部品なし（Web Crypto だけ）。
// Android の鍵の証明書（attestation.ts）と Apple の App Attest（appattest.ts）で共通に使う。

import { DerError, derBits, derChildren, derIntHex, derOid, derTime, expectTag, parseDer } from "./asn1.ts";

export interface Cert {
  tbs: Uint8Array;
  sigAlg: string;
  sig: Uint8Array;
  serial: string;
  notBefore: number;
  notAfter: number;
  spki: Uint8Array;
  spkiAlg: string;
  spkiCurve?: string;
  extensions: Map<string, Uint8Array>;
}

export function parseCert(raw: Uint8Array): Cert {
  const [tbsD, algD, sigD] = derChildren(expectTag(parseDer(raw), 16));
  const tbs = derChildren(expectTag(tbsD, 16));
  let k = 0;
  if (tbs[0] && tbs[0].cls === 2 && tbs[0].tag === 0) k++; // 版
  const serial = derIntHex(tbs[k++]!);
  k++; // 署名の方式（外側と同じもの）
  k++; // 発行者
  const [nb, na] = derChildren(expectTag(tbs[k++], 16));
  k++; // 主体
  const spkiD = expectTag(tbs[k++], 16);
  const [spkiAlgD] = derChildren(spkiD);
  const spkiAlgParts = derChildren(expectTag(spkiAlgD, 16));
  const spkiAlg = derOid(spkiAlgParts[0]!);
  const spkiCurve = spkiAlgParts[1] && spkiAlgParts[1].tag === 6 ? derOid(spkiAlgParts[1]) : undefined;
  const extensions = new Map<string, Uint8Array>();
  for (; k < tbs.length; k++) {
    const d = tbs[k]!;
    if (d.cls === 2 && d.tag === 3) {
      for (const ext of derChildren(expectTag(derChildren(d)[0], 16))) {
        const parts = derChildren(expectTag(ext, 16));
        const oid = derOid(parts[0]!);
        const val = expectTag(parts[parts.length - 1], 4).value;
        if (extensions.has(oid)) throw new DerError("同じ拡張が 2 つあります");
        extensions.set(oid, val);
      }
    }
  }
  const out: Cert = {
    tbs: tbsD!.raw,
    sigAlg: derOid(derChildren(expectTag(algD, 16))[0]!),
    sig: derBits(sigD!),
    serial,
    notBefore: derTime(nb!),
    notAfter: derTime(na!),
    spki: spkiD.raw,
    spkiAlg,
    extensions,
  };
  if (spkiCurve) out.spkiCurve = spkiCurve;
  return out;
}

const SIG_ALGS: Record<string, { kind: "ecdsa" | "rsa"; hash: "SHA-256" | "SHA-384" | "SHA-512" }> = {
  "1.2.840.10045.4.3.2": { kind: "ecdsa", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { kind: "ecdsa", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { kind: "ecdsa", hash: "SHA-512" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
};
const CURVES: Record<string, { name: "P-256" | "P-384" | "P-521"; size: number }> = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
  "1.3.132.0.34": { name: "P-384", size: 48 },
  "1.3.132.0.35": { name: "P-521", size: 66 },
};

/** ECDSA の DER の署名を、Web Crypto の形（r||s）にする */
function ecdsaRaw(der: Uint8Array, size: number): Uint8Array {
  const [r, s] = derChildren(expectTag(parseDer(der), 16));
  const out = new Uint8Array(size * 2);
  [r, s].forEach((d, i) => {
    let v = expectTag(d, 2).value;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new DerError("署名の大きさが違います");
    out.set(v, i * size + (size - v.length));
  });
  return out;
}

type Subtle = {
  importKey(f: "spki", k: Uint8Array, a: unknown, x: boolean, u: KeyUsage[]): Promise<CryptoKey>;
  verify(a: unknown, k: CryptoKey, s: Uint8Array, d: Uint8Array): Promise<boolean>;
};
const subtle = globalThis.crypto.subtle as unknown as Subtle;

/** child の署名を、issuer の公開鍵で確かめる */
export async function signedBy(child: Cert, issuer: Cert): Promise<boolean> {
  const alg = SIG_ALGS[child.sigAlg];
  if (!alg) return false;
  try {
    if (alg.kind === "rsa") {
      if (issuer.spkiAlg !== "1.2.840.113549.1.1.1") return false;
      const key = await subtle.importKey("spki", issuer.spki, { name: "RSASSA-PKCS1-v1_5", hash: alg.hash }, false, ["verify"]);
      return await subtle.verify("RSASSA-PKCS1-v1_5", key, child.sig, child.tbs);
    }
    const curve = issuer.spkiAlg === "1.2.840.10045.2.1" && issuer.spkiCurve ? CURVES[issuer.spkiCurve] : undefined;
    if (!curve) return false;
    const key = await subtle.importKey("spki", issuer.spki, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
    return await subtle.verify({ name: "ECDSA", hash: alg.hash }, key, ecdsaRaw(child.sig, curve.size), child.tbs);
  } catch {
    return false;
  }
}


/** 証明書の鎖（先頭が葉・最後が根）の有効期間と署名を確かめる。根は自分で署名している */
export async function verifyChain(certs: readonly Cert[], now: number): Promise<"ok" | "time" | "signature"> {
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i]!;
    if (now < c.notBefore || now > c.notAfter) return "time";
    if (!(await signedBy(c, certs[Math.min(i + 1, certs.length - 1)]!))) return "signature";
  }
  return "ok";
}

/** P-256 の公開鍵の SubjectPublicKeyInfo から、65 バイトの非圧縮形式を取り出す。P-256 でなければ undefined */
export function p256PublicKeyOf(c: Cert): Uint8Array | undefined {
  if (c.spkiAlg !== "1.2.840.10045.2.1" || c.spkiCurve !== "1.2.840.10045.3.1.7") return undefined;
  const [, bitsD] = derChildren(parseDer(c.spki));
  const raw = derBits(bitsD!);
  return raw.length === 65 && raw[0] === 0x04 ? raw : undefined;
}
