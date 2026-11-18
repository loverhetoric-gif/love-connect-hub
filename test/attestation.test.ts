// Android の鍵の証明書（規格書 第21章）。本物と同じ形の証明書の鎖を試験の中で作り、正しいものだけが通ることを確かめる
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GOOGLE_ATTESTATION_ROOTS,
  attestationChallenge,
  createDeviceEnrollment,
  createTokenVerifier,
  createWebDeviceKey,
  issuePairingCode,
  pairingRequest,
  sha256Hex,
  toBase64Url,
  verifyAndroidAttestation,
  type DeviceKey,
  type PublicJwk,
} from "../src/index.ts";

// ---- DER を書く小さな道具（試験用） ----
const cat = (...a: Uint8Array[]) => { const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { out.set(x, i); i += x.length; } return out; };
const lenBytes = (n: number) => (n < 128 ? Uint8Array.of(n) : n < 256 ? Uint8Array.of(0x81, n) : n < 65536 ? Uint8Array.of(0x82, n >> 8, n & 0xff) : Uint8Array.of(0x83, n >> 16, (n >> 8) & 0xff, n & 0xff));
const tlv = (tag: number, ...v: Uint8Array[]) => { const body = cat(...v); return cat(Uint8Array.of(tag), lenBytes(body.length), body); };
const seq = (...v: Uint8Array[]) => tlv(0x30, ...v);
const set = (...v: Uint8Array[]) => tlv(0x31, ...v);
const int = (n: number) => { const b: number[] = []; let x = n; do { b.unshift(x & 0xff); x = Math.floor(x / 256); } while (x > 0); if (b[0]! & 0x80) b.unshift(0); return tlv(0x02, Uint8Array.from(b)); };
const enumv = (n: number) => tlv(0x0a, Uint8Array.of(n));
const octet = (b: Uint8Array | string) => tlv(0x04, typeof b === "string" ? new TextEncoder().encode(b) : b);
const bool = (v: boolean) => tlv(0x01, Uint8Array.of(v ? 0xff : 0));
const nul = () => Uint8Array.of(0x05, 0x00);
const bits = (b: Uint8Array) => tlv(0x03, Uint8Array.of(0), b);
const utc = (ms: number) => { const d = new Date(ms); const p = (n: number) => String(n).padStart(2, "0"); return tlv(0x17, new TextEncoder().encode(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`)); };
const oid = (s: string) => { const p = s.split(".").map(Number); const out: number[] = [p[0]! * 40 + p[1]!]; for (const n of p.slice(2)) { const b: number[] = []; let x = n; do { b.unshift(x & 0x7f); x = Math.floor(x / 128); } while (x > 0); for (let i = 0; i < b.length - 1; i++) b[i]! |= 0x80; out.push(...b); } return tlv(0x06, Uint8Array.from(out)); };
// 文脈のタグ（EXPLICIT）。31 以上は長い書き方
const ctx = (tag: number, inner: Uint8Array) => {
  if (tag < 31) return tlv(0xa0 | tag, inner);
  const b: number[] = []; let x = tag; do { b.unshift(x & 0x7f); x = Math.floor(x / 128); } while (x > 0); for (let i = 0; i < b.length - 1; i++) b[i]! |= 0x80;
  return cat(Uint8Array.of(0xbf, ...b), lenBytes(inner.length), inner);
};
const name = (cn: string) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));
const rawToDer = (raw: Uint8Array) => { const h = raw.length / 2; const part = (v: Uint8Array) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let x = v.subarray(i); if (x[0]! & 0x80) x = cat(Uint8Array.of(0), x); return tlv(0x02, x); }; return seq(part(raw.subarray(0, h)), part(raw.subarray(h))); };

const T0 = Date.UTC(2026, 10, 18);
const DAY = 86_400_000;
type Kp = { privateKey: CryptoKey; publicKey: CryptoKey; curve: "P-256" | "P-384" };
const ec = async (curve: "P-256" | "P-384"): Promise<Kp> => ({ ...((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, false, ["sign", "verify"])) as CryptoKeyPair), curve });
const spki = async (k: CryptoKey) => new Uint8Array(await crypto.subtle.exportKey("spki", k));

async function cert(o: { serial: number; subjectPub: CryptoKey; issuer: Kp; ext?: Uint8Array; notBefore?: number; notAfter?: number }) {
  const alg = seq(oid(o.issuer.curve === "P-384" ? "1.2.840.10045.4.3.3" : "1.2.840.10045.4.3.2"));
  const exts = o.ext ? ctx(3, seq(seq(oid("1.3.6.1.4.1.11129.2.1.17"), octet(o.ext)))) : new Uint8Array();
  const tbs = seq(ctx(0, int(2)), int(o.serial), alg, name("issuer"), seq(utc(o.notBefore ?? T0 - DAY), utc(o.notAfter ?? T0 + 365 * DAY)), name("subject"), await spki(o.subjectPub), exts);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: o.issuer.curve === "P-384" ? "SHA-384" : "SHA-256" }, o.issuer.privateKey, tbs));
  return seq(tbs, alg, bits(rawToDer(raw)));
}

type Kd = { level?: number; challenge?: Uint8Array; noAuth?: boolean; userAuthType?: number; authTimeout?: number; origin?: number; locked?: boolean; boot?: number; pkg?: string; digest?: Uint8Array; algorithm?: number };
function keyDescription(o: Kd & { challenge: Uint8Array }) {
  const lv = o.level ?? 1;
  const app = seq(set(seq(octet(o.pkg ?? "jp.pleats.app"), int(1))), set(octet(o.digest ?? new Uint8Array(32).fill(7))));
  const hw = [
    ctx(1, set(int(2))), ctx(2, int(o.algorithm ?? 3)), ctx(3, int(256)), ctx(5, set(int(4))), ctx(10, int(1)),
    ...(o.noAuth ? [ctx(503, nul())] : []),
    ...(o.userAuthType !== undefined ? [ctx(504, int(o.userAuthType))] : []),
    ...(o.authTimeout !== undefined ? [ctx(505, int(o.authTimeout))] : []),
    ctx(509, nul()),
    ctx(702, int(o.origin ?? 0)),
    ctx(704, seq(octet(new Uint8Array(32)), bool(o.locked ?? true), enumv(o.boot ?? 0), octet(new Uint8Array(32)))),
  ];
  return seq(int(300), enumv(lv), int(300), enumv(lv), octet(o.challenge), octet(new Uint8Array()), seq(ctx(709, octet(app))), seq(...hw));
}

async function chain(o: Kd & { use?: "device" | "approve" } = {}) {
  const root = await ec("P-384"), mid = await ec("P-256"), key = await createWebDeviceKey();
  const challenge = o.challenge ?? (await attestationChallenge("CO_A", "emp-1"));
  const kd = keyDescription({ userAuthType: (o.use ?? "approve") === "approve" ? 2 : undefined, ...o, challenge } as Kd & { challenge: Uint8Array });
  const leaf = await cert({ serial: 3, subjectPub: key.pair.publicKey, issuer: mid, ext: kd });
  const inter = await cert({ serial: 2, subjectPub: mid.publicKey, issuer: root });
  const top = await cert({ serial: 1, subjectPub: root.publicKey, issuer: root });
  return { key, root, ders: [leaf, inter, top], chain: [leaf, inter, top].map(toBase64Url), roots: [await sha256Hex(await spki(root.publicKey))] };
}

const base = async (c: Awaited<ReturnType<typeof chain>>, use: "device" | "approve" = "approve") =>
  ({ chain: c.chain, pub: c.key.pub, use, challenge: await attestationChallenge("CO_A", "emp-1"), now: T0, roots: c.roots });

test("Google の根：公開されている 2 つ（RSA 4096・ECDSA P-384）の公開鍵の SHA-256 を持つ", () => {
  assert.equal(GOOGLE_ATTESTATION_ROOTS.length, 2);
  for (const r of GOOGLE_ATTESTATION_ROOTS) assert.match(r, /^[0-9a-f]{64}$/);
});

test("正しい鎖：金庫の部品で作られ、使うたびに強い生体認証を求める承認の鍵は通る", async () => {
  const c = await chain();
  assert.deepEqual(await verifyAndroidAttestation(await base(c)), { ok: true, securityLevel: "tee", packages: ["jp.pleats.app"] });
  const sb = await chain({ level: 2 });
  const r = await verifyAndroidAttestation({ ...(await base(sb)), requireStrongBox: true });
  assert.equal(r.ok && r.securityLevel, "strongbox");
  // 送るための鍵は、生体認証を求めない作り方で通る
  const dv = await chain({ use: "device" });
  assert.equal((await verifyAndroidAttestation(await base(dv, "device"))).ok, true);
});

test("鎖：Google の根でない・署名を書き換えた・期限切れ・取り消し・形の違いは通さない", async () => {
  const c = await chain();
  const code = async (o: Parameters<typeof verifyAndroidAttestation>[0]) => { const r = await verifyAndroidAttestation(o); return r.ok ? "ok" : r.code; };
  assert.equal(await code({ ...(await base(c)), roots: undefined }), "ATTEST_ROOT", "既定は Google の根だけ");
  const tampered = c.ders.map((d) => d.slice());
  tampered[0]![60] = tampered[0]![60]! ^ 1;
  assert.equal(await code({ ...(await base(c)), chain: tampered.map(toBase64Url) }), "ATTEST_CHAIN");
  assert.equal(await code({ ...(await base(c)), now: T0 + 400 * DAY }), "ATTEST_CHAIN", "有効期間の外");
  assert.equal(await code({ ...(await base(c)), revoked: (s) => s === "02" }), "ATTEST_REVOKED");
  assert.equal(await code({ ...(await base(c)), chain: [c.chain[0]!] }), "ATTEST_BAD");
  assert.equal(await code({ ...(await base(c)), chain: ["AAAA", "BBBB"] }), "ATTEST_BAD");
  // 順番を入れ替えた鎖
  assert.equal(await code({ ...(await base(c)), chain: [c.chain[1]!, c.chain[0]!, c.chain[2]!] }), "ATTEST_CHAIN");
});

test("鍵の記述：別の鍵・ソフトウェアの鍵・問いかけ違い・生体認証の作り方の違いは通さない", async () => {
  const code = async (c: Awaited<ReturnType<typeof chain>>, extra: object = {}) => { const r = await verifyAndroidAttestation({ ...(await base(c)), ...extra }); return r.ok ? "ok" : r.code; };
  const c = await chain();
  assert.equal(await code(c, { pub: (await createWebDeviceKey()).pub }), "ATTEST_KEY");
  assert.equal(await code(await chain({ level: 0 })), "ATTEST_LEVEL", "ソフトウェアの鍵");
  assert.equal(await code(await chain(), { requireStrongBox: true }), "ATTEST_LEVEL");
  assert.equal(await code(await chain({ challenge: new Uint8Array(32) })), "ATTEST_CHALLENGE");
  assert.equal(await code(await chain({ userAuthType: 3 })), "ATTEST_POLICY", "PIN・パスワードでも代われる作り方");
  assert.equal(await code(await chain({ userAuthType: 1 })), "ATTEST_POLICY", "PIN・パスワードだけ");
  assert.equal(await code(await chain({ authTimeout: 30 })), "ATTEST_POLICY", "30 秒は認証なしで使える作り方");
  assert.equal(await code(await chain({ noAuth: true, userAuthType: undefined })), "ATTEST_POLICY", "認証が要らない作り方");
  assert.equal(await code(await chain({ origin: 2 })), "ATTEST_POLICY", "外から持ち込んだ鍵");
  assert.equal(await code(await chain({ algorithm: 1 })), "ATTEST_POLICY", "RSA の鍵");
  assert.equal(await code(await chain({ locked: false })), "ATTEST_BOOT", "起動の検査を外した端末");
  assert.equal(await code(await chain({ boot: 2 })), "ATTEST_BOOT");
  assert.equal(await code(await chain({ locked: false }), { requireVerifiedBoot: false }), "ok");
});

test("アプリ：許したパッケージ名と署名の証明書のものだけ通す", async () => {
  const digest = new Uint8Array(32).fill(9);
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  const c = await chain({ digest });
  const ok = await verifyAndroidAttestation({ ...(await base(c)), apps: [{ packageName: "jp.pleats.app", signatureDigests: [hex] }] });
  assert.equal(ok.ok, true);
  const otherPkg = await verifyAndroidAttestation({ ...(await base(c)), apps: [{ packageName: "jp.other.app", signatureDigests: [hex] }] });
  assert.equal(otherPkg.ok ? "ok" : otherPkg.code, "ATTEST_APP");
  const otherSig = await verifyAndroidAttestation({ ...(await base(c)), apps: [{ packageName: "jp.pleats.app", signatureDigests: ["00".repeat(32)] }] });
  assert.equal(otherSig.ok ? "ok" : otherSig.code, "ATTEST_APP");
});

test("登録の入口：鍵の証明を求める設定では、証明の無い・通らない登録を断る", async () => {
  const iss = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...((await crypto.subtle.exportKey("jwk", iss.publicKey)) as PublicJwk), kid: "k1" } as PublicJwk;
  const b64 = (o: unknown) => toBase64Url(new TextEncoder().encode(JSON.stringify(o)));
  const h = b64({ alg: "ES256", typ: "JWT", kid: "k1" }), s = T0 / 1000;
  const p = b64({ sub: "emp-1", iss: "iss", aud: "app", iat: s - 10, exp: s + 600 });
  const token = `${h}.${p}.${toBase64Url(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, iss.privateKey, new TextEncoder().encode(`${h}.${p}`))))}`;
  const keys: DeviceKey[] = [];
  const codes = new Map<string, number>();
  const store = { keys: () => keys, take: (_c: string, _b: string, hash: string, now: number) => { const u = codes.get(hash); codes.delete(hash); return u !== undefined && u > now; }, add: (_c: string, _b: string, k: DeviceKey) => void keys.push(k) };
  const c = await chain();
  const enroll = createDeviceEnrollment({
    verifier: createTokenVerifier({ issuer: "iss", audience: "app", now: () => T0, jwks: async () => ({ keys: [jwk] }) }),
    identify: (cl) => ({ co: "CO_A", by: cl.sub }),
    store,
    now: () => T0,
    // Android の承認の鍵には、鍵の証明を必須にする（アプリ側の決め方の見本）
    attest: async ({ who, pub, use, att }) => {
      const a = att as { platform?: string; chain?: string[] } | undefined;
      if (use !== "approve") return { ok: true };
      if (!a || a.platform !== "android" || !Array.isArray(a.chain)) return { ok: false, code: "ATTEST_BAD", message: "鍵の証明がありません" };
      return verifyAndroidAttestation({ chain: a.chain, pub, use, challenge: await attestationChallenge(who.co, who.by), now: T0, roots: c.roots });
    },
  });
  const send = async (body: object) => enroll(new Request("https://hub.example/lch/v1/device", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) }));
  const code1 = await issuePairingCode(T0); codes.set(code1.hash, code1.expiresAt);
  const req = await pairingRequest(c.key, { co: "CO_A", by: "emp-1", use: "approve", code: code1.code });
  const noAtt = await send(req);
  assert.equal(noAtt.status, 403);
  assert.deepEqual(await noAtt.json(), { ok: false, code: "PAIR_ATTEST", reason: "ATTEST_BAD", message: "鍵の証明がありません" });
  assert.equal(codes.size, 1, "証明が通らなければ、合言葉は使わない");
  const ok = await send({ ...req, att: { platform: "android", chain: c.chain } });
  assert.equal(ok.status, 200, await ok.clone().text());
  assert.deepEqual(keys, [{ pub: c.key.pub, use: "approve" }]);
  // 別の端末の鍵の証明書を付け替えても通らない
  const other = await chain();
  const code2 = await issuePairingCode(T0); codes.set(code2.hash, code2.expiresAt);
  const req2 = await pairingRequest(c.key, { co: "CO_A", by: "emp-1", use: "approve", code: code2.code });
  const swapped = await send({ ...req2, att: { platform: "android", chain: other.chain } });
  assert.equal(((await swapped.json()) as { code: string }).code, "PAIR_ATTEST");
});
