// Apple の App Attest（規格書 第21章）。本物と同じ形の attestation object を試験の中で作り、正しいものだけが通ることを確かめる
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APPLE_APP_ATTEST_ROOT,
  APPLE_APP_ATTEST_ROOT_SPKI_SHA256,
  appAttestClientDataHash,
  createAttestationCheck,
  createDeviceEnrollment,
  createTokenVerifier,
  issuePairingCode,
  pairingRequest,
  type DeviceKey,
  type PublicJwk,
  createWebDeviceKey,
  decodeCbor,
  fromBase64Url,
  sha256Hex,
  toBase64Url,
  verifyAppleAppAttest,
} from "../src/index.ts";
import { parseCert } from "../src/x509.ts";

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

async function cert(o: { serial: number; subjectPub: CryptoKey; issuer: Kp; extOid?: string; ext?: Uint8Array; notBefore?: number; notAfter?: number }) {
  const alg = seq(oid(o.issuer.curve === "P-384" ? "1.2.840.10045.4.3.3" : "1.2.840.10045.4.3.2"));
  const exts = o.ext ? ctx(3, seq(seq(oid(o.extOid ?? "1.2.840.113635.100.8.2"), octet(o.ext)))) : new Uint8Array();
  const tbs = seq(ctx(0, int(2)), int(o.serial), alg, name("issuer"), seq(utc(o.notBefore ?? T0 - DAY), utc(o.notAfter ?? T0 + 365 * DAY)), name("subject"), await spki(o.subjectPub), exts);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: o.issuer.curve === "P-384" ? "SHA-384" : "SHA-256" }, o.issuer.privateKey, tbs));
  return seq(tbs, alg, bits(rawToDer(raw)));
}

// ---- CBOR を書く小さな道具（試験用） ----
const head = (major: number, n: number) => (n < 24 ? Uint8Array.of((major << 5) | n) : n < 256 ? Uint8Array.of((major << 5) | 24, n) : Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff));
type C = string | Uint8Array | C[] | number | { raw: Uint8Array };
const cbor = (v: C): Uint8Array => {
  if (typeof v === "number") return head(0, v);
  if (typeof v === "string") { const b = new TextEncoder().encode(v); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (!Array.isArray(v)) return v.raw;
  return cat(head(4, v.length), ...v.map(cbor));
};
const cmap = (entries: [string, C][]): { raw: Uint8Array } => ({ raw: cat(head(5, entries.length), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)])) });

const sha = async (d: Uint8Array | string) => Uint8Array.from((await sha256Hex(d)).match(/../g)!, (h) => parseInt(h, 16));
const APP = "ABCDE12345.jp.pleats.app";
const PROD = cat(new TextEncoder().encode("appattest"), new Uint8Array(7));
const DEV = new TextEncoder().encode("appattestdevelop");

type Opt = { appId?: string; signCount?: number; aaguid?: Uint8Array; credId?: Uint8Array; nonce?: Uint8Array; cdh?: Uint8Array; fmt?: string; notAfter?: number; mid?: Kp };

/** attestation object を作る（根 P-384 → 中間 P-256 → 葉 P-256「アプリの鍵」） */
async function attest(o: Opt = {}) {
  const root = await ec("P-384"), mid = o.mid ?? (await ec("P-256")), appKey = await ec("P-256"), device = await createWebDeviceKey();
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", appKey.publicKey));
  const keyId = await sha(pubRaw);
  const cdh = o.cdh ?? (await appAttestClientDataHash({ co: "CO_A", by: "emp-1", use: "approve", pub: device.pub }));
  const credId = o.credId ?? keyId;
  const count = o.signCount ?? 0;
  const authData = cat(await sha(o.appId ?? APP), Uint8Array.of(0x41, count >>> 24, (count >> 16) & 0xff, (count >> 8) & 0xff, count & 0xff), o.aaguid ?? PROD, Uint8Array.of(credId.length >> 8, credId.length & 0xff), credId, cmap([["1", 2]]).raw);
  const nonce = o.nonce ?? (await sha(cat(authData, await appAttestClientDataHash({ co: "CO_A", by: "emp-1", use: "approve", pub: device.pub }))));
  const leaf = await cert({ serial: 3, subjectPub: appKey.publicKey, issuer: mid, ext: seq(ctx(1, octet(nonce))), ...(o.notAfter ? { notAfter: o.notAfter } : {}) });
  const inter = await cert({ serial: 2, subjectPub: mid.publicKey, issuer: root });
  const top = await cert({ serial: 1, subjectPub: root.publicKey, issuer: root });
  const obj = cmap([["fmt", o.fmt ?? "apple-appattest"], ["attStmt", cmap([["x5c", [leaf, inter]], ["receipt", new Uint8Array(40).fill(1)]])], ["authData", authData]]);
  return {
    device,
    cdh: await appAttestClientDataHash({ co: "CO_A", by: "emp-1", use: "approve", pub: device.pub }),
    attestation: toBase64Url(obj.raw),
    keyId: toBase64Url(keyId),
    root: toBase64Url(top),
    rootSpkiSha256: await sha256Hex(await spki(root.publicKey)),
  };
}

const base = (a: Awaited<ReturnType<typeof attest>>) => ({ attestation: a.attestation, keyId: a.keyId, clientDataHash: a.cdh, appIds: [APP], now: T0, root: a.root, rootSpkiSha256: a.rootSpkiSha256 });
const code = async (o: Parameters<typeof verifyAppleAppAttest>[0]) => { const r = await verifyAppleAppAttest(o); return r.ok ? "ok" : r.code; };

test("Apple の根：持っている証明書を読め、公開鍵の SHA-256 が固定の値と同じ（2045-03-15 まで）", async () => {
  const root = parseCert(fromBase64Url(APPLE_APP_ATTEST_ROOT));
  assert.equal(await sha256Hex(root.spki), APPLE_APP_ATTEST_ROOT_SPKI_SHA256);
  assert.equal(root.spkiCurve, "1.3.132.0.34", "P-384");
  assert.equal(new Date(root.notAfter).toISOString(), "2045-03-15T00:00:00.000Z");
});

test("正しい証明：本番の証明は通り、アプリ・鍵の ID・受領書を返す", async () => {
  const a = await attest();
  const r = await verifyAppleAppAttest(base(a));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.environment, "production");
    assert.equal(r.appId, APP);
    assert.equal(r.keyId, Array.from(fromBase64Url(a.keyId), (b) => b.toString(16).padStart(2, "0")).join(""));
    assert.equal(r.receipt.length, 40);
  }
});

test("鎖：Apple の根でない・根の差し替え・署名の書き換え・有効期間の外は通さない", async () => {
  const a = await attest();
  assert.equal(await code({ ...base(a), root: undefined, rootSpkiSha256: undefined }), "APPATTEST_CHAIN", "既定は Apple の根だけ");
  assert.equal(await code({ ...base(a), rootSpkiSha256: undefined }), "APPATTEST_ROOT", "根を差し替えても、固定の値で止まる");
  const other = await attest();
  assert.equal(await code({ ...base(a), root: other.root, rootSpkiSha256: other.rootSpkiSha256 }), "APPATTEST_CHAIN");
  assert.equal(await code({ ...base(a), now: T0 + 400 * DAY }), "APPATTEST_CHAIN");
  const raw = fromBase64Url(a.attestation).slice();
  const at = raw.findIndex((_, i) => i > 200 && raw[i] === 0x30) + 40;
  raw[at] = raw[at]! ^ 1;
  assert.notEqual(await code({ ...base(a), attestation: toBase64Url(raw) }), "ok");
});

test("結び付き：別の登録の clientDataHash・nonce 違い・鍵の ID 違い・credentialId 違いは通さない", async () => {
  const a = await attest();
  const other = await appAttestClientDataHash({ co: "CO_A", by: "emp-2", use: "approve", pub: a.device.pub });
  assert.equal(await code({ ...base(a), clientDataHash: other }), "APPATTEST_NONCE", "別の本人");
  const dev = await appAttestClientDataHash({ co: "CO_A", by: "emp-1", use: "device", pub: a.device.pub });
  assert.equal(await code({ ...base(a), clientDataHash: dev }), "APPATTEST_NONCE", "別の使い道");
  assert.equal(await code(base(await attest({ nonce: new Uint8Array(32) }))), "APPATTEST_NONCE");
  assert.equal(await code({ ...base(a), keyId: toBase64Url(new Uint8Array(32).fill(3)) }), "APPATTEST_KEY");
  assert.equal(await code(base(await attest({ credId: new Uint8Array(32).fill(4) }))), "APPATTEST_KEY");
});

test("アプリと種類：許していないアプリ・使った鍵・開発用・形の違いは通さない", async () => {
  assert.equal(await code(base(await attest({ appId: "ZZZZZ99999.jp.other.app" }))), "APPATTEST_APP");
  assert.equal(await code(base(await attest({ signCount: 1 }))), "APPATTEST_BAD");
  const d = await attest({ aaguid: DEV });
  assert.equal(await code(base(d)), "APPATTEST_ENV");
  const ok = await verifyAppleAppAttest({ ...base(d), allowDevelopment: true });
  assert.equal(ok.ok && ok.environment, "development");
  assert.equal(await code(base(await attest({ aaguid: new Uint8Array(16) }))), "APPATTEST_BAD");
  assert.equal(await code(base(await attest({ fmt: "packed" }))), "APPATTEST_BAD");
  assert.equal(await code({ ...base(await attest()), attestation: "AAAA" }), "APPATTEST_BAD");
  assert.equal(await code({ ...base(await attest()), keyId: "AAAA" }), "APPATTEST_BAD");
});

test("CBOR：長さ不定・余り・同じキー・切れたものは読まない", () => {
  assert.deepEqual(decodeCbor(Uint8Array.of(0x82, 0x01, 0x20)), [1, -1]);
  assert.throws(() => decodeCbor(Uint8Array.of(0x9f, 0x01, 0xff)));
  assert.throws(() => decodeCbor(Uint8Array.of(0x01, 0x02)));
  assert.throws(() => decodeCbor(Uint8Array.of(0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02)));
  assert.throws(() => decodeCbor(Uint8Array.of(0x5a, 0xff, 0xff, 0xff, 0xff)));
  assert.throws(() => decodeCbor(Uint8Array.of(0xfb, 0, 0, 0, 0, 0, 0, 0, 0)), "浮動小数");
  let deep = Uint8Array.of(0x01);
  for (let i = 0; i < 20; i++) deep = cat(Uint8Array.of(0x81), deep);
  assert.throws(() => decodeCbor(deep), "深すぎる入れ子");
});

test("決まり（createAttestationCheck）：platform で振り分け、承認の鍵は証明を必須にする", async () => {
  const a = await attest();
  const check = createAttestationCheck({ now: () => T0, apple: { appIds: [APP], root: a.root, rootSpkiSha256: a.rootSpkiSha256 } });
  const who = { co: "CO_A", by: "emp-1" };
  const att = { platform: "apple", keyId: a.keyId, attestation: a.attestation };
  assert.deepEqual(await check({ who, pub: a.device.pub, use: "approve", att }), { ok: true });
  const r = (x: Awaited<ReturnType<typeof check>>) => (x.ok ? "ok" : x.code);
  assert.equal(r(await check({ who, pub: a.device.pub, use: "approve", att: undefined })), "ATTEST_MISSING");
  assert.equal(r(await check({ who, pub: a.device.pub, use: "device", att: undefined })), "ok", "送るための鍵は既定で証明なしでよい");
  assert.equal(r(await check({ who: { co: "CO_A", by: "emp-2" }, pub: a.device.pub, use: "approve", att })), "APPATTEST_NONCE", "別の本人");
  assert.equal(r(await check({ who, pub: (await createWebDeviceKey()).pub, use: "approve", att })), "APPATTEST_NONCE", "別の端末の鍵に付け替え");
  assert.equal(r(await check({ who, pub: a.device.pub, use: "approve", att: { platform: "android", chain: ["AAAA"] } })), "ATTEST_PLATFORM", "Android の決まりを渡していない");
  assert.equal(r(await check({ who, pub: a.device.pub, use: "approve", att: { platform: "windows" } })), "ATTEST_PLATFORM");
  assert.equal(r(await check({ who, pub: a.device.pub, use: "approve", att: { platform: "apple", keyId: 1 } })), "ATTEST_BAD");
  const strict = createAttestationCheck({ now: () => T0, require: ["device", "approve"], apple: { appIds: [APP] } });
  assert.equal(r(await strict({ who, pub: a.device.pub, use: "device", att: undefined })), "ATTEST_MISSING");
});

test("登録の入口：App Attest を添えた登録が通り、大きな証明（約 6KB）も受け取れる", async () => {
  const iss = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...((await crypto.subtle.exportKey("jwk", iss.publicKey)) as PublicJwk), kid: "k1" } as PublicJwk;
  const b64 = (o: unknown) => toBase64Url(new TextEncoder().encode(JSON.stringify(o)));
  const h = b64({ alg: "ES256", typ: "JWT", kid: "k1" }), s = T0 / 1000;
  const p = b64({ sub: "emp-1", iss: "iss", aud: "app", iat: s - 10, exp: s + 600 });
  const token = `${h}.${p}.${toBase64Url(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, iss.privateKey, new TextEncoder().encode(`${h}.${p}`))))}`;
  const keys: DeviceKey[] = [];
  const codes = new Map<string, number>();
  const store = { keys: () => keys, take: (_c: string, _b: string, hash: string, now: number) => { const u = codes.get(hash); codes.delete(hash); return u !== undefined && u > now; }, add: (_c: string, _b: string, k: DeviceKey) => void keys.push(k) };
  const a = await attest();
  const enroll = createDeviceEnrollment({
    verifier: createTokenVerifier({ issuer: "iss", audience: "app", now: () => T0, jwks: async () => ({ keys: [jwk] }) }),
    identify: (cl) => ({ co: "CO_A", by: cl.sub }),
    store,
    now: () => T0,
    attest: createAttestationCheck({ now: () => T0, apple: { appIds: [APP], root: a.root, rootSpkiSha256: a.rootSpkiSha256 } }),
  });
  const send = async (body: object) => enroll(new Request("https://hub.example/lch/v1/device", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) }));
  const c1 = await issuePairingCode(T0); codes.set(c1.hash, c1.expiresAt);
  const req = await pairingRequest(a.device, { co: "CO_A", by: "emp-1", use: "approve", code: c1.code });
  const noAtt = await send(req);
  assert.equal(((await noAtt.json()) as { reason: string }).reason, "ATTEST_MISSING");
  assert.equal(codes.size, 1, "証明が通らなければ、合言葉は使わない");
  const ok = await send({ ...req, att: { platform: "apple", keyId: a.keyId, attestation: a.attestation } });
  assert.equal(ok.status, 200, await ok.clone().text());
  assert.deepEqual(keys, [{ pub: a.device.pub, use: "approve" }]);
  // 本物の App Attest の証明は受領書を含めて 5〜6KB ほど。8KB の証明でも、大きさでは断らない
  const bigBody = JSON.stringify({ ...req, att: { platform: "apple", keyId: a.keyId, attestation: "A".repeat(8000) } });
  assert.ok(bigBody.length > 8000 && bigBody.length < 16384);
  const r = await enroll(new Request("https://hub.example/lch/v1/device", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: bigBody }));
  assert.equal(((await r.json()) as { code: string }).code, "PAIR_ATTEST", "大きさでは断らず、中身で断る");
});
