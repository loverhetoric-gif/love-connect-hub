// 端末の鍵（規格書 第21章）。WARPHOLE. の取り出せない鍵・ペアリング・Face ID の承認を、利用者の口に取り入れたもの
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type DeviceKey,
  type Envelope,
  type PairingStore,
  type PublicJwk,
  DEVICE_HEADER,
  createDeviceEnrollment,
  createDeviceVerifier,
  createSender,
  createTokenVerifier,
  createUserClient,
  createUserGateway,
  createWebDeviceKey,
  deviceProofHeader,
  formatTable,
  importSigningKey,
  issuePairingCode,
  pairingRequest,
  sha256Hex,
  signApproval,
  toBase64Url,
  verifyApproval,
} from "../src/index.ts";

const enc = new TextEncoder();
const b64 = (o: unknown) => toBase64Url(enc.encode(JSON.stringify(o)));
const T0 = 1_800_000_000_000;
const URL_USER = "https://hub.example/lch/v1/user";
const URL_DEVICE = "https://hub.example/lch/v1/device";

async function issuer() {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...((await crypto.subtle.exportKey("jwk", kp.publicKey)) as PublicJwk), kid: "k1" } as PublicJwk;
  const mint = async (sub: string) => {
    const h = b64({ alg: "ES256", typ: "JWT", kid: "k1" });
    const s = T0 / 1000;
    const p = b64({ sub, iss: "iss", aud: "app", iat: s - 10, exp: s + 600 });
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, enc.encode(`${h}.${p}`)));
    return `${h}.${p}.${toBase64Url(sig)}`;
  };
  return { mint, verifier: createTokenVerifier({ issuer: "iss", audience: "app", now: () => T0, jwks: async () => ({ keys: [jwk] }) }) };
}

// 端末の一覧と合言葉の置き場所（試験用。実際はデータベース・Durable Objects など）
function memoryStore() {
  const keys = new Map<string, DeviceKey[]>();
  const codes = new Map<string, number>();
  const store: PairingStore & { putCode(co: string, by: string, hash: string, until: number): void } = {
    keys: (co, by) => keys.get(`${co}/${by}`) ?? [],
    take(co, by, hash, now) {
      const k = `${co}/${by}/${hash}`, until = codes.get(k);
      codes.delete(k);
      return until !== undefined && until > now;
    },
    add(co, by, key) {
      keys.set(`${co}/${by}`, [...(keys.get(`${co}/${by}`) ?? []), key]);
    },
    putCode(co, by, hash, until) {
      codes.set(`${co}/${by}/${hash}`, until);
    },
  };
  return store;
}

async function setup() {
  const iss = await issuer();
  const store = memoryStore();
  let now = T0;
  const clock = () => now;
  const received: Envelope[] = [];
  const identify = (c: { sub: string }) => ({ co: "CO_A", by: c.sub });
  const gateway = createUserGateway({
    verifier: iss.verifier,
    identify,
    formats: formatTable({ record: ["record.attendance.clockin"] }),
    now: clock,
    signingKey: async () => importSigningKey(new Uint8Array(32).fill(7)),
    onEnvelope: (env) => (received.push(env), undefined),
    device: createDeviceVerifier({ directory: store, now: clock }),
  });
  const enroll = createDeviceEnrollment({ verifier: iss.verifier, identify, store, now: clock });
  const token = await iss.mint("emp-1");
  return { iss, store, gateway, enroll, token, received, setNow: (t: number) => (now = t) };
}

const post = (url: string, token: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(url, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...headers }, body: JSON.stringify(body) });

async function enrolled(s: Awaited<ReturnType<typeof setup>>, use: "device" | "approve" = "device") {
  const key = await createWebDeviceKey();
  const c = await issuePairingCode(T0);
  s.store.putCode("CO_A", "emp-1", c.hash, c.expiresAt);
  const r = await s.enroll(post(URL_DEVICE, s.token, await pairingRequest(key, { co: "CO_A", by: "emp-1", use, code: c.code })));
  assert.equal(r.status, 200, await r.clone().text());
  return key;
}

test("端末の鍵：秘密の部分は取り出せない。公開鍵は 65 バイトの非圧縮形式", async () => {
  const key = await createWebDeviceKey();
  assert.equal(key.pair.privateKey.extractable, false);
  assert.equal(key.pub.length, 87);
  await assert.rejects(crypto.subtle.exportKey("jwk", key.pair.privateKey));
  const ext = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  await assert.rejects(createWebDeviceKey(ext), /取り出せない/);
});

test("登録：トークン ＋ 使い捨ての合言葉 ＋ 鍵を持っている証明がそろったときだけ。合言葉は 1 回だけ・5 分で失効", async () => {
  const s = await setup();
  const key = await createWebDeviceKey();
  const c = await issuePairingCode(T0);
  assert.equal(c.hash, await sha256Hex(c.code));
  assert.equal(c.expiresAt, T0 + 300_000);
  s.store.putCode("CO_A", "emp-1", c.hash, c.expiresAt);
  const body = await pairingRequest(key, { co: "CO_A", by: "emp-1", use: "device", code: c.code });
  // トークンが無い
  assert.equal((await s.enroll(new Request(URL_DEVICE, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }))).status, 401);
  // 別の鍵の署名（鍵を持っていない）→ 合言葉は使われない
  const other = await createWebDeviceKey();
  const forged = { ...body, pub: other.pub };
  const f = await s.enroll(post(URL_DEVICE, s.token, forged));
  assert.equal(f.status, 401);
  assert.equal(((await f.json()) as { code: string }).code, "PAIR_BAD_PROOF");
  // 正しい登録
  const ok = await s.enroll(post(URL_DEVICE, s.token, body));
  assert.equal(ok.status, 200);
  assert.deepEqual(await s.store.keys("CO_A", "emp-1"), [{ pub: key.pub, use: "device" }]);
  // 同じ合言葉の 2 回目は通らない
  const again = await s.enroll(post(URL_DEVICE, s.token, await pairingRequest(other, { co: "CO_A", by: "emp-1", use: "device", code: c.code })));
  assert.equal(((await again.json()) as { code: string }).code, "PAIR_CODE");
  // 失効した合言葉
  const old = await issuePairingCode(T0 - 600_000);
  s.store.putCode("CO_A", "emp-1", old.hash, old.expiresAt);
  const exp = await s.enroll(post(URL_DEVICE, s.token, await pairingRequest(other, { co: "CO_A", by: "emp-1", use: "device", code: old.code })));
  assert.equal(((await exp.json()) as { code: string }).code, "PAIR_CODE");
  // 別の人の名前で署名したもの（会社・本人はトークンから決まる）
  const c2 = await issuePairingCode(T0);
  s.store.putCode("CO_A", "emp-1", c2.hash, c2.expiresAt);
  const wrongWho = await s.enroll(post(URL_DEVICE, s.token, await pairingRequest(other, { co: "CO_A", by: "emp-2", use: "device", code: c2.code })));
  assert.equal(((await wrongWho.json()) as { code: string }).code, "PAIR_BAD_PROOF");
  // 余計な項目・形の違い
  const bad = await s.enroll(post(URL_DEVICE, s.token, { ...body, extra: 1 }));
  assert.equal(((await bad.json()) as { code: string }).code, "PAIR_BAD_REQUEST");
});

test("送るたびの証明：登録した端末の鍵が無ければ、正しいトークンでも送れない", async () => {
  const s = await setup();
  const draft = { v: 1, l: "record", f: "record.attendance.clockin", id: "draft-0001", b: { kind: "in" } };
  // 証明なし（トークンだけ盗まれた状態）
  const none = await s.gateway(post(URL_USER, s.token, draft));
  assert.equal(none.status, 401);
  assert.equal(((await none.json()) as { code: string }).code, "DEVICE_MISSING");
  // 登録していない端末
  const stranger = await createWebDeviceKey();
  const body = JSON.stringify(draft);
  const h1 = await deviceProofHeader(stranger, { method: "POST", path: "/lch/v1/user", token: s.token, body, now: T0 });
  const r1 = await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: h1 }));
  assert.equal(r1.status, 403);
  assert.equal(((await r1.json()) as { code: string }).code, "DEVICE_UNKNOWN");
  // 登録した端末
  const key = await enrolled(s);
  const h2 = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/user", token: s.token, body, now: T0 });
  const r2 = await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: h2 }));
  assert.equal(r2.status, 202, await r2.clone().text());
  assert.equal(s.received.length, 1);
  assert.equal(s.received[0]!.by, "emp-1");
  // 同じ証明の使い回し（番号は 5 分覚える）
  const r3 = await s.gateway(post(URL_USER, s.token, { ...draft, id: "draft-0002" }, { [DEVICE_HEADER]: h2 }));
  assert.equal(((await r3.json()) as { code: string }).code, "DEVICE_BAD_PROOF", "本文が違うので署名が合わない");
  const r4 = await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: h2 }));
  assert.equal(((await r4.json()) as { code: string }).code, "DEVICE_REPLAY");
});

test("送るたびの証明：トークン・本文・入口に結び付き、時計のずれは前後 2 分まで", async () => {
  const s = await setup();
  const key = await enrolled(s);
  const draft = { v: 1, l: "record", f: "record.attendance.clockin", id: "draft-0003", b: { kind: "in" } };
  const body = JSON.stringify(draft);
  // 別のトークンに付け替え
  const token2 = await s.iss.mint("emp-1");
  const h = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/user", token: s.token, body, now: T0 });
  assert.notEqual(token2, s.token);
  const swapped = await s.gateway(post(URL_USER, token2, draft, { [DEVICE_HEADER]: h }));
  assert.equal(((await swapped.json()) as { code: string }).code, "DEVICE_BAD_PROOF");
  // 別の入口のための証明
  const hp = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/other", token: s.token, body, now: T0 });
  assert.equal(((await (await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: hp }))).json()) as { code: string }).code, "DEVICE_BAD_PROOF");
  // 時計のずれ
  const late = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/user", token: s.token, body, now: T0 - 121_000 });
  assert.equal(((await (await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: late }))).json()) as { code: string }).code, "DEVICE_CLOCK");
  const ok = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/user", token: s.token, body, now: T0 - 119_000 });
  assert.equal((await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: ok }))).status, 202);
  // 形の違い
  for (const bad of ["v2.x", "v1.a.b.c.d", `v1.${key.pub}.abc.${"A".repeat(22)}.${"A".repeat(86)}`]) {
    assert.equal(((await (await s.gateway(post(URL_USER, s.token, draft, { [DEVICE_HEADER]: bad }))).json()) as { code: string }).code, "DEVICE_BAD_PROOF", bad);
  }
  // 承認の鍵は、送るたびの証明には使えない
  const ap = await enrolled(s, "approve");
  const ha = await deviceProofHeader(ap, { method: "POST", path: "/lch/v1/user", token: s.token, body: JSON.stringify({ ...draft, id: "draft-0004" }), now: T0 });
  assert.equal(((await (await s.gateway(post(URL_USER, s.token, { ...draft, id: "draft-0004" }, { [DEVICE_HEADER]: ha }))).json()) as { code: string }).code, "DEVICE_UNKNOWN");
});

test("送り口：端末の鍵を渡すと、送り直しのたびに新しい証明を付ける（下書きの番号は同じ）", async () => {
  const s = await setup();
  const key = await enrolled(s);
  const seen: string[] = [];
  let first = true;
  const client = createUserClient({
    url: URL_USER,
    token: async () => s.token,
    device: key,
    now: () => T0,
    sleep: async () => {},
    random: () => 0.5,
    fetch: async (req) => {
      seen.push(req.headers.get(DEVICE_HEADER) ?? "");
      if (first) {
        first = false;
        return new Response("{}", { status: 503 });
      }
      return s.gateway(req);
    },
  });
  const r = await client.send({ l: "record", f: "record.attendance.clockin", b: { kind: "in" } });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1], "番号が変わる");
  assert.equal(s.received.length, 1);
});

test("承認：本人の承認の鍵で、この封筒の中身に署名したときだけ通る。1 文字でも変えると通らない", async () => {
  const s = await setup();
  const ap = await enrolled(s, "approve");
  const dev = await enrolled(s, "device");
  const sender = createSender({ co: "CO_A", by: "ai-agent", now: () => T0, signingKey: await importSigningKey(new Uint8Array(32).fill(7)) });
  const env = await sender.make("record", "record.attendance.clockin", { c: 2, ap: true, b: { kind: "in" } });
  const approval = await signApproval(ap, env, T0);
  const who = { co: "CO_A", by: "emp-1" };
  assert.deepEqual(await verifyApproval({ env, approval, approver: who, directory: s.store, now: T0 }), { ok: true });
  // 中身を変えた封筒
  const changed = { ...env, b: { kind: "out" } };
  assert.equal((await verifyApproval({ env: changed, approval, approver: who, directory: s.store, now: T0 })).ok, false);
  // 送るための鍵では承認できない
  const byDevice = await signApproval(dev, env, T0);
  assert.equal(((await verifyApproval({ env, approval: byDevice, approver: who, directory: s.store, now: T0 })) as { code: string }).code, "APPROVAL_UNKNOWN");
  // 別の人・別の会社
  assert.equal((await verifyApproval({ env, approval, approver: { co: "CO_A", by: "emp-2" }, directory: s.store, now: T0 })).ok, false);
  assert.equal((await verifyApproval({ env, approval, approver: { co: "CO_B", by: "emp-1" }, directory: s.store, now: T0 })).ok, false);
  // 古い承認
  assert.equal(((await verifyApproval({ env, approval, approver: who, directory: s.store, now: T0 + 301_000 })) as { code: string }).code, "APPROVAL_CLOCK");
});
