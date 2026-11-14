import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Envelope,
  type PublicJwk,
  USER_PATH,
  createReceiver,
  createTokenVerifier,
  createUserClient,
  createUserGateway,
  formatTable,
  importSealKey,
  importSigningKey,
  readBody,
  toBase64Url,
  verifyEnvelope,
} from "../src/index.ts";

const enc = new TextEncoder();
const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (o: unknown) => toBase64Url(enc.encode(JSON.stringify(o)));
const ISS = "https://auth.example/v1";
const AUD = "authenticated";
const T0 = 1_800_000_000_000; // 土台の時計（ミリ秒）
const S0 = T0 / 1000;

type Signer = { alg: string; kid?: string; sign: (data: Uint8Array) => Promise<Uint8Array> };

async function es256(kid = "k1") {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as PublicJwk;
  const signer: Signer = {
    alg: "ES256",
    kid,
    sign: async (d) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, d as BufferSource)),
  };
  return { signer, jwk: { ...jwk, kid, alg: "ES256", use: "sig" } as PublicJwk };
}

async function rs256(kid = "r1") {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as PublicJwk;
  const signer: Signer = {
    alg: "RS256",
    kid,
    sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, d as BufferSource)),
  };
  return { signer, jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, kid } as PublicJwk };
}

async function hs256Key(raw: Uint8Array) {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function mint(s: Signer, claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const h = b64({ alg: s.alg, typ: "JWT", ...(s.kid ? { kid: s.kid } : {}), ...header });
  const p = b64(claims);
  const sig = await s.sign(enc.encode(`${h}.${p}`));
  return `${h}.${p}.${toBase64Url(sig)}`;
}

const claims = (over: Record<string, unknown> = {}) => ({
  sub: "11111111-2222-3333-4444-555555555555",
  iss: ISS,
  aud: AUD,
  iat: S0 - 10,
  exp: S0 + 600,
  company: "CO_NS",
  ...over,
});

const formats = formatTable({
  record: ["record.nsc.attendance"],
  event: ["event.nsc.clockin"],
  key: ["key.nsc.token"],
});

async function setup(extra: { identify?: (c: Record<string, unknown>) => { co: string; by: string } | undefined } = {}) {
  let t = T0;
  const now = () => t;
  const { signer, jwk } = await es256();
  let fetches = 0;
  const verifier = createTokenVerifier({
    issuer: ISS,
    audience: AUD,
    now,
    jwks: async () => {
      fetches++;
      return { keys: [jwk] };
    },
  });
  const signingKey = await importSigningKey(rnd(32));
  const sealKey = await importSealKey(rnd(32));
  const got: { env: Envelope; who: { co: string; by: string } }[] = [];
  const gateway = createUserGateway({
    verifier,
    identify: extra.identify ?? ((c) => (typeof c.company === "string" ? { co: c.company, by: c.sub } : undefined)),
    formats,
    now,
    signingKey: (co) => (co === "CO_NS" ? signingKey : undefined),
    sealKey: (co) => (co === "CO_NS" ? sealKey : undefined),
    onEnvelope: (env, who) => {
      got.push({ env, who });
      return env.f === "record.nsc.attendance" ? { saved: true } : undefined;
    },
  });
  return { gateway, signer, signingKey, sealKey, got, now, advance: (ms: number) => (t += ms), fetches: () => fetches };
}

const req = (body: unknown, token?: string, init: { type?: string; path?: string } = {}) =>
  new Request(`https://hub.example${init.path ?? USER_PATH}`, {
    method: "POST",
    headers: { "content-type": init.type ?? "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

const draft = (over: Record<string, unknown> = {}) => ({ v: 1, l: "event", f: "event.nsc.clockin", id: "clk-00000001", b: { kind: "in" }, ...over });

test("利用者の口：会社と送り手は、下書きではなくトークンから決まる", async () => {
  const s = await setup();
  const res = await s.gateway(req(draft(), await mint(s.signer, claims())));
  assert.equal(res.status, 202);
  const body = (await res.json()) as { ok: boolean; id: string; at: number };
  assert.equal(body.ok, true);
  assert.equal(body.id, "clk-00000001");
  assert.equal(body.at, T0);
  assert.equal(s.got.length, 1);
  assert.equal(s.got[0]!.env.co, "CO_NS");
  assert.equal(s.got[0]!.env.by, "11111111-2222-3333-4444-555555555555");
  assert.equal(s.got[0]!.env.at, T0);
});

test("利用者の口：会社・送り手・時刻・署名・暗号方式を下書きに書けば拒否する（黙って書き換えない）", async () => {
  const s = await setup();
  const token = await mint(s.signer, claims());
  for (const k of ["co", "by", "at", "sig", "e"]) {
    const res = await s.gateway(req(draft({ id: `stamp-${k}-0001`, [k]: k === "at" ? 1 : "X_X" }), token));
    assert.equal(res.status, 400, k);
    const b = (await res.json()) as { code: string; field: string };
    assert.equal(b.code, "STAMPED_FIELD");
    assert.equal(b.field, k);
  }
  assert.equal(s.got.length, 0);
});

test("利用者の口：トークンが無い・壊れている・署名違い・期限切れは、本文を読む前に 401", async () => {
  const s = await setup();
  const other = await es256("k1"); // 同じ kid の偽の鍵
  const cases: [string | undefined, string][] = [
    [undefined, "TOKEN_MISSING"],
    ["abc", "TOKEN_INVALID"],
    [await mint(other.signer, claims()), "TOKEN_INVALID"],
    [await mint(s.signer, claims({ exp: S0 - 120, iat: S0 - 700 })), "TOKEN_EXPIRED"],
  ];
  for (const [token, code] of cases) {
    // 本文は JSON ですらない。本人確認が先なので、BAD_JSON にはならない
    const res = await s.gateway(req("{", token));
    assert.equal(res.status, 401);
    assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer error=/);
    assert.equal(((await res.json()) as { code: string }).code, code);
  }
});

test("トークン：発行元・宛先・開始前・長すぎる期間・本人なしを拒否する", async () => {
  const s = await setup();
  const bad = [
    claims({ iss: "https://evil.example" }),
    claims({ aud: "someone-else" }),
    claims({ nbf: S0 + 600 }),
    claims({ iat: S0 - 10, exp: S0 + 86400 }),
    claims({ sub: "" }),
    claims({ exp: "never" }),
  ];
  for (const c of bad) {
    const res = await s.gateway(req(draft(), await mint(s.signer, c)));
    assert.equal(res.status, 401, JSON.stringify(c));
  }
  // 宛先は配列でもよい
  const ok = await s.gateway(req(draft(), await mint(s.signer, claims({ aud: ["x", AUD] }))));
  assert.equal(ok.status, 202);
});

test("トークン：none と、方式の取り違え（公開鍵を共通鍵として使わせる）を拒否する", async () => {
  const s = await setup();
  const h = b64({ alg: "none", typ: "JWT" });
  const none = `${h}.${b64(claims())}.${toBase64Url(rnd(32))}`;
  assert.equal((await s.gateway(req(draft(), none))).status, 401);
  // HS256 は共通鍵を渡していない限り受け付けない
  const hsSigner: Signer = { alg: "HS256", kid: "k1", sign: async (d) => new Uint8Array(await crypto.subtle.sign("HMAC", await hs256Key(rnd(32)), d as BufferSource)) };
  assert.equal((await s.gateway(req(draft(), await mint(hsSigner, claims())))).status, 401);
  // ES256 の鍵の番号で RS256 を名乗っても使えない
  const rs = await rs256("k1");
  assert.equal((await s.gateway(req(draft(), await mint(rs.signer, claims())))).status, 401);
});

test("トークン：知らない鍵の番号は一覧を取り直すが、間隔を空ける（偽の番号で叩かせない）", async () => {
  const s = await setup();
  await s.gateway(req(draft(), await mint(s.signer, claims())));
  assert.equal(s.fetches(), 1);
  const ghost: Signer = { ...s.signer, kid: "ghost" };
  s.advance(61_000);
  for (let i = 0; i < 5; i++) {
    const res = await s.gateway(req(draft({ id: `ghost-${i}-0000` }), await mint(ghost, claims())));
    assert.equal(res.status, 401);
  }
  assert.equal(s.fetches(), 2); // 間隔が空いた最初の 1 回だけ取り直す
  s.advance(61_000);
  await s.gateway(req(draft({ id: "ghost-9-0000" }), await mint(ghost, claims({ exp: S0 + 700 }))));
  assert.equal(s.fetches(), 3);
});

test("トークン：RS256（公開鍵の一覧）と HS256（共通鍵）も使える", async () => {
  const rs = await rs256();
  const v1 = createTokenVerifier({ issuer: ISS, audience: AUD, now: () => T0, jwks: async () => ({ keys: [rs.jwk] }) });
  assert.equal((await v1.verify(await mint(rs.signer, claims()))).ok, true);

  const raw = rnd(32);
  const hs: Signer = { alg: "HS256", sign: async (d) => new Uint8Array(await crypto.subtle.sign("HMAC", await hs256Key(raw), d as BufferSource)) };
  const v2 = createTokenVerifier({ issuer: ISS, audience: AUD, now: () => T0, hsKey: await hs256Key(raw) });
  const r = await v2.verify(await mint(hs, claims()));
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.claims.company, "CO_NS");
  const wrong: Signer = { alg: "HS256", sign: async (d) => new Uint8Array(await crypto.subtle.sign("HMAC", await hs256Key(rnd(32)), d as BufferSource)) };
  assert.equal((await v2.verify(await mint(wrong, claims()))).ok, false);
});

test("利用者の口：会社が決まらない利用者は 403。鍵レーンは利用者から使えない", async () => {
  const s = await setup();
  const res = await s.gateway(req(draft(), await mint(s.signer, claims({ company: undefined }))));
  assert.equal(res.status, 403);
  assert.equal(((await res.json()) as { code: string }).code, "USER_FORBIDDEN");

  const token = await mint(s.signer, claims());
  const k = await s.gateway(req(draft({ l: "key", f: "key.nsc.token", ref: "ut:1", b: undefined, c: 3 }), token));
  assert.equal(k.status, 403);
  assert.equal(((await k.json()) as { code: string }).code, "LANE_NOT_ALLOWED");
});

test("利用者の口：許可表に無い形式・番号の無い下書き・規格に無い項目を拒否する", async () => {
  const s = await setup();
  const token = await mint(s.signer, claims());
  const a = await s.gateway(req(draft({ f: "event.nsc.other" }), token));
  assert.equal(a.status, 403);
  const { id: _id, ...noId } = draft();
  const b = await s.gateway(req(noId, token));
  assert.equal(b.status, 400);
  assert.equal(((await b.json()) as { field: string }).field, "id");
  const c = await s.gateway(req(draft({ __proto__x: 1 }), token));
  assert.equal(c.status, 400);
  assert.equal(s.got.length, 0);
});

test("利用者の口：同じ番号の送り直しは 409（二重に実行しない）。他人の同じ番号は邪魔されない", async () => {
  const s = await setup();
  const t1 = await mint(s.signer, claims());
  assert.equal((await s.gateway(req(draft(), t1))).status, 202);
  const again = await s.gateway(req(draft(), t1));
  assert.equal(again.status, 409);
  const t2 = await mint(s.signer, claims({ sub: "someone-else" }));
  assert.equal((await s.gateway(req(draft(), t2))).status, 202);
  assert.equal(s.got.length, 2);
});

test("利用者の口：機密以上は土台が署名し、極秘の本文は土台が暗号化する。返事は開いた形で返す", async () => {
  const s = await setup();
  const token = await mint(s.signer, claims());
  const res = await s.gateway(req(draft({ l: "record", f: "record.nsc.attendance", id: "att-00000001", c: 3, b: { minutes: 480 } }), token));
  assert.equal(res.status, 200);
  assert.deepEqual(((await res.json()) as { b: unknown }).b, { saved: true });
  const env = s.got[0]!.env;
  assert.equal(env.e, "A256GCM");
  assert.equal(typeof env.b, "string");
  assert.equal(await verifyEnvelope(env, s.signingKey), true);
  assert.deepEqual(await readBody(env, s.sealKey), { minutes: 480 });
  // 作った封筒は、封筒の受け口にもそのまま通る
  const receiver = createReceiver({ formats, now: s.now, signingKey: () => s.signingKey });
  assert.equal((await receiver.receive(JSON.stringify(env))).ok, true);
});

test("利用者の口：署名用の鍵が無い会社は、機密以上を受け付けない（署名なしで流さない）", async () => {
  const s = await setup({ identify: (c) => ({ co: "CO_OTHER", by: String(c.sub) }) });
  const res = await s.gateway(req(draft({ c: 2 }), await mint(s.signer, claims())));
  assert.equal(res.status, 500);
  assert.equal(((await res.json()) as { code: string }).code, "SERVER_KEY");
  assert.equal(s.got.length, 0);
});

test("利用者の口：拒否の応答に、トークンも本文も返さない", async () => {
  const s = await setup();
  const token = await mint(s.signer, claims());
  const res = await s.gateway(req(draft({ f: "event.nsc.secret", b: { secret: "社外秘" } }), token));
  const text = await res.text();
  assert.equal(text.includes(token), false);
  assert.equal(text.includes("社外秘"), false);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("利用者の送り口：期限切れは一度だけトークンを取り直し、同じ番号で送り直す", async () => {
  const s = await setup();
  const old = await mint(s.signer, claims({ exp: S0 - 120, iat: S0 - 700 }));
  const fresh = await mint(s.signer, claims());
  const asked: boolean[] = [];
  const client = createUserClient({
    url: "https://hub.example/lch/v1/user",
    now: s.now,
    sleep: async () => {},
    token: async (refresh) => {
      asked.push(refresh);
      return refresh ? fresh : old;
    },
    fetch: (r) => s.gateway(r),
  });
  const r = await client.send({ l: "record", f: "record.nsc.attendance", b: { minutes: 1 } });
  assert.equal(r.ok, true);
  if (r.ok) assert.deepEqual(r.b, { saved: true });
  assert.deepEqual(asked, [false, true]);
  // 送り直し（同じ番号）は、届いたものとして扱う
  const id = s.got[0]!.env.id;
  const r2 = await client.send({ id, l: "record", f: "record.nsc.attendance", b: { minutes: 1 } });
  assert.equal(r2.ok, true);
  if (r2.ok) assert.equal(r2.duplicate, true);
  assert.equal(s.got.length, 1);
});

test("利用者の送り口：https 以外には送らない", () => {
  assert.throws(() => createUserClient({ url: "http://hub.example/x", now: () => 0, token: async () => "" }));
});
