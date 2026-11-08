import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Envelope,
  canonicalJson,
  checkEnvelope,
  createDedupe,
  fromBase64Url,
  importSealKey,
  importSigningKey,
  matchesBody,
  openBodyText,
  sealBody,
  sha256Hex,
  signEnvelope,
  toBase64Url,
  verifyEnvelope,
} from "../src/index.ts";

const rnd = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
};

const env: Envelope = { v: 1, l: "api", f: "api.freee.deals", id: "msg_0001", co: "nsc", by: "u1", at: 1000, c: 2, b: { z: 1, a: [1, { y: 2, x: 1 }] } };

test("base64url は往復で一致し、不正な文字を拒否する", () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33, 70000]) {
    const b = rnd(n);
    assert.deepEqual(fromBase64Url(toBase64Url(b)), b);
  }
  assert.throws(() => fromBase64Url("a+b/"));
});

test("決まった並びの JSON：項目の順番に左右されない", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
  assert.throws(() => canonicalJson(() => 1));
});

test("署名：付けて検査を通り、どこを変えても失敗する", async () => {
  const key = await importSigningKey(rnd(32));
  const signed = await signEnvelope(env, key);
  assert.equal(env.sig, undefined, "元の封筒は書き換えない");
  assert.ok(checkEnvelope(signed).ok);
  assert.equal(await verifyEnvelope(signed, key), true);
  assert.equal(await verifyEnvelope({ ...signed, by: "u2" }, key), false);
  assert.equal(await verifyEnvelope({ ...signed, b: { z: 2, a: [] } }, key), false);
  assert.equal(await verifyEnvelope({ ...signed, c: 3 }, key), false);
  assert.equal(await verifyEnvelope({ ...signed, sig: undefined }, key), false);
  assert.equal(await verifyEnvelope({ ...signed, sig: "!!" }, key), false);
  const other = await importSigningKey(rnd(32));
  assert.equal(await verifyEnvelope(signed, other), false);
  // 項目の順番が変わっても通る
  const reordered = JSON.parse(JSON.stringify({ sig: signed.sig, b: { a: [1, { x: 1, y: 2 }], z: 1 }, at: 1000, by: "u1", co: "nsc", id: "msg_0001", f: "api.freee.deals", l: "api", v: 1, c: 2 }));
  assert.equal(await verifyEnvelope(reordered, key), true);
});

test("署名用の鍵が短すぎるときは拒否", () => {
  assert.throws(() => importSigningKey(rnd(16)));
});

test("ハッシュ：既知の値と一致し、本文の照合ができる", async () => {
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const data = new TextEncoder().encode("hello");
  const h = await sha256Hex(data);
  assert.equal(await matchesBody({ len: 5, h }, data), true);
  assert.equal(await matchesBody({ len: 6, h }, data), false);
  assert.equal(await matchesBody({ len: 5, h: "0".repeat(64) }, data), false);
  assert.equal(await matchesBody({ len: 5 }, data), false);
});

test("暗号化：開けるのは同じ鍵・同じ封筒だけ", async () => {
  const key = await importSealKey(rnd(32));
  const b = await sealBody(env, "極秘の本文", key);
  const sealed = { ...env, c: 3 as const, e: "A256GCM" as const, b };
  assert.equal(await openBodyText(sealed, key), "極秘の本文");
  // 同じ文でも毎回ちがう暗号文になる
  assert.notEqual(await sealBody(env, "極秘の本文", key), b);
  // 別の封筒・別の会社・別の鍵・改ざんは失敗
  await assert.rejects(openBodyText({ ...sealed, id: "msg_0002" }, key));
  await assert.rejects(openBodyText({ ...sealed, co: "other" }, key));
  await assert.rejects(openBodyText(sealed, await importSealKey(rnd(32))));
  const raw = fromBase64Url(b);
  raw[raw.length - 1]! ^= 1;
  await assert.rejects(openBodyText({ ...sealed, b: toBase64Url(raw) }, key));
  await assert.rejects(openBodyText({ ...sealed, b: "AAAA" }, key));
  assert.throws(() => importSealKey(rnd(16)));
});

test("重複防止：時間内は一度だけ、会社が違えば別物、上限で古いものから忘れる", () => {
  const d = createDedupe({ windowMs: 100, capacity: 3 });
  assert.equal(d.first("a", "m1", 0), true);
  assert.equal(d.first("a", "m1", 50), false);
  assert.equal(d.first("b", "m1", 50), true);
  assert.equal(d.first("a", "m1", 100), true, "時間を過ぎたら通す");
  d.first("a", "m2", 101);
  d.first("a", "m3", 102);
  d.first("a", "m4", 103);
  assert.ok(d.size <= 3);
  assert.throws(() => createDedupe({ windowMs: 0, capacity: 1 }));
});
