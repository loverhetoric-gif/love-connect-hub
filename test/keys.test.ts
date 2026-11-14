import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type KeyBroker,
  callWithKey,
  createCompanyKeys,
  createReceiver,
  createSender,
  formatTable,
  parseKeyRef,
  readBody,
  toBase64Url,
} from "../src/index.ts";

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const formats = formatTable({ record: ["record.attendance.clockin"] });

test("鍵の参照：env:大文字の名前 と ut:カテゴリ だけを受け付ける", () => {
  assert.deepEqual(parseKeyRef("env:LCH_SIGNING_KEY"), { store: "env", name: "LCH_SIGNING_KEY" });
  assert.deepEqual(parseKeyRef("ut:nsc-navitime"), { store: "ut", name: "nsc-navitime" });
  for (const bad of ["LCH_KEY", "env:lower", "ut:UPPER", "vault:x", "env:", "ut:", "env:A", "https://x"]) {
    assert.throws(() => parseKeyRef(bad), /鍵の参照/, bad);
  }
});

test("会社の鍵：署名用・暗号化用は env: だけ（代理実行の参照は使えない）", () => {
  assert.throws(() => createCompanyKeys({ read: () => undefined, signing: { CO_NS: ["ut:nsc-sign"] } }), /env:/);
  assert.throws(() => createCompanyKeys({ read: () => undefined, signing: {}, seal: { CO_NS: ["ut:x"] } }), /env:/);
});

test("会社の鍵：入れ替えの途中は、古い鍵の封筒も確かめられ、新しい鍵で署名する", async () => {
  const secrets: Record<string, string> = { SIGN_OLD: toBase64Url(rnd(32)), SIGN_NEW: toBase64Url(rnd(32)) };
  const read = (n: string) => secrets[n];
  const now = () => 1_000_000;

  // 入れ替え前：古い鍵だけ
  const before = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN_OLD"] } });
  const oldEnv = await createSender({ co: "CO_NS", by: "u1", now, signingKey: (await before.signingKey("CO_NS"))! }).make("record", "record.attendance.clockin", { c: 2, b: { a: 1 } });

  // 入れ替え中：新しい鍵を先頭に、古い鍵を後ろに
  const during = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN_NEW", "env:SIGN_OLD"] } });
  const newEnv = await createSender({ co: "CO_NS", by: "u1", now, signingKey: (await during.signingKey("CO_NS"))! }).make("record", "record.attendance.clockin", { c: 2, b: { a: 2 } });
  const rx = createReceiver({ formats, now, signingKey: (co) => during.verifyKeys(co) });
  assert.equal((await rx.receive(JSON.stringify(oldEnv))).ok, true);
  assert.equal((await rx.receive(JSON.stringify(newEnv))).ok, true);

  // 入れ替え後：古い鍵を外すと、古い鍵の封筒は通らない
  const after = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN_NEW"] } });
  const rx2 = createReceiver({ formats, now, signingKey: (co) => after.verifyKeys(co) });
  const r = await rx2.receive(JSON.stringify({ ...oldEnv, id: oldEnv.id }));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.code, "BAD_SIGNATURE");
});

test("会社の鍵：秘密の値が変わったら読み直す。無い会社・無い値は undefined", async () => {
  const secrets: Record<string, string> = { SIGN: toBase64Url(rnd(32)) };
  const keys = createCompanyKeys({ read: (n) => secrets[n], signing: { CO_NS: ["env:SIGN"] } });
  const k1 = await keys.signingKey("CO_NS");
  assert.equal(await keys.signingKey("CO_NS"), k1); // 同じ値なら覚えたものを使う
  secrets.SIGN = toBase64Url(rnd(32));
  assert.notEqual(await keys.signingKey("CO_NS"), k1);
  assert.equal(await keys.signingKey("CO_OTHER"), undefined);
  delete secrets.SIGN;
  assert.equal(await keys.signingKey("CO_NS"), undefined);
  assert.deepEqual(await keys.verifyKeys("CO_NS"), []);
});

test("会社の鍵：短すぎる鍵・形の違う値は読み込まない", async () => {
  const keys = createCompanyKeys({ read: (n) => ({ SHORT: toBase64Url(rnd(16)), BAD: "***" })[n], signing: { A: ["env:SHORT"], B: ["env:BAD"] } });
  await assert.rejects(keys.signingKey("A"), /32 バイト/);
  await assert.rejects(keys.signingKey("B"), /base64url/);
});

test("会社の鍵：暗号化の鍵の入れ替え中は、古い鍵で暗号化した本文も開ける", async () => {
  const secrets: Record<string, string> = { SEAL_OLD: toBase64Url(rnd(32)), SEAL_NEW: toBase64Url(rnd(32)), SIGN: toBase64Url(rnd(32)) };
  const read = (n: string) => secrets[n];
  const now = () => 1;
  const before = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN"] }, seal: { CO_NS: ["env:SEAL_OLD"] } });
  const env = await createSender({ co: "CO_NS", by: "u1", now, signingKey: (await before.signingKey("CO_NS"))!, sealKey: (await before.sealKey("CO_NS"))! })
    .make("record", "record.attendance.clockin", { c: 3, b: { secret: 1 } });
  const during = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN"] }, seal: { CO_NS: ["env:SEAL_NEW", "env:SEAL_OLD"] } });
  assert.deepEqual(await readBody(env, await during.openKeys("CO_NS")), { secret: 1 });
  const after = createCompanyKeys({ read, signing: { CO_NS: ["env:SIGN"] }, seal: { CO_NS: ["env:SEAL_NEW"] } });
  await assert.rejects(readBody(env, await after.openKeys("CO_NS")));
});

test("代理実行：ut: の参照だけを窓口へ渡す。env: の鍵を外へ渡す道は無い", async () => {
  const calls: unknown[] = [];
  const broker: KeyBroker = { call: async (category, op, args) => (calls.push({ category, op, args }), { ok: true }) };
  assert.deepEqual(await callWithKey("ut:nsc-navitime", broker, "request", { method: "GET" }), { ok: true });
  assert.deepEqual(calls, [{ category: "nsc-navitime", op: "request", args: { method: "GET" } }]);
  await assert.rejects(callWithKey("env:NAVITIME_API_KEY", broker, "request", {}), /ut:/);
  assert.equal(calls.length, 1);
});
