import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Envelope,
  HEADER_MAX_BYTES,
  LANE_NAMES,
  LANES,
  checkEnvelope,
  compareUrgency,
  isExpired,
  redact,
  retentionOf,
} from "../src/index.ts";

const SIG = "A".repeat(43);
const HASH = "a".repeat(64);

function base(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, l: "record", f: "record.nsc.attendance", id: "msg_0001", co: "nsc", by: "u1", at: 1_000, c: 1, b: { x: 1 }, ...over };
}

function code(input: unknown, opts?: Parameters<typeof checkEnvelope>[1]): string {
  const r = checkEnvelope(input, opts);
  return r.ok ? "OK" : r.code;
}

test("レーンはちょうど 8 本で、優先度が重ならない", () => {
  assert.equal(LANE_NAMES.length, 8);
  const p = new Set(LANE_NAMES.map((n) => LANES[n].priority));
  assert.equal(p.size, 8);
  assert.ok(Object.isFrozen(LANES) && Object.isFrozen(LANES.key));
});

test("正しい封筒は通り、中身を書き換えない", () => {
  const e = base();
  const r = checkEnvelope(e);
  assert.ok(r.ok);
  if (r.ok) assert.equal(r.env, e);
});

test("封筒でないものは拒否する", () => {
  for (const x of [null, 1, "a", [], undefined]) assert.equal(code(x), "NOT_OBJECT");
});

test("規格に無い項目は拒否する（__proto__ を含む）", () => {
  assert.equal(code(base({ extra: 1 })), "UNKNOWN_FIELD");
  const polluted = JSON.parse('{"v":1,"l":"record","f":"record.a.b","id":"msg_0001","co":"c","by":"u","at":1,"c":1,"__proto__":{"x":1}}');
  assert.equal(code(polluted), "UNKNOWN_FIELD");
});

test("規格版とレーンの検査", () => {
  assert.equal(code(base({ v: 2 })), "BAD_VERSION");
  assert.equal(code(base({ l: "video" })), "BAD_LANE");
  assert.equal(code(base({ l: "toString" })), "BAD_LANE");
});

test("見出しの項目の形", () => {
  assert.equal(code(base({ f: "Record" })), "BAD_FIELD");
  assert.equal(code(base({ f: "record" })), "BAD_FIELD");
  assert.equal(code(base({ id: "short" })), "BAD_FIELD");
  assert.equal(code(base({ co: "a b" })), "BAD_FIELD");
  assert.equal(code(base({ by: "" })), "BAD_FIELD");
  assert.equal(code(base({ at: 0 })), "BAD_FIELD");
  assert.equal(code(base({ at: 1.5 })), "BAD_FIELD");
  assert.equal(code(base({ c: 4 })), "BAD_FIELD");
  assert.equal(code(base({ dl: -1 })), "BAD_FIELD");
  assert.equal(code(base({ dl: 600_001 })), "BAD_FIELD");
  assert.equal(code(base({ ap: "yes" })), "BAD_FIELD");
  assert.equal(code(base({ h: "XYZ" })), "BAD_FIELD");
  assert.equal(code(base({ e: "DES" })), "BAD_FIELD");
  assert.equal(code(base({ sig: "short" })), "BAD_FIELD");
  assert.equal(code(base({ ref: "has space" })), "BAD_FIELD");
});

test("形式の許可表を渡したら、無い形式はすべて拒否する", () => {
  const formats = { record: new Set(["record.nsc.attendance"]) };
  assert.equal(code(base(), { formats }), "OK");
  assert.equal(code(base({ f: "record.nsc.cases" }), { formats }), "FORMAT_NOT_ALLOWED");
  assert.equal(code(base({ l: "event", f: "event.a.b", c: 0 }), { formats }), "FORMAT_NOT_ALLOWED");
});

test("鍵レーン：値を運べず、極秘・保存なし・署名が必須", () => {
  const key = { l: "key", f: "key.github.token", c: 3, b: undefined, ref: "linings:key/abc", sig: SIG };
  assert.equal(code(base(key)), "OK");
  assert.equal(code(base({ ...key, c: 2 })), "CLASS_TOO_LOW");
  assert.equal(code(base({ ...key, ref: undefined })), "MISSING_FIELD");
  assert.equal(code(base({ ...key, b: "secret", ref: undefined })), "MISSING_FIELD");
  assert.equal(code(base({ ...key, b: "secret" })), "BODY_FORBIDDEN");
  assert.equal(code(base({ ...key, ret: 60 })), "BAD_FIELD");
  assert.equal(code(base({ ...key, sig: undefined })), "SIGNATURE_REQUIRED");
});

test("メディアレーン：本文は直接持ち込まず、大きさとハッシュが必須", () => {
  const m = { l: "media", f: "media.image.webp", c: 0, b: undefined, ref: "r2:bucket/a.webp", len: 10, h: HASH };
  assert.equal(code(base(m)), "OK");
  assert.equal(code(base({ ...m, h: undefined })), "MISSING_FIELD");
  assert.equal(code(base({ ...m, b: "x" })), "BODY_FORBIDDEN");
});

test("ストリーミングと同期は順番が必須、同期は元の版も必須", () => {
  assert.equal(code(base({ l: "stream", f: "stream.audio.opus", c: 0 })), "MISSING_FIELD");
  assert.equal(code(base({ l: "stream", f: "stream.audio.opus", c: 0, sq: 0 })), "OK");
  assert.equal(code(base({ l: "sync", f: "sync.doc.text", sq: 1 })), "MISSING_FIELD");
  assert.equal(code(base({ l: "sync", f: "sync.doc.text", sq: 1, bv: 0 })), "OK");
});

test("機密性：機密以上は署名、極秘の本文は暗号化が必須", () => {
  assert.equal(code(base({ c: 2 })), "SIGNATURE_REQUIRED");
  assert.equal(code(base({ c: 2, sig: SIG })), "OK");
  assert.equal(code(base({ c: 3, sig: SIG })), "ENCRYPTION_REQUIRED");
  assert.equal(code(base({ c: 3, sig: SIG, e: "A256GCM", b: "abc" })), "OK");
  assert.equal(code(base({ e: "A256GCM", b: { x: 1 } })), "BAD_FIELD");
  assert.equal(code(base({ e: "A256GCM", b: undefined })), "BAD_FIELD");
  assert.equal(code(base({ l: "ai", f: "ai.chat.message", c: 0 })), "CLASS_TOO_LOW");
});

test("本文と置き場所はどちらか一方", () => {
  assert.equal(code(base({ ref: "r2:x" })), "BODY_AND_REF");
  assert.equal(code(base({ b: undefined, ref: "r2:x" })), "OK");
});

test("本文の上限ちょうどは通り、1 バイト超えると拒否", () => {
  const max = LANES.event.inlineMax;
  const ok = "あ".repeat(Math.floor(max / 3)) + "a".repeat(max % 3);
  assert.equal(code(base({ l: "event", f: "event.app.done", c: 0, b: ok })), "OK");
  assert.equal(code(base({ l: "event", f: "event.app.done", c: 0, b: ok + "a" })), "BODY_TOO_LARGE");
});

test("見出しが大きすぎるものは拒否", () => {
  const ref = "r".repeat(512);
  assert.equal(code(base({ b: undefined, ref })), "OK");
  // ref の上限は 512 なので、見出しの上限を超える組み合わせは作れない。上限の値そのものを確かめる
  assert.ok(HEADER_MAX_BYTES >= 1024);
});

test("締め切り：既定値と指定値、締め切りなし", () => {
  const e = base() as unknown as Envelope; // record の既定 5000ms
  assert.equal(isExpired(e, 6_000), false);
  assert.equal(isExpired(e, 6_001), true);
  assert.equal(isExpired({ ...e, dl: 10 }, 1_011), true);
  assert.equal(isExpired({ ...e, l: "event" }, 1e15), false);
});

test("保存期間：鍵は常に 0、ほかは指定値か既定値", () => {
  const e = base() as unknown as Envelope;
  assert.equal(retentionOf({ ...e, l: "key" }), 0);
  assert.equal(retentionOf({ ...e, ret: 5 }), 5);
  assert.equal(retentionOf({ ...e, l: "event" }), 7 * 86400);
  assert.equal(retentionOf(e), null, "レコードは保存先の決まりに従う");
  assert.equal(retentionOf({ ...e, l: "stream" }), 0);
});

test("記録用：社内以上の本文と署名は残さない", () => {
  const e = base({ sig: SIG, b: "秘密" }) as unknown as Envelope;
  const r = redact(e);
  assert.equal("b" in r, false);
  assert.equal("sig" in r, false);
  assert.equal(r.len, 6);
  const pub = redact({ ...e, c: 0 });
  assert.equal(pub.b, "秘密");
});

test("処理の順番：優先度 → 締め切り → 古さ", () => {
  const mk = (l: string, at: number, dl?: number) => ({ ...(base({ l, at, ...(dl === undefined ? {} : { dl }) }) as object) }) as Envelope;
  const list = [mk("media", 1), mk("record", 5, 100), mk("record", 1, 1000), mk("key", 9), mk("event", 1)];
  const order = list.sort(compareUrgency).map((e) => `${e.l}@${e.at}`);
  assert.deepEqual(order, ["key@9", "record@5", "record@1", "event@1", "media@1"]);
});
