import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHubTables, checkEnvelope } from "../src/index.ts";

const hubs = [
  { hub: "attendance", emits: ["record.attendance.clockin", "event.attendance.clockedin"], user: ["record.attendance.clockin"] },
  { hub: "work", emits: ["record.work.case.create", "event.work.case.saved"], user: ["record.work.case.create"] },
  { hub: "chat", emits: ["api.chat.send"], accepts: ["event.attendance.clockedin", "event.work.case.saved"] },
];

test("ハブの宣言：許可表・持ち主・受け手を組み立てる", () => {
  const t = buildHubTables(hubs);
  assert.equal(t.all.record?.has("record.work.case.create"), true);
  assert.equal(t.all.event?.has("event.attendance.clockedin"), true);
  assert.equal(t.user.record?.has("record.attendance.clockin"), true);
  assert.equal(t.user.event, undefined); // イベントはアプリから直接は送れない
  assert.equal(t.owner.get("event.work.case.saved"), "work");
  assert.deepEqual(t.subscribers.get("event.work.case.saved"), ["chat"]);
  // 組み立てた表は、そのまま封筒の検査に使える
  const env = { v: 1, l: "event", f: "event.work.case.saved", id: "evt-00000001", co: "CO_NS", by: "work", at: 1, c: 0 };
  assert.equal(checkEnvelope(env, { formats: t.all }).ok, true);
  assert.equal(checkEnvelope(env, { formats: t.user }).ok, false);
});

test("ハブの宣言：食い違いは動かす前に止める", () => {
  const bad: [unknown, RegExp][] = [
    [[{ hub: "work", emits: ["record.attendance.clockin"] }], /自分の形式だけ/],
    [[{ hub: "a1", emits: ["event.a1.x"] }, { hub: "a1" }], /重複/],
    [[{ hub: "a", emits: ["event.a.x"] }, { hub: "b", emits: ["event.a.x"] }], /自分の形式だけ/],
    [[{ hub: "chat", accepts: ["event.work.none"] }], /誰も出さない/],
    [[{ hub: "work", emits: ["event.work.x"], user: ["event.work.y"] }], /自分が出さない/],
    [[{ hub: "vault", emits: ["key.vault.token"], user: ["key.vault.token"] }], /鍵レーン/],
    [[{ hub: "Bad", emits: [] }], /ハブ ID/],
    [[{ hub: "work", emits: ["nolane.work.x"] }], /形式の名前/],
  ];
  for (const [h, re] of bad) assert.throws(() => buildHubTables(h as never), re);
});
