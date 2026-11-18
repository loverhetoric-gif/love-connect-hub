// 作業 ID（規格書 第22章）：封筒の tk・第2版・相互に分け合う記録帳
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SPEC_VERSION,
  TASK_DEFAULTS,
  checkDraft,
  checkEnvelope,
  createReceiver,
  createSender,
  createTaskBook,
  importSigningKey,
  newTaskId,
  verifyEnvelope,
} from "../src/index.ts";

const T0 = 1_800_000_000_000;
const base = (over: Record<string, unknown> = {}) => ({ v: 2, l: "record", f: "record.nsc.attendance", id: "msg_0001", co: "nsc", by: "u1", at: 1_000, c: 1, b: { x: 1 }, ...over });
const code = (x: unknown) => { const r = checkEnvelope(x); return r.ok ? "OK" : `${r.code}:${r.field}`; };
const mem = () => { const m = new Map<string, unknown>(); return { m, get: async <T>(k: string) => m.get(k) as T | undefined, put: async <T>(k: string, v: T) => { m.set(k, v); } }; };

test("封筒の作業 ID：第2版の封筒にだけ付けられ、形は w- ＋ 英数字 8 文字", () => {
  assert.equal(SPEC_VERSION, 2);
  assert.equal(code(base({ tk: "w-Ab12Cd34" })), "OK");
  assert.equal(code(base()), "OK", "作業 ID の無い第2版の封筒も通る");
  assert.equal(code(base({ v: 1, tk: "w-Ab12Cd34" })), "UNKNOWN_FIELD:tk", "第1版の封筒に作業 ID");
  assert.equal(code(base({ v: 1 })), "OK", "第1版の封筒は、これまでどおり通る");
  for (const tk of ["w-12345", "w-Ab12Cd345", "W-Ab12Cd34", "w-Ab12_d34", "w-Ab12Cd3!", "", 12345678]) assert.equal(code(base({ tk })), "BAD_FIELD:tk", String(tk));
});

test("送り口：作業 ID を付けると第2版、付けなければ第1版のまま（第1版だけの受け口にも届く）。署名は作業 ID も守る", async () => {
  const key = await importSigningKey(crypto.getRandomValues(new Uint8Array(32)));
  const s = createSender({ co: "nsc", by: "hub1", now: () => T0, signingKey: key });
  const plain = await s.make("event", "event.work.case.saved", { b: { n: 1 } });
  assert.equal(plain.v, 1); assert.equal("tk" in plain, false);
  const tagged = await s.make("event", "event.work.case.saved", { b: { n: 1 }, tk: "w-Ab12Cd34" });
  assert.equal(tagged.v, 2); assert.equal(tagged.tk, "w-Ab12Cd34");
  assert.equal(await verifyEnvelope(tagged, key), true);
  // 作業 ID を付け替える・外すと、署名が合わない
  assert.equal(await verifyEnvelope({ ...tagged, tk: "w-Zz99Yy88" }, key), false);
  const { tk: _tk, ...stripped } = tagged;
  assert.equal(await verifyEnvelope(stripped, key), false);
  await assert.rejects(s.make("event", "event.work.case.saved", { tk: "w-bad" }), (e: Error & { field?: string }) => e.field === "tk");
  // 受け口は第1版・第2版の両方を受け取り、作業 ID をそのまま渡す
  const r = createReceiver({ formats: { event: new Set(["event.work.case.saved"]) }, now: () => T0, signingKey: () => key });
  const got = await r.receive(JSON.stringify(tagged));
  assert.ok(got.ok); if (got.ok) assert.equal(got.env.tk, "w-Ab12Cd34");
  assert.ok((await r.receive(JSON.stringify(plain))).ok);
});

test("利用者の下書き：第2版にだけ作業 ID を付けられる。形が違えば断る", () => {
  const d = (over: Record<string, unknown>) => checkDraft({ v: 2, l: "record", f: "record.nsc.attendance", id: "msg_0001", ...over });
  assert.ok(d({ tk: "w-Ab12Cd34" }).ok);
  assert.ok(d({}).ok);
  assert.ok(checkDraft({ v: 1, l: "record", f: "record.nsc.attendance", id: "msg_0001" }).ok);
  assert.deepEqual(pick(checkDraft({ v: 1, l: "record", f: "record.nsc.attendance", id: "msg_0001", tk: "w-Ab12Cd34" })), ["UNKNOWN_FIELD", "tk"]);
  assert.deepEqual(pick(d({ tk: "w-12" })), ["BAD_FIELD", "tk"]);
  assert.deepEqual(pick(d({ v: 3 })), ["BAD_VERSION", "v"]);
});
function pick(r: ReturnType<typeof checkDraft>) { return r.ok ? ["OK", ""] : [r.code, r.field]; }

test("記録帳：id が無ければ自分で出し（self）、渡されればその ID のまま引用する（quoted）。同じ ID は二重に作らない", async () => {
  const book = createTaskBook({ store: mem(), now: () => T0 });
  const own = await book.start(undefined, "書類を作る");
  assert.ok(own.ok); if (!own.ok) return;
  assert.match(own.task.id, /^w-[0-9A-Za-z]{8}$/);
  assert.equal(own.task.issued_by, "self"); assert.equal(own.existing, false);
  const again = await book.start(own.task.id);
  assert.ok(again.ok && again.existing && again.task.issued_by === "self");
  const q = await book.start("w-HW000001");
  assert.ok(q.ok && q.task.issued_by === "quoted" && q.task.title === TASK_DEFAULTS.quotedTitle);
  const named = await book.start("w-HW000001", "請求書の発行");
  assert.ok(named.ok && named.existing && named.task.title === "請求書の発行" && named.task.issued_by === "quoted");
  const all = await Promise.all([book.start("w-Same0001"), book.touch("w-Same0001"), book.start("w-Same0001")]);
  assert.ok(all.every((r) => r.ok));
  assert.equal((await book.list()).active.length, 3);
  assert.equal((await book.start("w-12")).ok, false);
});

test("記録帳：知らない ID の操作は引用として引き受け、終了を宣言した ID は操作も始め直しも断る", async () => {
  const book = createTaskBook({ store: mem(), now: () => T0 });
  const t = await book.touch("w-Fr0mHW99");
  assert.ok(t.ok && t.adopted && t.task.issued_by === "quoted");
  assert.ok((await book.touch("w-Fr0mHW99")).ok);
  const e = await book.end("w-Fr0mHW99");
  assert.ok(e.ok && !e.already && e.task.state === "ended");
  const e2 = await book.end("w-Fr0mHW99");
  assert.ok(e2.ok && e2.already);
  assert.deepEqual(code2(await book.touch("w-Fr0mHW99")), "TASK_ENDED");
  assert.deepEqual(code2(await book.start("w-Fr0mHW99")), "TASK_ENDED");
  assert.deepEqual(code2(await book.end("w-Unknown1")), "TASK_UNKNOWN");
  assert.deepEqual(code2(await book.touch("x")), "BAD_TASK_ID");
});
function code2(r: { ok: boolean; code?: string }) { return r.ok ? "OK" : r.code; }

test("記録帳：放置された作業は、どれだけたっても消さない。消すのは終了を宣言して 7 日たった物だけ", async () => {
  const clock = { now: T0 };
  const book = createTaskBook({ store: mem(), now: () => clock.now });
  await book.start("w-Idle0001", "放置");
  await book.start("w-Done0001", "終わり");
  await book.end("w-Done0001");
  clock.now += TASK_DEFAULTS.keepEndedMs - 1000;
  assert.deepEqual((await book.list()).ended.map((x) => x.id), ["w-Done0001"]);
  clock.now += 2000;
  assert.deepEqual((await book.list()).ended, []);
  clock.now += 365 * 86_400_000;
  assert.deepEqual((await book.list()).active.map((x) => x.id), ["w-Idle0001"]);
});

test("記録帳：上限を超えたら終わった物の古い順にだけ消す。進行中だけで一杯なら、新しい作業を断る", async () => {
  const clock = { now: T0 };
  const book = createTaskBook({ store: mem(), now: () => clock.now, max: 5 });
  for (let i = 0; i < 5; i++) { clock.now++; assert.ok((await book.start()).ok); }
  assert.equal(code2(await book.start()), "TASK_FULL");
  assert.equal(code2(await book.touch("w-Over0001")), "TASK_FULL");
  const oldest = (await book.list()).active.at(-1)!.id;
  await book.end(oldest);
  assert.ok((await book.start("w-Next0001")).ok);
  const l = await book.list();
  assert.equal(l.active.length, 5); assert.deepEqual(l.ended, []);
});

test("出す作業 ID は、いつも w- ＋ 英数字 8 文字で、重ならない", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 5000; i++) { const id = newTaskId(); assert.match(id, /^w-[0-9A-Za-z]{8}$/); seen.add(id); }
  assert.equal(seen.size, 5000);
});
