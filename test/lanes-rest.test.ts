import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Attempt,
  type Envelope,
  aiDelta,
  aiEnd,
  checkEnvelope,
  checkVersion,
  createAiAssembler,
  createStreamReorder,
  isRetryable,
  mergeFields,
  parseSeqId,
  seqId,
  withRetry,
} from "../src/index.ts";

const mk = (l: Envelope["l"], id: string, extra: Partial<Envelope> = {}): Envelope =>
  ({ v: 1, l, f: `${l}.test.item`, id, co: "nsc", by: "u", at: 1000, c: l === "ai" ? 1 : 0, ...extra }) as Envelope;

// ---- 続き物の番号 ----

test("続き物の番号：作って読める。形が違えば読めない", () => {
  assert.equal(seqId("stream-0001", 5), "stream-0001_5");
  assert.deepEqual(parseSeqId("stream-0001_5"), { group: "stream-0001", sq: 5 });
  assert.deepEqual(parseSeqId("stream-0001_end"), { group: "stream-0001", sq: "end" });
  assert.equal(parseSeqId("short_1"), undefined);
  assert.equal(parseSeqId("stream-0001-5"), undefined);
  assert.throws(() => seqId("abc", 0));
  assert.throws(() => seqId("stream-0001", -1));
  assert.throws(() => seqId("stream-0001", 1.5));
  // 作った番号は封筒の検査を通る
  assert.ok(checkEnvelope(mk("stream", seqId("stream-0001", 999_999_999), { sq: 999_999_999 })).ok);
});

// ---- ストリーミング ----

const piece = (sq: number) => mk("stream", seqId("stream-0001", sq), { sq });
const sqs = (es: Envelope[]) => es.map((e) => e.sq);

test("ストリーミング：順番どおりならそのまま渡す", () => {
  const r = createStreamReorder();
  assert.deepEqual(sqs(r.push(piece(0), 0)), [0]);
  assert.deepEqual(sqs(r.push(piece(1), 1)), [1]);
  assert.equal(r.next, 2);
});

test("ストリーミング：前後して届いても並べ直す", () => {
  const r = createStreamReorder();
  r.push(piece(0), 0);
  assert.deepEqual(sqs(r.push(piece(2), 1)), []);
  assert.deepEqual(sqs(r.push(piece(3), 2)), []);
  assert.deepEqual(sqs(r.push(piece(1), 3)), [1, 2, 3]);
  assert.equal(r.stats.skipped, 0);
});

test("ストリーミング：途中から受け取り始めてよい", () => {
  const r = createStreamReorder();
  assert.deepEqual(sqs(r.push(piece(42), 0)), [42]);
  assert.equal(r.next, 43);
});

test("ストリーミング：欠けは待ち時間だけ待ち、来なければ飛ばす。後から来た片は捨てる", () => {
  const r = createStreamReorder({ waitMs: 100 });
  r.push(piece(0), 0);
  assert.deepEqual(sqs(r.push(piece(2), 10)), []);
  assert.deepEqual(sqs(r.flush(109)), [], "まだ待つ");
  assert.deepEqual(sqs(r.flush(110)), [2], "100ms 待って 1 を飛ばす");
  assert.equal(r.stats.skipped, 1);
  assert.deepEqual(sqs(r.push(piece(1), 120)), [], "遅れた片は捨てる");
  assert.equal(r.stats.late, 1);
});

test("ストリーミング：二重の片は捨て、置き場所があふれたら先へ進む", () => {
  const r = createStreamReorder({ waitMs: 1e9, maxBuffered: 3 });
  r.push(piece(0), 0);
  r.push(piece(2), 0);
  assert.deepEqual(sqs(r.push(piece(2), 0)), []);
  assert.equal(r.stats.duplicate, 1);
  r.push(piece(3), 0);
  r.push(piece(4), 0);
  assert.deepEqual(sqs(r.push(piece(5), 0)), [2, 3, 4, 5], "4 片待ったところで 1 を飛ばす");
  assert.throws(() => r.push(mk("stream", "stream-0001_9"), 0), /sq/);
  assert.throws(() => createStreamReorder({ maxBuffered: 0 }));
});

// ---- 同期 ----

test("同期：元の版が今の版と同じときだけ書ける", () => {
  assert.deepEqual(checkVersion(3, 3), { ok: true, next: 4 });
  assert.deepEqual(checkVersion(3, 2), { ok: false, code: "VERSION_CONFLICT", current: 3 });
  assert.deepEqual(checkVersion(3, undefined), { ok: false, code: "VERSION_CONFLICT", current: 3 });
});

test("同期：片方だけが変えた項目は自動でまとめる（追加・削除を含む）", () => {
  const base = { a: 1, b: 2, c: 3, d: { x: 1 } };
  const theirs = { a: 9, b: 2, c: 3, d: { x: 1 }, e: "相手が追加" };
  const mine = { a: 1, b: 7, d: { x: 1 } }; // c を消した
  const r = mergeFields(base, theirs, mine);
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(r.merged, { a: 9, b: 7, d: { x: 1 }, e: "相手が追加" });
});

test("同期：両方が同じ項目を別の値に変えたらぶつかりとして返し、相手の値を残す", () => {
  const r = mergeFields({ a: 1, b: 1 }, { a: 2, b: 5 }, { a: 3, b: 5 });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.deepEqual(r.fields, ["a"]);
    assert.deepEqual(r.merged, { a: 2, b: 5 }, "同じ値に変えた b はぶつからない");
  }
  // 入れ子の中身も、並びに関係なく同じものは同じとみなす
  const r2 = mergeFields({ o: { x: 1 } }, { o: { y: 2, x: 1 } }, { o: { x: 1, y: 2 } });
  assert.ok(r2.ok);
});

test("同期：__proto__ などの危ない項目名は常にぶつかり扱い", () => {
  const evil = JSON.parse('{"__proto__":{"polluted":1}}');
  const r = mergeFields({}, {}, evil);
  assert.equal(r.ok, false);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

// ---- API の再試行 ----

function fakeClock() {
  let t = 0;
  const waits: number[] = [];
  return { now: () => t, sleep: async (ms: number) => { waits.push(ms); t += ms; }, waits };
}

test("API：やり直してよい失敗の見分け", () => {
  for (const s of [0, 408, 425, 429, 500, 502, 503, 504]) assert.equal(isRetryable(s), true, String(s));
  for (const s of [400, 401, 403, 404, 409, 422, 501]) assert.equal(isRetryable(s), false, String(s));
});

test("API：一時的な失敗はやり直し、成功したら返す。待ち時間は倍々で上限あり", async () => {
  const c = fakeClock();
  const seq: Attempt<string>[] = [{ status: 503 }, { status: 0 }, { status: 200, value: "済" }];
  const r = await withRetry(async (i) => seq[i - 1]!, { now: c.now, sleep: c.sleep, random: () => 0.999, baseMs: 100, maxMs: 150 });
  assert.deepEqual(r, { ok: true, value: "済", attempts: 3 });
  assert.equal(c.waits.length, 2);
  assert.ok(c.waits[0]! <= 100 && c.waits[0]! >= 50);
  assert.ok(c.waits[1]! <= 150, "上限を超えない");
});

test("API：やり直せない失敗はすぐ止める。例外は通信失敗として扱う", async () => {
  const c = fakeClock();
  const r = await withRetry(async () => ({ status: 403 }), { now: c.now, sleep: c.sleep });
  assert.deepEqual(r, { ok: false, status: 403, attempts: 1, reason: "NOT_RETRYABLE" });
  let n = 0;
  const r2 = await withRetry(async () => { n++; throw new Error("切断"); }, { now: c.now, sleep: c.sleep, attempts: 2 });
  assert.deepEqual(r2, { ok: false, status: 0, attempts: 2, reason: "ATTEMPTS" });
  assert.equal(n, 2);
});

test("API：締め切りを越える待ちはしない。相手の待ち指示は上限内で守る", async () => {
  const c = fakeClock();
  const r = await withRetry(async () => ({ status: 429, retryAfterSec: 3 }), { now: c.now, sleep: c.sleep, maxMs: 5000, deadlineAt: 2000 });
  assert.deepEqual(r, { ok: false, status: 429, attempts: 1, reason: "DEADLINE" });
  assert.equal(c.waits.length, 0);
  const c2 = fakeClock();
  await withRetry(async (i) => (i === 1 ? { status: 429, retryAfterSec: 2 } : { status: 200, value: 1 }), { now: c2.now, sleep: c2.sleep, random: () => 0 });
  assert.equal(c2.waits[0], 2000);
  await assert.rejects(withRetry(async () => ({ status: 200 }), { now: c.now, attempts: 0 }));
});

// ---- AI の逐次受け取り ----

const frag = (sq: number, d: string, g = "reply-0001") => mk("ai", seqId(g, sq), { sq, b: aiDelta(d) });
const end = (n: number, g = "reply-0001", u?: { in: number; out: number }) => mk("ai", seqId(g, "end"), { b: aiEnd(n, u) });

test("AI：つながった分から先に返し、終わりで使った量を返す", () => {
  const a = createAiAssembler();
  assert.deepEqual(a.add(frag(0, "こんに")), { state: "partial", delta: "こんに", text: "こんに" });
  assert.deepEqual(a.add(frag(2, "は")), { state: "partial", delta: "", text: "こんに" }, "1 が来るまで出さない");
  // 1 が届くと、待っていた 2 もつながって一度に出る
  assert.deepEqual(a.add(frag(1, "ちは、世界")), { state: "partial", delta: "ちは、世界は", text: "こんにちは、世界は" });
  const r = a.add(end(3, "reply-0001", { in: 10, out: 5 }));
  assert.deepEqual(r, { state: "done", delta: "", text: "こんにちは、世界は", usage: { in: 10, out: 5 } });
  assert.equal(a.add(frag(3, "x")).state, "error", "終わった後は受け取らない");
});

test("AI：終わりが先に届いても、全部そろった時点で完了する", () => {
  const a = createAiAssembler();
  assert.equal(a.add(end(2)).state, "partial");
  a.add(frag(1, "B"));
  const r = a.add(frag(0, "A"));
  assert.deepEqual(r, { state: "done", delta: "AB", text: "AB" });
});

test("AI：二重・範囲外・別の応答・形違い・大きすぎを拒否", () => {
  const a = createAiAssembler({ maxChars: 5 });
  a.add(frag(0, "abc"));
  const code = (s: ReturnType<typeof a.add>) => (s.state === "error" ? s.code : s.state);
  assert.equal(code(a.add(frag(0, "x"))), "DUPLICATE_PART");
  assert.equal(code(a.add(frag(1, "x", "reply-0002"))), "OTHER_GROUP");
  assert.equal(code(a.add(mk("ai", seqId("reply-0001", 1), { sq: 2, b: aiDelta("x") }))), "BAD_PART");
  assert.equal(code(a.add(mk("ai", seqId("reply-0001", 1), { sq: 1, b: { t: "x" } }))), "BAD_PART");
  assert.equal(code(a.add(frag(1, "xyz"))), "TOO_LARGE");
  assert.equal(code(a.add(mk("record", seqId("reply-0001", 1), { sq: 1 }))), "BAD_LANE");
  assert.equal(code(a.add(mk("ai", "not-a-seq-id"))), "BAD_ID");
  assert.equal(code(a.add(end(0))), "BAD_PART", "受け取り済みより少ない数");
  assert.equal(code(a.add(mk("ai", seqId("reply-0001", "end"), { b: { n: 2, u: { in: -1, out: 0 } } }))), "BAD_END");
});
