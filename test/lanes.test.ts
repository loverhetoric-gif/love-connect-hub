import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Envelope,
  BATCH_PART_BYTES,
  RAW_MAX_BYTES,
  SendError,
  createBatchAssembler,
  createDedupe,
  createMediaAssembler,
  createReceiver,
  createSender,
  describeMedia,
  formatTable,
  importSealKey,
  importSigningKey,
  partCount,
  partId,
  planBatch,
  readBody,
  signEnvelope,
  splitMedia,
} from "../src/index.ts";

const rnd = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
};

const formats = formatTable({
  key: ["key.github.token"],
  record: ["record.nsc.attendance"],
  event: ["event.app.done"],
  media: ["media.image.webp"],
  api: ["api.freee.deals"],
});

async function setup(nowRef = { t: 1_000_000 }) {
  const signingKey = await importSigningKey(rnd(32));
  const sealKey = await importSealKey(rnd(32));
  const now = () => nowRef.t;
  const sender = createSender({ co: "nsc", by: "u1", now, signingKey, sealKey });
  const receiver = createReceiver({ formats, now, signingKey: (co) => (co === "nsc" ? signingKey : undefined) });
  return { signingKey, sealKey, sender, receiver, nowRef };
}

// ---- 形式の許可表 ----

test("許可表：形式はレーン名で始める", () => {
  assert.throws(() => formatTable({ record: ["event.x.y"] }));
});

test("形式はレーン名で始まらないと拒否（封筒の検査）", async () => {
  const { sender } = await setup();
  await assert.rejects(sender.make("record", "event.app.done"), (e: unknown) => e instanceof SendError && e.code === "BAD_FIELD");
});

// ---- 送り口 ----

test("送り口：番号・時刻・既定の機密度を付け、署名する", async () => {
  const { sender } = await setup();
  const e = await sender.make("record", "record.nsc.attendance", { b: { d: "2026-11-08" }, bv: 3 });
  assert.equal(e.v, 1);
  assert.equal(e.at, 1_000_000);
  assert.equal(e.c, 1, "レコードの下限は社内");
  assert.equal(e.bv, 3);
  assert.match(e.id, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(typeof e.sig, "string");
});

test("送り口：極秘の本文は自動で暗号化し、受け手は開ける", async () => {
  const { sender, receiver, sealKey } = await setup();
  const e = await sender.make("api", "api.freee.deals", { c: 3, b: { amount: 1 } });
  assert.equal(e.e, "A256GCM");
  assert.equal(typeof e.b, "string");
  assert.ok(!String(e.b).includes("amount"));
  const r = await receiver.receive(JSON.stringify(e));
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(await readBody(r.env, sealKey), { amount: 1 });
  await assert.rejects(readBody(e));
});

test("送り口：鍵が無いときは機密以上・極秘を送らない", async () => {
  const s = createSender({ co: "nsc", by: "u1", now: () => 1 });
  await assert.rejects(s.make("api", "api.freee.deals", { c: 2, b: 1 }), (e: unknown) => e instanceof SendError && e.code === "NO_SIGNING_KEY");
  await assert.rejects(s.make("api", "api.freee.deals", { c: 3, b: 1 }), (e: unknown) => e instanceof SendError && e.code === "NO_SEAL_KEY");
});

test("送り口：規格に合わない封筒は送る前に止める", async () => {
  const { sender } = await setup();
  await assert.rejects(sender.make("media", "media.image.webp", { b: "x" }), (e: unknown) => e instanceof SendError && e.code === "MISSING_FIELD");
  await assert.rejects(sender.make("key", "key.github.token", { b: "secret", ref: "linings:k" }), (e: unknown) => e instanceof SendError && e.code === "BODY_FORBIDDEN");
});

// ---- 受け口 ----

test("受け口：正しい封筒は通る（文字列・解析済みの両方）", async () => {
  const { sender, receiver } = await setup();
  const e = await sender.make("event", "event.app.done", { b: { ok: 1 } });
  assert.ok((await receiver.receive(JSON.stringify(e))).ok);
  const e2 = await sender.make("event", "event.app.done", { b: { ok: 2 } });
  assert.ok((await receiver.receive(e2)).ok);
});

test("受け口：大きすぎる・JSON でない・許可表に無いものを拒否", async () => {
  const { sender, receiver } = await setup();
  const code = async (x: unknown) => {
    const r = await receiver.receive(x);
    return r.ok ? "OK" : r.code;
  };
  assert.equal(await code("x".repeat(RAW_MAX_BYTES + 1)), "TOO_LARGE");
  assert.equal(await code("あ".repeat(Math.ceil(RAW_MAX_BYTES / 3) + 1)), "TOO_LARGE");
  assert.equal(await code("{"), "BAD_JSON");
  const s = createSender({ co: "nsc", by: "u1", now: () => 1_000_000, signingKey: (await setup()).signingKey });
  const other = await s.make("stream", "stream.audio.opus", { sq: 0 });
  assert.equal(await code(other), "FORMAT_NOT_ALLOWED");
  void sender;
});

test("受け口：締め切り切れ・未来の時刻を拒否", async () => {
  const t = { t: 1_000_000 };
  const { sender, receiver } = await setup(t);
  const e = await sender.make("record", "record.nsc.attendance", { b: 1, dl: 100 });
  t.t += 101;
  const r1 = await receiver.receive(e);
  assert.equal(r1.ok ? "OK" : r1.code, "EXPIRED");
  t.t = 1_000_000 - 60_001;
  const e2 = await sender.make("record", "record.nsc.attendance", { b: 1 });
  t.t = 1_000_000 - 120_002;
  const r2 = await receiver.receive(e2);
  assert.equal(r2.ok ? "OK" : r2.code, "FUTURE_TIME");
});

test("受け口：署名の改ざん・鍵の無い会社・別の鍵を拒否", async () => {
  const { sender, receiver } = await setup();
  const e = await sender.make("record", "record.nsc.attendance", { b: { x: 1 } });
  const tampered = { ...e, b: { x: 2 } };
  const r1 = await receiver.receive(tampered);
  assert.equal(r1.ok ? "OK" : r1.code, "BAD_SIGNATURE");
  const s2 = createSender({ co: "other", by: "u1", now: () => 1_000_000, signingKey: await importSigningKey(rnd(32)) });
  const r2 = await receiver.receive(await s2.make("record", "record.nsc.attendance", { b: 1 }));
  assert.equal(r2.ok ? "OK" : r2.code, "NO_KEY");
  const s3 = createSender({ co: "nsc", by: "u1", now: () => 1_000_000, signingKey: await importSigningKey(rnd(32)) });
  const r3 = await receiver.receive(await s3.make("record", "record.nsc.attendance", { b: 1 }));
  assert.equal(r3.ok ? "OK" : r3.code, "BAD_SIGNATURE");
});

test("受け口：同じ番号は一度だけ。偽の署名の封筒は番号を記録しない", async () => {
  const { sender, receiver } = await setup();
  const e = await sender.make("event", "event.app.done", { b: 1 });
  // 先に偽物（同じ番号・別の本文）が届いても、正しい封筒は弾かれない
  const fake = { ...e, b: 2 };
  assert.equal(((await receiver.receive(fake)) as { code?: string }).code, "BAD_SIGNATURE");
  assert.ok((await receiver.receive(e)).ok);
  const again = await receiver.receive(e);
  assert.equal(again.ok ? "OK" : again.code, "DUPLICATE");
});

test("受け口：機密以上で署名が無いものは、鍵を探す前に拒否", async () => {
  let asked = 0;
  const receiver = createReceiver({ formats, now: () => 2_000, signingKey: () => { asked++; return undefined; } });
  const r = await receiver.receive({ v: 1, l: "api", f: "api.freee.deals", id: "msg_0001", co: "nsc", by: "u", at: 1_000, c: 2, b: 1 });
  assert.equal(r.ok ? "OK" : r.code, "SIGNATURE_REQUIRED");
  assert.equal(asked, 0);
});

test("受け口：鍵レーンは置き場所だけを通す", async () => {
  const { sender, receiver } = await setup();
  const e = await sender.make("key", "key.github.token", { ref: "linings:GITHUB_WRITE" });
  assert.equal(e.c, 3);
  const r = await receiver.receive(e);
  assert.ok(r.ok);
  if (r.ok) assert.equal(r.env.b, undefined);
});

// ---- レコードの一括 ----

test("一括：分けて送り、順番が前後しても、件数とハッシュで照合して組み立てる", async () => {
  const { sender, receiver } = await setup();
  const rows = Array.from({ length: 3000 }, (_, i) => ({ id: i, name: `行${i}`, note: "x".repeat(40) }));
  const plan = await planBatch(rows);
  assert.ok(plan.parts.length > 1, "複数の片に分かれる");
  for (const p of plan.parts) assert.ok(new TextEncoder().encode(JSON.stringify(p)).byteLength <= BATCH_PART_BYTES);
  const batchId = "import-20261108";
  const envs: Envelope[] = [];
  for (let i = 0; i < plan.parts.length; i++) envs.push(await sender.make("record", "record.nsc.attendance", { id: partId(batchId, i), sq: i, b: plan.parts[i] }));
  envs.push(await sender.make("record", "record.nsc.attendance", { id: partId(batchId, "end"), b: { parts: plan.parts.length, rows: plan.rows }, h: plan.h }));
  envs.reverse(); // 逆順で届いても組み立てられる
  const asm = createBatchAssembler();
  let last;
  for (const e of envs) {
    const r = await receiver.receive(e);
    assert.ok(r.ok);
    if (r.ok) last = await asm.add(r.env);
  }
  assert.equal(last?.state, "done");
  if (last?.state === "done") assert.deepEqual(last.rows, rows);
});

test("一括：件数・ハッシュの不一致、二重の片、別の一括を拒否", async () => {
  const mk = (id: string, extra: Partial<Envelope>): Envelope => ({ v: 1, l: "record", f: "record.nsc.attendance", id, co: "nsc", by: "u", at: 1, c: 1, ...extra });
  const plan = await planBatch([{ a: 1 }, { a: 2 }]);
  const a1 = createBatchAssembler();
  await a1.add(mk("batch-001_0", { sq: 0, b: plan.parts[0] }));
  assert.equal((await a1.add(mk("batch-001_0", { sq: 0, b: plan.parts[0] }))).state, "error");
  assert.equal((await a1.add(mk("batch-002_1", { sq: 1, b: [] }))).state, "error");
  const r = await a1.add(mk("batch-001_end", { b: { parts: 1, rows: 3 }, h: plan.h }));
  assert.equal(r.state === "error" && r.code, "COUNT_MISMATCH");
  const a2 = createBatchAssembler();
  await a2.add(mk("batch-003_0", { sq: 0, b: [{ a: 1 }, { a: 9 }] }));
  const r2 = await a2.add(mk("batch-003_end", { b: { parts: 1, rows: 2 }, h: plan.h }));
  assert.equal(r2.state === "error" && r2.code, "HASH_MISMATCH");
  const a3 = createBatchAssembler();
  assert.equal((await a3.add(mk("batch-004_1", { sq: 2, b: [] }))).state, "error", "番号と sq の食い違い");
  assert.equal((await a3.add(mk("short", { b: [] }))).state, "error");
  assert.throws(() => partId("abc", 0));
});

test("一括：1 行が上限を超えるものは分けられない", async () => {
  await assert.rejects(planBatch([{ x: "x".repeat(BATCH_PART_BYTES) }]));
  const empty = await planBatch([]);
  assert.equal(empty.parts.length, 0);
});

// ---- メディア ----

test("メディア：分けて、順番が前後しても組み立て、ハッシュで照合する", async () => {
  const chunk = 1000;
  const data = rnd(3500);
  const meta = await describeMedia(data);
  assert.equal(partCount(data.byteLength, chunk), 4);
  const pieces = [...splitMedia(data, chunk)];
  assert.equal(pieces.length, 4);
  const asm = createMediaAssembler(meta, { chunk });
  for (const p of pieces.reverse()) assert.ok(asm.add(p.sq, p.bytes).ok);
  assert.ok(asm.complete);
  assert.deepEqual(await asm.finish(), data);
});

test("メディア：範囲外・二重・大きさ違い・中身の改ざん・上限超えを拒否", async () => {
  const chunk = 1000;
  const data = rnd(2500);
  const meta = await describeMedia(data);
  const asm = createMediaAssembler(meta, { chunk });
  assert.equal((asm.add(3, new Uint8Array(500)) as { code?: string }).code, "BAD_PART");
  assert.equal((asm.add(-1, new Uint8Array(1000)) as { code?: string }).code, "BAD_PART");
  assert.equal((asm.add(0, new Uint8Array(999)) as { code?: string }).code, "BAD_SIZE");
  assert.equal((asm.add(2, new Uint8Array(1000)) as { code?: string }).code, "BAD_SIZE", "最後の片は残りの大きさ");
  assert.ok(asm.add(0, data.subarray(0, 1000)).ok);
  assert.equal((asm.add(0, data.subarray(0, 1000)) as { code?: string }).code, "DUPLICATE_PART");
  await assert.rejects(asm.finish());
  const bad = data.slice(1000, 2000);
  bad[0] = bad[0]! ^ 1;
  asm.add(1, bad);
  asm.add(2, data.subarray(2000));
  await assert.rejects(asm.finish(), /ハッシュ/);
  assert.throws(() => createMediaAssembler({ len: 101 * 1024 * 1024, h: meta.h }));
  assert.throws(() => createMediaAssembler({ len: 1 }));
});

test("メディア：大きさ 0 のファイルも扱える", async () => {
  const meta = await describeMedia(new Uint8Array(0));
  const asm = createMediaAssembler(meta);
  assert.ok(asm.add(0, new Uint8Array(0)).ok);
  assert.equal((await asm.finish()).byteLength, 0);
});

test("メディア：封筒には本文を入れず、大きさとハッシュだけを送る", async () => {
  const { sender, receiver } = await setup();
  const meta = await describeMedia(rnd(10));
  const e = await sender.make("media", "media.image.webp", { ref: "r2:lch/abc.webp", ...meta });
  const r = await receiver.receive(e);
  assert.ok(r.ok);
});

// ---- 重複防止の上限 ----

test("重複防止：上限を超えたら古いものから忘れる", () => {
  const d = createDedupe({ windowMs: 1e9, capacity: 2 });
  d.first("a", "1", 0);
  d.first("a", "2", 1);
  d.first("a", "3", 2);
  assert.equal(d.size, 2);
  assert.equal(d.first("a", "1", 3), true, "最も古いものは忘れている");
  void signEnvelope;
});
