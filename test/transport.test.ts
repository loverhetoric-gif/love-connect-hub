import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Envelope,
  CLOSE_POLICY,
  HTTP_PATH,
  RAW_MAX_BYTES,
  attachSocket,
  createHttpClient,
  createHttpHandler,
  createReceiver,
  createSender,
  formatTable,
  importSigningKey,
  readLimited,
  seqId,
} from "../src/index.ts";

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const formats = formatTable({
  record: ["record.nsc.attendance"],
  event: ["event.app.done"],
  stream: ["stream.audio.opus"],
  ai: ["ai.chat.reply"],
});

async function setup() {
  let t = 1_000_000;
  const now = () => t;
  const key = await importSigningKey(rnd(32));
  const sender = createSender({ co: "nsc", by: "u1", now, signingKey: key });
  const receiver = createReceiver({ formats, now, signingKey: (co) => (co === "nsc" ? key : undefined) });
  return { sender, receiver, now, advance: (ms: number) => (t += ms) };
}

const post = (body: string, init: { path?: string; type?: string; method?: string } = {}) =>
  new Request(`https://hub.example${init.path ?? HTTP_PATH}`, {
    method: init.method ?? "POST",
    headers: { "content-type": init.type ?? "application/json" },
    ...(init.method === "GET" ? {} : { body }),
  });

// ---- HTTP の受け口 ----

test("HTTP：正しい封筒は受け付け、処理の応答を返す。応答が無ければ 202", async () => {
  const { sender, receiver } = await setup();
  const got: Envelope[] = [];
  const h = createHttpHandler({ receiver, onEnvelope: (e) => { got.push(e); } });
  const e = await sender.make("record", "record.nsc.attendance", { b: { d: 1 } });
  const res = await h(post(JSON.stringify(e)));
  assert.equal(res.status, 202);
  assert.deepEqual(await res.json(), { ok: true, id: e.id });
  assert.equal(got.length, 1);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");

  const reply = await sender.make("event", "event.app.done", { b: { ok: 1 } });
  const h2 = createHttpHandler({ receiver, onEnvelope: () => reply });
  const e2 = await sender.make("record", "record.nsc.attendance", { b: { d: 2 } });
  const res2 = await h2(post(JSON.stringify(e2)));
  assert.equal(res2.status, 200);
  assert.deepEqual(((await res2.json()) as { env: Envelope }).env, reply);
});

test("HTTP：入口・方法・種類の違いを断る", async () => {
  const { receiver } = await setup();
  const h = createHttpHandler({ receiver, onEnvelope: () => {} });
  assert.equal((await h(post("{}", { path: "/other" }))).status, 404);
  const r405 = await h(post("", { method: "GET" }));
  assert.equal(r405.status, 405);
  assert.equal(r405.headers.get("allow"), "POST");
  assert.equal((await h(post("{}", { type: "text/plain" }))).status, 415);
  assert.equal((await h(post("{}", { type: "application/json; charset=utf-8" }))).status, 400, "charset 付きは受け付けて中身で断る");
});

test("HTTP：拒否の理由ごとの状態番号。送られた中身は返さない", async () => {
  const { sender, receiver, advance } = await setup();
  const h = createHttpHandler({ receiver, onEnvelope: () => {} });
  const status = async (body: string) => {
    const r = await h(post(body));
    const text = await r.text();
    assert.ok(!text.includes("秘密の本文"), "本文を返さない");
    return [r.status, (JSON.parse(text) as { code: string }).code];
  };
  assert.deepEqual(await status("{"), [400, "BAD_JSON"]);
  const e = await sender.make("record", "record.nsc.attendance", { b: "秘密の本文" });
  assert.deepEqual(await status(JSON.stringify({ ...e, b: "改ざん" })), [401, "BAD_SIGNATURE"]);
  assert.deepEqual(await status(JSON.stringify(e)), [202, undefined]);
  assert.deepEqual(await status(JSON.stringify(e)), [409, "DUPLICATE"]);
  const old = await sender.make("record", "record.nsc.attendance", { b: 1, dl: 10 });
  advance(11);
  assert.deepEqual(await status(JSON.stringify(old)), [410, "EXPIRED"]);
  const media = await sender.make("event", "event.app.done", { b: 1 });
  assert.deepEqual(await status(JSON.stringify({ ...media, f: "event.app.other" })), [403, "FORMAT_NOT_ALLOWED"]);
});

test("HTTP：大きすぎる本文は、申告でも実際の中身でも断る", async () => {
  const { receiver } = await setup();
  const h = createHttpHandler({ receiver, onEnvelope: () => {} });
  const big = "x".repeat(RAW_MAX_BYTES + 1);
  assert.equal((await h(post(big))).status, 413);
  // 申告をうのみにしない：読む途中で上限を超えたら止める
  let pulled = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      pulled++;
      if (pulled > 100) return c.close();
      c.enqueue(new Uint8Array(64 * 1024));
    },
  });
  const req = new Request(`https://hub.example${HTTP_PATH}`, { method: "POST", headers: { "content-type": "application/json" }, body: stream, duplex: "half" } as RequestInit);
  assert.equal(await readLimited(req, 200 * 1024), undefined);
  assert.ok(pulled < 10, "上限を超えた時点で読むのをやめる");
});

test("HTTP：処理中の失敗は 500 で返し、記録には本文を渡さない", async () => {
  const { sender, receiver } = await setup();
  const errors: unknown[] = [];
  const h = createHttpHandler({ receiver, onEnvelope: () => { throw new Error("内部"); }, onError: (i) => errors.push(i) });
  const e = await sender.make("record", "record.nsc.attendance", { b: "x" });
  const r = await h(post(JSON.stringify(e)));
  assert.equal(r.status, 500);
  assert.equal(errors.length, 1);
  assert.deepEqual(Object.keys(errors[0] as object).sort(), ["error", "id", "lane"]);
});

// ---- HTTP の送り口 ----

test("HTTP の送り口：受け口と組み合わせて届く。受け取り済みは届いたとみなす", async () => {
  const { sender, receiver, now } = await setup();
  const h = createHttpHandler({ receiver, onEnvelope: () => {} });
  const client = createHttpClient({ url: `https://hub.example${HTTP_PATH}`, fetch: h, now, sleep: async () => {} });
  const e = await sender.make("record", "record.nsc.attendance", { b: 1 });
  assert.deepEqual(await client.send(e), { ok: true, status: 202, duplicate: false, attempts: 1 });
  assert.deepEqual(await client.send(e), { ok: true, status: 409, duplicate: true, attempts: 1 });
});

test("HTTP の送り口：一時的な失敗は同じ封筒でやり直し、やり直せない失敗はすぐ止める", async () => {
  const { sender, now } = await setup();
  const bodies: string[] = [];
  let n = 0;
  const flaky = async (req: Request) => {
    bodies.push(await req.text());
    return ++n < 3 ? new Response("{}", { status: 503 }) : new Response(JSON.stringify({ ok: true }), { status: 202 });
  };
  const client = createHttpClient({ url: "https://hub.example/x", fetch: flaky, now, sleep: async () => {} });
  const e = await sender.make("event", "event.app.done", { b: 1 });
  const r = await client.send(e);
  assert.equal(r.ok, true);
  assert.equal(r.attempts, 3);
  assert.equal(new Set(bodies).size, 1, "毎回まったく同じ封筒を送る");

  const deny = createHttpClient({ url: "https://hub.example/x", fetch: async () => new Response(JSON.stringify({ ok: false, code: "BAD_SIGNATURE" }), { status: 401 }), now, sleep: async () => {} });
  assert.deepEqual(await deny.send(e), { ok: false, status: 401, code: "BAD_SIGNATURE", attempts: 1, reason: "NOT_RETRYABLE" });
});

test("HTTP の送り口：https 以外は断る（手元の開発だけ http 可）", () => {
  assert.throws(() => createHttpClient({ url: "http://hub.example/x", now: () => 0 }));
  assert.doesNotThrow(() => createHttpClient({ url: "http://localhost:8787/x", now: () => 0 }));
});

// ---- WebSocket ----

class FakeSocket {
  sent: string[] = [];
  closedWith: number | undefined;
  private handlers: Record<string, ((ev: { data: unknown }) => void)[]> = {};
  send(d: string) { this.sent.push(d); }
  close(code?: number) { this.closedWith = code; this.emit("close", {}); }
  addEventListener(type: string, fn: (ev: { data: unknown }) => void) { (this.handlers[type] ??= []).push(fn); }
  emit(type: string, ev: { data?: unknown }) { for (const f of this.handlers[type] ?? []) f(ev as { data: unknown }); }
}
const settle = () => new Promise((r) => setTimeout(r, 10));

test("WebSocket：1 通ずつ検査して、届いた順に処理する", async () => {
  const { sender, receiver } = await setup();
  const ws = new FakeSocket();
  const got: number[] = [];
  attachSocket(ws, { receiver, onEnvelope: async (e) => { await new Promise((r) => setTimeout(r, e.sq === 0 ? 5 : 0)); got.push(e.sq!); } });
  for (let i = 0; i < 3; i++) ws.emit("message", { data: JSON.stringify(await sender.make("stream", "stream.audio.opus", { id: seqId("stream-0001", i), sq: i })) });
  // 署名の確認と 5 ミリ秒の遅れを 3 通分待つ。決まった時間だけ待つと、混み合った時に間に合わないため、揃うまで待つ（最大 2 秒）
  for (let waited = 0; got.length < 3 && waited < 2000; waited += 10) await settle();
  assert.deepEqual(got, [0, 1, 2], "前の処理が遅くても順番を守る");
  assert.equal(ws.sent.length, 0);
});

test("WebSocket：この口で受けないレーン・不正な通信は断り、続いたら切る", async () => {
  const { sender, receiver } = await setup();
  const ws = new FakeSocket();
  const s = attachSocket(ws, { receiver, onEnvelope: () => {}, maxStrikes: 3 });
  ws.emit("message", { data: JSON.stringify(await sender.make("record", "record.nsc.attendance", { b: 1 })) });
  await settle();
  assert.equal(JSON.parse(ws.sent[0]!).code, "LANE_NOT_ON_SOCKET");
  ws.emit("message", { data: new Uint8Array(4) });
  ws.emit("message", { data: "{" });
  await settle();
  assert.equal(ws.closedWith, CLOSE_POLICY);
  assert.equal(s.closed, true);
  assert.throws(() => s.send({} as Envelope));
});

test("WebSocket：送るのは決めたレーンだけ", async () => {
  const { sender, receiver } = await setup();
  const ws = new FakeSocket();
  const s = attachSocket(ws, { receiver, onEnvelope: () => {} });
  s.send(await sender.make("ai", "ai.chat.reply", { id: seqId("reply-0001", 0), sq: 0, b: { d: "a" } }));
  assert.equal(ws.sent.length, 1);
  await assert.rejects(async () => s.send(await sender.make("record", "record.nsc.attendance", { b: 1 })));
});

// ---- 見本（Cloudflare Workers）----

test("見本の Worker：秘密の値の鍵で署名された封筒だけを受け付ける", async () => {
  const { default: worker } = await import("../examples/worker.ts");
  const { toBase64Url } = await import("../src/index.ts");
  const raw = rnd(32);
  const env = { LCH_SIGNING_KEY: toBase64Url(raw), LCH_COMPANY: "nsc" };
  const s = createSender({ co: "nsc", by: "u1", now: () => Date.now(), signingKey: await importSigningKey(raw) });
  const e = await s.make("event", "event.app.done", { b: { ok: 1 } });
  assert.equal((await worker.fetch(post(JSON.stringify(e)), env)).status, 202);
  const other = createSender({ co: "nsc", by: "u1", now: () => Date.now(), signingKey: await importSigningKey(rnd(32)) });
  const bad = await other.make("event", "event.app.done", { b: { ok: 1 } });
  assert.equal((await worker.fetch(post(JSON.stringify(bad)), env)).status, 401);
  const wrongCo = createSender({ co: "other", by: "u1", now: () => Date.now(), signingKey: await importSigningKey(raw) });
  assert.equal((await worker.fetch(post(JSON.stringify(await wrongCo.make("event", "event.app.done", { b: 1 }))), env)).status, 401);
});
