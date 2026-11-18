// 台数をまたぐ重複の記憶（規格書 第16章）。Durable Objects の代わりに、同じ動きの置き場所で確かめる
import { test } from "node:test";
import assert from "node:assert/strict";
import { type DedupeStorage, createDeviceVerifier, createWebDeviceKey, deviceProofHeader, storageFirst } from "../src/index.ts";
import { LchDedupeObject, createDurableDedupe } from "../adapters/cloudflare/dedupe.ts";

// Durable Objects の storage と同じ呼び方の置き場所（鍵の順に並べて返す）
function memoryStorage(): DedupeStorage & { m: Map<string, unknown> } {
  const m = new Map<string, unknown>();
  return {
    m,
    async get(k) { return m.get(k); },
    async put(k, v) { m.set(k, v); },
    async delete(keys) { let n = 0; for (const k of keys) if (m.delete(k)) n++; return n; },
    async list({ prefix, end, limit }) {
      return new Map([...m.entries()].filter(([k]) => k.startsWith(prefix) && k < end).sort(([a], [b]) => (a < b ? -1 : 1)).slice(0, limit));
    },
  };
}

// Durable Objects の名前空間の代わり：名前ごとに 1 つの物を作り、1 件ずつ処理する
function namespace() {
  const objects = new Map<string, { obj: LchDedupeObject; storage: ReturnType<typeof memoryStorage>; queue: Promise<unknown> }>();
  let calls = 0;
  return {
    objects,
    get calls() { return calls; },
    idFromName: (name: string) => name,
    get(id: unknown) {
      const name = String(id);
      if (!objects.has(name)) { const storage = memoryStorage(); objects.set(name, { obj: new LchDedupeObject({ storage }), storage, queue: Promise.resolve() }); }
      const o = objects.get(name)!;
      return {
        fetch(req: Request) {
          calls++;
          const p = o.queue.then(() => o.obj.fetch(req));
          o.queue = p.catch(() => {});
          return p;
        },
      };
    },
  };
}

test("置き場所の記憶：窓の中の 2 回目は通さず、窓を過ぎたら通す。古いものは少しずつ消える", async () => {
  const s = memoryStorage();
  assert.equal(await storageFirst(s, "a", 1_000, 100), true);
  assert.equal(await storageFirst(s, "a", 1_050, 100), false);
  assert.equal(await storageFirst(s, "a", 1_100, 100), true, "窓を過ぎたら新しく覚える");
  assert.equal(await storageFirst(s, "b", 1_150, 100), true);
  // a を 1_100 で見直したので、1_000 の並べ替えの鍵だけが消え、a の見出しは残る
  assert.equal(s.m.get("s:a"), 1_100);
  assert.equal(await storageFirst(s, "a", 1_150, 100), false);
  assert.equal(await storageFirst(s, "c", 5_000, 100), true);
  assert.deepEqual([...s.m.keys()].sort(), ["s:c", `t:${"5000".padStart(16, "0")}:c`], "窓を過ぎた a と b は消える");
});

test("Durable Objects：別々の台の受け口が、同じ記憶で同じ番号を 1 回だけ通す。同時に送られても 1 回だけ", async () => {
  const ns = namespace();
  const dA = createDurableDedupe({ namespace: ns, windowMs: 60_000 });
  const dB = createDurableDedupe({ namespace: ns, windowMs: 60_000 });
  const got = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? dA : dB).first("CO_A", "same-id", 1_000)));
  assert.equal(got.filter(Boolean).length, 1, "同時に 20 回来ても、通るのは 1 回だけ");
  assert.equal(await dA.first("CO_B", "same-id", 1_000), true, "会社が違えば別の番号");
  assert.deepEqual([...ns.objects.keys()].sort(), ["lch-dedupe:CO_A", "lch-dedupe:CO_B"], "既定は会社ごとに 1 つ");
});

test("Durable Objects：答えられないときは通さない。形の違う問い合わせは断る", async () => {
  const broken = { idFromName: (n: string) => n, get: () => ({ fetch: async () => new Response(null, { status: 500 }) }) };
  await assert.rejects(createDurableDedupe({ namespace: broken, windowMs: 1000 }).first("CO_A", "x", 1), /問い合わせられません/);
  const obj = new LchDedupeObject({ storage: memoryStorage() });
  assert.equal((await obj.fetch(new Request("https://x/first", { method: "POST", body: JSON.stringify({ key: "", now: 1, windowMs: 1 }) }))).status, 400);
  assert.equal((await obj.fetch(new Request("https://x/other", { method: "POST", body: "{}" }))).status, 404);
});

test("端末の確認：使い捨ての番号を台数をまたいで覚え、別の台での使い回しも断る", async () => {
  const ns = namespace();
  const key = await createWebDeviceKey();
  const directory = { keys: () => [{ pub: key.pub, use: "device" as const }] };
  const now = () => 1_800_000_000_000;
  const a = createDeviceVerifier({ directory, now, nonces: createDurableDedupe({ namespace: ns, windowMs: 300_000 }) });
  const b = createDeviceVerifier({ directory, now, nonces: createDurableDedupe({ namespace: ns, windowMs: 300_000 }) });
  const header = await deviceProofHeader(key, { method: "POST", path: "/lch/v1/user", token: "t", body: "{}", now: now() });
  const p = { header, method: "POST", path: "/lch/v1/user", token: "t", body: "{}", who: { co: "CO_A", by: "emp-1" } };
  assert.equal((await a.verify(p)).ok, true);
  const again = await b.verify(p);
  assert.equal(again.ok, false);
  assert.equal((again as { code: string }).code, "DEVICE_REPLAY", "別の台に送り直しても断る");
});
