// Cloudflare Durable Objects に置く、台数をまたぐ重複の記憶（規格書 第16章・第2版の計画 A の 1）。
// 中核部品（src/）は Cloudflare に依存しないため、ここに分けて置く（作業規約）。
// 1 つの Durable Object は名前ごとに 1 か所でしか動かず、1 件ずつ処理するので、同じ番号を 2 台が同時に「初めて」と答えることがない。
//
// 使い方（wrangler の設定）:
//   [[durable_objects.bindings]]
//   name = "LCH_DEDUPE"
//   class_name = "LchDedupeObject"
//   [[migrations]]
//   tag = "lch-dedupe-v1"
//   new_sqlite_classes = ["LchDedupeObject"]
// Worker の入口から `export { LchDedupeObject } from "…/adapters/cloudflare/dedupe.ts"` で書き出す。

import { type DedupeStorage, type SharedDedupe, storageFirst } from "../../src/dedupe.ts";

/** Durable Objects の名前空間のうち、使う分だけ */
export interface DedupeNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

/** Durable Object の状態のうち、使う分だけ */
export interface DedupeState {
  storage: DedupeStorage;
}

const ORIGIN = "https://lch-dedupe.internal";
const KEY_MAX = 512;

/** 重複の記憶の Durable Object。呼べるのは同じ Worker の中からだけ（外へは公開しない） */
export class LchDedupeObject {
  private readonly state: DedupeState;
  constructor(state: DedupeState, _env?: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/first") return new Response(null, { status: 404 });
    let o: { key?: unknown; now?: unknown; windowMs?: unknown };
    try {
      o = (await request.json()) as typeof o;
    } catch {
      return new Response(null, { status: 400 });
    }
    const { key, now, windowMs } = o;
    if (typeof key !== "string" || key.length === 0 || key.length > KEY_MAX || !Number.isSafeInteger(now) || !Number.isSafeInteger(windowMs) || (windowMs as number) <= 0) {
      return new Response(null, { status: 400 });
    }
    const first = await storageFirst(this.state.storage, key, now as number, windowMs as number);
    return Response.json({ first });
  }
}

export interface DurableDedupeOptions {
  namespace: DedupeNamespace;
  /** 覚えておく時間（ミリ秒） */
  windowMs: number;
  /**
   * どの Durable Object に置くか。既定は会社ごとに 1 つ（会社の中では取り合いが起きない）。
   * 1 つの会社の送信が多いときは、会社＋利用者などで分けてよい（分け方を変えると、変える前の記憶は引き継がれない）
   */
  shard?: (co: string, id: string) => string;
}

/** 台数をまたぐ重複の記憶。受け口・利用者の口・端末の確認の dedupe / nonces に渡す */
export function createDurableDedupe(opts: DurableDedupeOptions): SharedDedupe {
  const shard = opts.shard ?? ((co: string) => co);
  return {
    async first(co, id, now) {
      const stub = opts.namespace.get(opts.namespace.idFromName(`lch-dedupe:${shard(co, id)}`));
      const res = await stub.fetch(
        new Request(`${ORIGIN}/first`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: `${co}\u0000${id}`, now, windowMs: opts.windowMs }) }),
      );
      // 答えられないときは通さない（機密性を先にする。規格書 第1章）
      if (!res.ok) throw new Error(`重複の記憶に問い合わせられません（${res.status}）`);
      const body = (await res.json()) as { first?: unknown };
      return body.first === true;
    },
  };
}
