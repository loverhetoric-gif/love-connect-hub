// 重複防止。同じ会社・同じ番号（id）の封筒は、決めた時間のあいだ一度だけ通す。
// 記憶の量に上限を設け、古いものから忘れる（軽さの原則）。

export interface Dedupe {
  /** 初めてなら true を返して覚える。見たことがあれば false */
  first(co: string, id: string, now: number): boolean;
  readonly size: number;
}

export function createDedupe(opts: { windowMs: number; capacity: number }): Dedupe {
  const { windowMs, capacity } = opts;
  if (!(windowMs > 0) || !(capacity > 0)) throw new Error("windowMs と capacity は正の数です");
  // Map は入れた順を保つので、先頭が最も古い
  const seen = new Map<string, number>();

  function sweep(now: number): void {
    for (const [k, t] of seen) {
      if (now - t < windowMs && seen.size <= capacity) break;
      seen.delete(k);
    }
  }

  return {
    first(co, id, now) {
      const k = `${co}\u0000${id}`;
      const t = seen.get(k);
      if (t !== undefined && now - t < windowMs) return false;
      if (t !== undefined) seen.delete(k);
      seen.set(k, now);
      sweep(now);
      return true;
    },
    get size() {
      return seen.size;
    },
  };
}

// ---- 台数をまたぐ重複の記憶（規格書 第16章）----
// Workers の実行は台数・拠点をまたいで並ぶため、手元の記憶（createDedupe）だけでは同じ番号が別の台で 2 回通りうる。
// 名前ごとに 1 か所でしか動かず、1 件ずつ処理する置き場所（Cloudflare Durable Objects など）に記憶を置くと、取り合いが起きない。

/** 台数をまたいで使える重複の記憶。答えを待つ形 */
export interface SharedDedupe {
  /** 初めてなら true を返して覚える。見たことがあれば false */
  first(co: string, id: string, now: number): Promise<boolean>;
}

/** 手元の記憶と台数をまたぐ記憶の、どちらでも受け付ける */
export type AnyDedupe = Dedupe | SharedDedupe;

/** 重複の記憶を置く場所の形（Durable Objects の storage と同じ呼び方の一部） */
export interface DedupeStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: number): Promise<void>;
  delete(keys: string[]): Promise<number>;
  list(options: { prefix: string; end: string; limit: number }): Promise<Map<string, unknown>>;
}

const pad = (n: number) => String(Math.max(0, Math.floor(n))).padStart(16, "0");

/**
 * 置き場所を使った重複の確かめ。1 件ずつ処理される置き場所（Durable Objects の 1 つ）の中で呼ぶ。
 * 見出しの鍵 s:<鍵> に最後に見た時刻、並べ替え用の鍵 t:<時刻>:<鍵> を置き、窓を過ぎたものを古い順に少しずつ消す
 */
export async function storageFirst(storage: DedupeStorage, key: string, now: number, windowMs: number, sweepLimit = 128): Promise<boolean> {
  if (!(windowMs > 0)) throw new Error("windowMs は正の数です");
  const seen = await storage.get(`s:${key}`);
  if (typeof seen === "number" && now - seen < windowMs) return false;
  await storage.put(`s:${key}`, now);
  await storage.put(`t:${pad(now)}:${key}`, now);
  // 窓を過ぎたものを消す（その鍵が後で見直されていれば、見出しの鍵は残す）
  const old = await storage.list({ prefix: "t:", end: `t:${pad(now - windowMs)}`, limit: sweepLimit });
  const drop: string[] = [];
  for (const [k, t] of old) {
    const rest = k.slice(2 + 16 + 1);
    if ((await storage.get(`s:${rest}`)) === t) drop.push(`s:${rest}`);
    drop.push(k);
  }
  if (drop.length) await storage.delete(drop);
  return true;
}
