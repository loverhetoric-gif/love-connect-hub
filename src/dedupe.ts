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
