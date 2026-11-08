// LOVE connect HUB の入口。外部部品なし。
export * from "./lanes.ts";
export * from "./envelope.ts";
export * from "./crypto.ts";
export * from "./dedupe.ts";
export * from "./sender.ts";
export * from "./receiver.ts";
export * from "./batch.ts";
export * from "./media.ts";

import { LANES } from "./lanes.ts";
import type { Envelope } from "./envelope.ts";

/**
 * 処理の順番を決める比較。優先度の高いレーン → 締め切りの早いもの → 古いもの の順。
 * 混み合ったときに、遅れると価値がなくなるものから先に通す（レスポンスの原則）。
 */
export function compareUrgency(a: Envelope, b: Envelope): number {
  const p = LANES[a.l].priority - LANES[b.l].priority;
  if (p !== 0) return p;
  const da = dueOf(a);
  const db = dueOf(b);
  if (da !== db) return da < db ? -1 : 1;
  return a.at - b.at;
}

/** 締め切りの時刻。締め切りなしは最後に回す */
function dueOf(env: Envelope): number {
  const dl = env.dl ?? LANES[env.l].deadlineMs;
  return dl > 0 ? env.at + dl : Number.POSITIVE_INFINITY;
}
