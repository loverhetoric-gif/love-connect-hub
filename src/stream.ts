// ストリーミングの並べ直し。規格書 第15章。
// 届いた片を順番（sq）どおりに渡す。欠けた片は決めた時間だけ待ち、来なければ飛ばす。
// 渡し済みより前の片が遅れて届いたら捨てる（遅れより途切れを選ぶ：レスポンスの原則）。

import type { Envelope } from "./envelope.ts";

export interface StreamStats {
  /** 渡した片 */
  delivered: number;
  /** 遅れて届いて捨てた片 */
  late: number;
  /** 二重に届いて捨てた片 */
  duplicate: number;
  /** 待っても来ずに飛ばした番号の数 */
  skipped: number;
  /** 置き場所があふれて捨てた片 */
  overflow: number;
}

export interface StreamReorder {
  /** 片を受け取り、順番どおりに渡せる片を返す */
  push(env: Envelope, now: number): Envelope[];
  /** 時間が来た欠けを飛ばし、渡せる片を返す（定期的に呼ぶ） */
  flush(now: number): Envelope[];
  /** 次に渡す番号（まだ始まっていなければ undefined） */
  readonly next: number | undefined;
  readonly stats: Readonly<StreamStats>;
}

export interface StreamReorderOptions {
  /** 欠けた片を待つ時間（ミリ秒、既定 200） */
  waitMs?: number;
  /** 待たせておける片の数（既定 256）。超えたら欠けを飛ばして先へ進む */
  maxBuffered?: number;
}

export function createStreamReorder(opts: StreamReorderOptions = {}): StreamReorder {
  const waitMs = opts.waitMs ?? 200;
  const maxBuffered = opts.maxBuffered ?? 256;
  if (!(waitMs >= 0) || !(maxBuffered > 0)) throw new Error("waitMs と maxBuffered の値が正しくありません");

  const buf = new Map<number, Envelope>();
  let next: number | undefined;
  /** 今の欠けを待ち始めた時刻 */
  let gapSince: number | undefined;
  const stats: StreamStats = { delivered: 0, late: 0, duplicate: 0, skipped: 0, overflow: 0 };

  function drain(now: number): Envelope[] {
    const out: Envelope[] = [];
    for (;;) {
      if (next === undefined) break;
      const e = buf.get(next);
      if (e) {
        buf.delete(next);
        out.push(e);
        next++;
        gapSince = undefined;
        continue;
      }
      if (buf.size === 0) break;
      // 欠けがある。待ち時間を過ぎたか、置き場所があふれたら、いちばん近い片まで飛ばす
      if (gapSince === undefined) gapSince = now;
      if (now - gapSince >= waitMs || buf.size > maxBuffered) {
        let min = Number.POSITIVE_INFINITY;
        for (const k of buf.keys()) if (k < min) min = k;
        stats.skipped += min - next;
        next = min;
        gapSince = undefined;
        continue;
      }
      break;
    }
    stats.delivered += out.length;
    return out;
  }

  return {
    push(env, now) {
      const sq = env.sq;
      if (sq === undefined) throw new Error("ストリーミングの片には順番（sq）が必要です");
      // 途中から受け取り始めてよい：最初に届いた片から始める
      if (next === undefined) next = sq;
      if (sq < next) {
        stats.late++;
        return [];
      }
      if (buf.has(sq)) {
        stats.duplicate++;
        return [];
      }
      buf.set(sq, env);
      if (buf.size > maxBuffered * 2) {
        // 異常に先の番号ばかり届くときの守り：いちばん先の片を捨てる
        let max = -1;
        for (const k of buf.keys()) if (k > max) max = k;
        buf.delete(max);
        stats.overflow++;
      }
      return drain(now);
    },
    flush(now) {
      return drain(now);
    },
    get next() {
      return next;
    },
    get stats() {
      return stats;
    },
  };
}
