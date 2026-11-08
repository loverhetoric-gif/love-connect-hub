// レコードの一括（大量の取り込み・書き出し・移行）。規格書 第3章・第12章。
// 行を本文の上限に収まるように分け、番号「一括番号_順番」で送り、
// 最後に「一括番号_end」で件数とハッシュを送る。受け手は全部そろってから照合する。

import type { Envelope } from "./envelope.ts";
import { bodyBytes } from "./envelope.ts";
import { LANES } from "./lanes.ts";
import { canonicalJson, sha256Hex } from "./crypto.ts";

const BATCH_ID_RE = /^[A-Za-z0-9-]{8,48}$/;
const PART_RE = /^([A-Za-z0-9-]{8,48})_(\d{1,9}|end)$/;

/** 分けた 1 片に使える本文の大きさ（余白を残す） */
export const BATCH_PART_BYTES = LANES.record.inlineMax - 1024;

export interface BatchPlan {
  /** 各片の行 */
  parts: unknown[][];
  /** 全件数 */
  rows: number;
  /** 全行のハッシュ（決まった並びの JSON） */
  h: string;
}

export function partId(batchId: string, sq: number | "end"): string {
  if (!BATCH_ID_RE.test(batchId)) throw new Error("一括番号は英数字とハイフンの 8〜48 字です");
  return `${batchId}_${sq}`;
}

/** 行を片に分ける。1 行で上限を超えるものはメディアか置き場所で渡す */
export async function planBatch(rows: readonly unknown[], maxBytes = BATCH_PART_BYTES): Promise<BatchPlan> {
  const parts: unknown[][] = [];
  let cur: unknown[] = [];
  let size = 2; // "[]"
  for (const row of rows) {
    const n = bodyBytes(row) + 1; // 区切りの ,
    if (n + 2 > maxBytes) throw new Error("1 行が大きすぎて分けられません");
    if (size + n > maxBytes) {
      parts.push(cur);
      cur = [];
      size = 2;
    }
    cur.push(row);
    size += n;
  }
  if (cur.length) parts.push(cur);
  return { parts, rows: rows.length, h: await sha256Hex(canonicalJson(rows)) };
}

export type BatchState =
  | { state: "partial"; received: number }
  | { state: "done"; batchId: string; rows: unknown[] }
  | { state: "error"; code: string; message: string };

export interface BatchAssembler {
  /** 受け口を通った封筒を渡す */
  add(env: Envelope): Promise<BatchState>;
}

/** 一括を組み立てる。1 つの一括番号ごとに 1 つ作る */
export function createBatchAssembler(opts: { maxParts?: number; maxRows?: number } = {}): BatchAssembler {
  const maxParts = opts.maxParts ?? 10_000;
  const maxRows = opts.maxRows ?? 1_000_000;
  const parts = new Map<number, unknown[]>();
  let batchId: string | undefined;
  let end: { parts: number; rows: number; h: string } | undefined;
  let rowCount = 0;
  let finished = false;

  const err = (code: string, message: string): BatchState => ({ state: "error", code, message });

  async function tryFinish(): Promise<BatchState> {
    if (!end || parts.size < end.parts) return { state: "partial", received: parts.size };
    const rows: unknown[] = [];
    for (let i = 0; i < end.parts; i++) {
      const p = parts.get(i);
      if (!p) return { state: "partial", received: parts.size };
      for (const r of p) rows.push(r);
    }
    if (rows.length !== end.rows) return err("COUNT_MISMATCH", "件数が一致しません");
    if ((await sha256Hex(canonicalJson(rows))) !== end.h) return err("HASH_MISMATCH", "ハッシュが一致しません");
    finished = true;
    return { state: "done", batchId: batchId!, rows };
  }

  return {
    async add(env) {
      if (finished) return err("FINISHED", "この一括は組み立て済みです");
      if (env.l !== "record") return err("BAD_LANE", "一括はレコードレーンだけです");
      const m = PART_RE.exec(env.id);
      if (!m) return err("BAD_ID", "一括の番号の形ではありません");
      if (batchId === undefined) batchId = m[1];
      else if (batchId !== m[1]) return err("OTHER_BATCH", "別の一括の封筒です");

      if (m[2] === "end") {
        const b = env.b as { parts?: unknown; rows?: unknown } | undefined;
        if (end) return err("DUPLICATE_END", "終わりの封筒が二度届きました");
        if (!b || !Number.isInteger(b.parts) || !Number.isInteger(b.rows) || typeof env.h !== "string") {
          return err("BAD_END", "終わりの封筒には parts・rows・h が必要です");
        }
        const p = b.parts as number;
        const r = b.rows as number;
        if (p < 0 || p > maxParts || r < 0 || r > maxRows) return err("TOO_LARGE", "一括が大きすぎます");
        if (parts.size > p || [...parts.keys()].some((k) => k >= p)) return err("BAD_PART", "片の数が合いません");
        end = { parts: p, rows: r, h: env.h };
        return tryFinish();
      }

      const sq = Number(m[2]);
      if (env.sq !== sq) return err("BAD_PART", "番号と順番（sq）が一致しません");
      if (sq >= maxParts || (end && sq >= end.parts)) return err("BAD_PART", "片の番号が範囲外です");
      if (parts.has(sq)) return err("DUPLICATE_PART", "同じ片が二度届きました");
      if (!Array.isArray(env.b)) return err("BAD_PART", "片の本文は行の並びです");
      rowCount += env.b.length;
      if (rowCount > maxRows) return err("TOO_LARGE", "一括が大きすぎます");
      parts.set(sq, env.b);
      return tryFinish();
    },
  };
}
