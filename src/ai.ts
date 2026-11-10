// AI の逐次受け取り。規格書 第15章。
// AI の応答は断片で届く。番号は「まとまり番号_順番」、本文は { d: 文字の追加分 }。
// 最後は「まとまり番号_end」で、本文は { n: 断片の数, u?: { in, out } 使った量 }。
// 順番が前後しても、つながった分から先に返す（画面にすぐ出せる：レスポンスの原則）。

import type { Envelope } from "./envelope.ts";
import { parseSeqId } from "./seq.ts";

export interface AiUsage {
  /** 入力の量（トークン） */
  in: number;
  /** 出力の量（トークン） */
  out: number;
}

export type AiState =
  | { state: "partial"; delta: string; text: string }
  | { state: "done"; delta: string; text: string; usage?: AiUsage }
  | { state: "error"; code: string; message: string };

export interface AiAssembler {
  /** 受け口を通った封筒を渡す。delta は今回新しくつながった文字 */
  add(env: Envelope): AiState;
  readonly text: string;
}

/** 断片の本文を作る（送り手用） */
export function aiDelta(d: string): { d: string } {
  return { d };
}

/** 終わりの本文を作る（送り手用） */
export function aiEnd(n: number, usage?: AiUsage): { n: number; u?: AiUsage } {
  return usage ? { n, u: usage } : { n };
}

export function createAiAssembler(opts: { maxChars?: number; maxParts?: number } = {}): AiAssembler {
  const maxChars = opts.maxChars ?? 1_000_000;
  const maxParts = opts.maxParts ?? 100_000;
  const pending = new Map<number, string>();
  let group: string | undefined;
  let next = 0;
  let text = "";
  let total: number | undefined;
  let usage: AiUsage | undefined;
  let finished = false;

  const err = (code: string, message: string): AiState => ({ state: "error", code, message });

  function advance(): string {
    let delta = "";
    for (let s = pending.get(next); s !== undefined; s = pending.get(next)) {
      pending.delete(next);
      delta += s;
      next++;
    }
    text += delta;
    return delta;
  }

  function result(delta: string): AiState {
    if (total !== undefined && next === total) {
      finished = true;
      return usage ? { state: "done", delta, text, usage } : { state: "done", delta, text };
    }
    return { state: "partial", delta, text };
  }

  return {
    add(env) {
      if (finished) return err("FINISHED", "この応答は受け取り済みです");
      if (env.l !== "ai") return err("BAD_LANE", "AI レーンの封筒ではありません");
      const p = parseSeqId(env.id);
      if (!p) return err("BAD_ID", "断片の番号の形ではありません");
      if (group === undefined) group = p.group;
      else if (group !== p.group) return err("OTHER_GROUP", "別の応答の断片です");
      const b = env.b as { d?: unknown; n?: unknown; u?: { in?: unknown; out?: unknown } } | undefined;

      if (p.sq === "end") {
        if (total !== undefined) return err("DUPLICATE_END", "終わりの封筒が二度届きました");
        if (!b || !Number.isInteger(b.n) || (b.n as number) < 0 || (b.n as number) > maxParts) {
          return err("BAD_END", "終わりの封筒には断片の数（n）が必要です");
        }
        const n = b.n as number;
        if (next > n || [...pending.keys()].some((k) => k >= n)) return err("BAD_PART", "断片の数が合いません");
        if (b.u !== undefined) {
          if (!Number.isInteger(b.u.in) || !Number.isInteger(b.u.out) || (b.u.in as number) < 0 || (b.u.out as number) < 0) {
            return err("BAD_END", "使った量（u）の形が正しくありません");
          }
          usage = { in: b.u.in as number, out: b.u.out as number };
        }
        total = n;
        return result("");
      }

      const sq = p.sq;
      if (env.sq !== sq) return err("BAD_PART", "番号と順番（sq）が一致しません");
      if (sq >= maxParts || (total !== undefined && sq >= total)) return err("BAD_PART", "断片の番号が範囲外です");
      if (sq < next || pending.has(sq)) return err("DUPLICATE_PART", "同じ断片が二度届きました");
      if (!b || typeof b.d !== "string") return err("BAD_PART", "断片の本文は { d: 文字 } です");
      let size = text.length + b.d.length;
      for (const s of pending.values()) size += s.length;
      if (size > maxChars) return err("TOO_LARGE", "応答が大きすぎます");
      pending.set(sq, b.d);
      return result(advance());
    },
    get text() {
      return text;
    },
  };
}
