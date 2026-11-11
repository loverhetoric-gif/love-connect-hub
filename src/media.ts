// メディアの分割と組み立て。規格書 第3章・第12章。
// 本文は封筒に入れず、1 MiB ずつに分けて置き場所へ送る。
// 受け手は、順番が前後しても組み立て、最後に大きさとハッシュで照合してから使う。

import { MEDIA_CHUNK_BYTES } from "./lanes.ts";
import type { Envelope } from "./envelope.ts";
import { sha256Hex } from "./crypto.ts";

/** 片の数 */
export function partCount(len: number, chunk = MEDIA_CHUNK_BYTES): number {
  return len === 0 ? 1 : Math.ceil(len / chunk);
}

/** 片に分ける（写しを作らない） */
export function* splitMedia(bytes: Uint8Array, chunk = MEDIA_CHUNK_BYTES): Generator<{ sq: number; bytes: Uint8Array }> {
  const n = partCount(bytes.byteLength, chunk);
  for (let sq = 0; sq < n; sq++) yield { sq, bytes: bytes.subarray(sq * chunk, Math.min(bytes.byteLength, (sq + 1) * chunk)) };
}

/** 送る前に、大きさとハッシュを求める（封筒の len・h に入れる） */
export async function describeMedia(bytes: Uint8Array): Promise<{ len: number; h: string }> {
  return { len: bytes.byteLength, h: await sha256Hex(bytes) };
}

export type MediaAddResult = { ok: true; received: number; total: number } | { ok: false; code: string; message: string };

export interface MediaAssembler {
  add(sq: number, bytes: Uint8Array): MediaAddResult;
  readonly complete: boolean;
  /** 全部そろったら照合して中身を返す。合わなければ例外 */
  finish(): Promise<Uint8Array>;
}

/** 組み立てる。上限（既定 100 MiB）を超える大きさの封筒は、受け取る前に断る */
export function createMediaAssembler(
  env: Pick<Envelope, "len" | "h">,
  opts: { maxBytes?: number; chunk?: number } = {},
): MediaAssembler {
  const maxBytes = opts.maxBytes ?? 100 * 1024 * 1024;
  const chunk = opts.chunk ?? MEDIA_CHUNK_BYTES;
  if (env.len === undefined || env.h === undefined) throw new Error("大きさ（len）とハッシュ（h）が必要です");
  if (env.len > maxBytes) throw new Error("受け取れる大きさを超えています");
  const len = env.len;
  const h = env.h;
  const total = partCount(len, chunk);
  const buf = new Uint8Array(len); // 大きさは上で確かめてから確保する
  const got = new Set<number>();

  return {
    add(sq, bytes) {
      if (!Number.isInteger(sq) || sq < 0 || sq >= total) return { ok: false, code: "BAD_PART", message: "片の番号が範囲外です" };
      if (got.has(sq)) return { ok: false, code: "DUPLICATE_PART", message: "同じ片が二度届きました" };
      const expect = sq === total - 1 ? len - sq * chunk : chunk;
      if (bytes.byteLength !== expect) return { ok: false, code: "BAD_SIZE", message: "片の大きさが合いません" };
      buf.set(bytes, sq * chunk);
      got.add(sq);
      return { ok: true, received: got.size, total };
    },
    get complete() {
      return got.size === total;
    },
    async finish() {
      if (got.size !== total) throw new Error("まだ全部の片が届いていません");
      if ((await sha256Hex(buf)) !== h) throw new Error("ハッシュが一致しません");
      return buf;
    },
  };
}
