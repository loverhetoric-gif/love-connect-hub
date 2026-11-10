// 通信の口：HTTP。規格書 第16章。
// 標準の Request / Response / fetch だけで書く（Cloudflare Workers・Node.js・ブラウザで同じように動く）。

import type { Envelope } from "./envelope.ts";
import { RAW_MAX_BYTES, type ReceiveCode, type Receiver } from "./receiver.ts";
import { withRetry, type RetryOptions, type RetryResult } from "./api.ts";
import { LANES } from "./lanes.ts";

/** 既定の入口のパス */
export const HTTP_PATH = "/lch/v1/envelope";

/** 拒否の名前と HTTP の状態番号の対応。やり直して意味のある失敗だけを 5xx・429 にしない */
export const HTTP_STATUS: Readonly<Record<ReceiveCode | "METHOD" | "NOT_FOUND" | "CONTENT_TYPE" | "HANDLER", number>> = Object.freeze({
  TOO_LARGE: 413,
  HEADER_TOO_LARGE: 413,
  BODY_TOO_LARGE: 413,
  BAD_JSON: 400,
  NOT_OBJECT: 400,
  UNKNOWN_FIELD: 400,
  BAD_VERSION: 400,
  BAD_LANE: 400,
  BAD_FIELD: 400,
  MISSING_FIELD: 400,
  BODY_FORBIDDEN: 400,
  BODY_AND_REF: 400,
  FUTURE_TIME: 400,
  FORMAT_NOT_ALLOWED: 403,
  CLASS_TOO_LOW: 403,
  ENCRYPTION_REQUIRED: 403,
  SIGNATURE_REQUIRED: 401,
  NO_KEY: 401,
  BAD_SIGNATURE: 401,
  EXPIRED: 410,
  DUPLICATE: 409,
  METHOD: 405,
  NOT_FOUND: 404,
  CONTENT_TYPE: 415,
  HANDLER: 500,
});

const SECURITY_HEADERS: Record<string, string> = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...SECURITY_HEADERS, ...extra } });
}

function reject(code: keyof typeof HTTP_STATUS, field: string, message: string): Response {
  return json(HTTP_STATUS[code], { ok: false, code, field, message });
}

/**
 * 本文を上限まで読む。上限を超えた時点で読むのをやめる（全部を受け取ってから断らない）。
 * Content-Length の申告は先に確かめるが、申告をうのみにはしない。
 */
export async function readLimited(req: Request, max: number): Promise<string | undefined> {
  const declared = Number(req.headers.get("content-length") ?? "NaN");
  if (Number.isFinite(declared) && declared > max) return undefined;
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => {});
      return undefined;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(all);
}

export interface HttpHandlerOptions {
  /** 受け口（createReceiver で作る） */
  receiver: Receiver;
  /** 受け口を通った封筒の処理。返した封筒は応答として返す（無ければ 202） */
  onEnvelope: (env: Envelope) => Promise<Envelope | void> | Envelope | void;
  /** 入口のパス（既定 /lch/v1/envelope） */
  path?: string;
  /** 処理中の失敗を記録する（本文は渡さない） */
  onError?: (info: { id: string; lane: string; error: unknown }) => void;
}

/** HTTP の受け口。Cloudflare Workers なら fetch(request) からそのまま呼ぶ */
export function createHttpHandler(opts: HttpHandlerOptions): (req: Request) => Promise<Response> {
  const path = opts.path ?? HTTP_PATH;
  return async (req) => {
    const url = new URL(req.url);
    if (url.pathname !== path) return reject("NOT_FOUND", "", "入口が違います");
    if (req.method !== "POST") return new Response(null, { status: 405, headers: { ...SECURITY_HEADERS, allow: "POST" } });
    const type = (req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") return reject("CONTENT_TYPE", "", "application/json で送ってください");

    const raw = await readLimited(req, RAW_MAX_BYTES);
    if (raw === undefined) return reject("TOO_LARGE", "", "受け取れる大きさを超えています");

    const r = await opts.receiver.receive(raw);
    if (!r.ok) return reject(r.code, r.field, r.message);

    try {
      const reply = await opts.onEnvelope(r.env);
      if (reply) return json(200, { ok: true, env: reply });
      return json(202, { ok: true, id: r.env.id });
    } catch (error) {
      opts.onError?.({ id: r.env.id, lane: r.env.l, error });
      return reject("HANDLER", "", "処理中に問題が起きました");
    }
  };
}

export interface HttpClientOptions extends Omit<RetryOptions, "deadlineAt"> {
  /** 送り先の入口（https のみ。開発時の localhost は可） */
  url: string;
  /** 通信の関数（既定は標準の fetch） */
  fetch?: (req: Request) => Promise<Response>;
}

export type SendResult =
  | { ok: true; status: number; reply?: Envelope; duplicate: boolean; attempts: number }
  | { ok: false; status: number; code?: string; attempts: number; reason: string };

/** HTTP の送り口。一時的な失敗だけを同じ封筒でやり直す。受け取り済み（409）は届いたとみなす */
export function createHttpClient(opts: HttpClientOptions): { send(env: Envelope): Promise<SendResult> } {
  const u = new URL(opts.url);
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new Error("送り先は https にしてください");
  const doFetch = opts.fetch ?? ((r: Request) => fetch(r));

  return {
    async send(env) {
      const body = JSON.stringify(env);
      const dl = env.dl ?? LANES[env.l].deadlineMs;
      let lastCode: string | undefined;
      const res: RetryResult<{ status: number; reply?: Envelope; duplicate: boolean }> = await withRetry(
        async () => {
          const resp = await doFetch(new Request(u, { method: "POST", headers: { "content-type": "application/json" }, body }));
          const status = resp.status;
          let data: { ok?: boolean; code?: string; env?: Envelope } = {};
          try {
            data = (await resp.json()) as typeof data;
          } catch {
            /* 本文が JSON でなくても状態番号で判断する */
          }
          lastCode = data.code;
          if (status === 409 && data.code === "DUPLICATE") return { status: 200, value: { status, duplicate: true } };
          if (status >= 200 && status <= 299) {
            const value = data.env ? { status, reply: data.env, duplicate: false } : { status, duplicate: false };
            return { status, value };
          }
          const ra = Number(resp.headers.get("retry-after") ?? "NaN");
          return Number.isFinite(ra) ? { status, retryAfterSec: ra } : { status };
        },
        { ...opts, ...(dl > 0 ? { deadlineAt: env.at + dl } : {}) },
      );
      if (res.ok) return { ok: true, ...res.value, attempts: res.attempts };
      return lastCode
        ? { ok: false, status: res.status, code: lastCode, attempts: res.attempts, reason: res.reason }
        : { ok: false, status: res.status, attempts: res.attempts, reason: res.reason };
    },
  };
}
