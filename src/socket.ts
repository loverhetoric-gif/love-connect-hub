// 通信の口：WebSocket。規格書 第16章。
// 途切れなく流れるレーン（ストリーミング・同期・AI・イベント）に使う。
// 1 通ごとに受け口と同じ検査を通す。不正な通信が続く相手は切る。
// 標準の WebSocket の形（addEventListener・send・close）だけを使う：
// Cloudflare Workers のサーバー側（accept() 後）とブラウザ側の両方で使える。

import type { Envelope } from "./envelope.ts";
import type { LaneName } from "./lanes.ts";
import type { Receiver } from "./receiver.ts";

/** 使う WebSocket の最小の形 */
export interface SocketLike {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "message", fn: (ev: { data: unknown }) => void): void;
  addEventListener(type: "close", fn: () => void): void;
}

export const SOCKET_LANES_DEFAULT: readonly LaneName[] = Object.freeze(["stream", "sync", "ai", "event"]);

/** 規約違反で切るときの番号（WebSocket の 1008 = 方針違反） */
export const CLOSE_POLICY = 1008;

export interface SocketSessionOptions {
  receiver: Receiver;
  /** 受け口を通った封筒の処理 */
  onEnvelope: (env: Envelope) => void | Promise<void>;
  /** この口で受け付けるレーン（既定：ストリーミング・同期・AI・イベント） */
  lanes?: readonly LaneName[];
  /** 続けて拒否したら切る回数（既定 10） */
  maxStrikes?: number;
  /** 処理中の失敗を記録する（本文は渡さない） */
  onError?: (info: { id: string; lane: string; error: unknown }) => void;
}

export interface SocketSession {
  /** 封筒を送る（送る前に自分で検査済みのものを渡す） */
  send(env: Envelope): void;
  readonly closed: boolean;
}

export function attachSocket(ws: SocketLike, opts: SocketSessionOptions): SocketSession {
  const lanes = new Set(opts.lanes ?? SOCKET_LANES_DEFAULT);
  const maxStrikes = opts.maxStrikes ?? 10;
  let strikes = 0;
  let closed = false;
  // 届いた順に 1 通ずつ処理する（順番を守る）
  let chain: Promise<void> = Promise.resolve();

  const nack = (id: string, code: string, message: string) => {
    if (closed) return;
    ws.send(JSON.stringify({ ok: false, id, code, message }));
    if (++strikes >= maxStrikes) {
      closed = true;
      ws.close(CLOSE_POLICY, "too many rejected messages");
    }
  };

  ws.addEventListener("message", (ev) => {
    if (closed) return;
    const data = ev.data;
    chain = chain.then(async () => {
      if (closed) return;
      if (typeof data !== "string") return nack("", "BAD_FRAME", "文字の通信だけを受け付けます");
      const r = await opts.receiver.receive(data);
      if (!r.ok) return nack("", r.code, r.message);
      if (!lanes.has(r.env.l)) return nack(r.env.id, "LANE_NOT_ON_SOCKET", "このレーンは HTTP で送ってください");
      strikes = 0;
      try {
        await opts.onEnvelope(r.env);
      } catch (error) {
        opts.onError?.({ id: r.env.id, lane: r.env.l, error });
        nack(r.env.id, "HANDLER", "処理中に問題が起きました");
      }
    });
  });
  ws.addEventListener("close", () => {
    closed = true;
  });

  return {
    send(env) {
      if (closed) throw new Error("接続は閉じています");
      if (!lanes.has(env.l)) throw new Error("このレーンは HTTP で送ってください");
      ws.send(JSON.stringify(env));
    },
    get closed() {
      return closed;
    },
  };
}
