// Cloudflare に置く、映像・音声の部屋と中継（TURN）の許可（規格書 第23章）。中核部品（src/）は Cloudflare に依存しないため、ここに分けて置く。
//
// 使い方（wrangler の設定）:
//   [[durable_objects.bindings]]
//   name = "LCH_RTC"
//   class_name = "LchRtcRoomObject"
//   [[migrations]]
//   tag = "lch-rtc-v1"
//   new_sqlite_classes = ["LchRtcRoomObject"]
// 秘密の値：TURN_KEY_ID・TURN_KEY_API_TOKEN（Cloudflare Realtime の TURN の鍵。無ければ直接だけでつなぐ）
//
// Worker の入口は、ログインのトークンと端末の証明（第18章・第21章）で本人を確かめてから、rtcRoomRequest で部屋へ渡す。
// 部屋の Durable Object は外へ公開しない（Worker の中からだけ呼ぶ）ので、Worker が付けた本人の見出しをそのまま信じてよい。

import { createRtcRoom, type RtcPeer, type RtcPurpose, type RtcRoom } from "../../src/rtc-room.ts";
import { type IceServer, sanitizeIceServers, TURN_TTL_SEC } from "../../src/rtc.ts";

/** Cloudflare Realtime の TURN から、期限つきの許可をもらう（WARPHOLE の relay/src/turn.ts と同じ）。失敗したら null */
export function cloudflareTurn(keyId: string, token: string, fetcher: typeof fetch = fetch): () => Promise<{ servers: IceServer[]; ttl: number } | null> {
  return async () => {
    const res = await fetcher(`https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ ttl: TURN_TTL_SEC }),
    });
    if (!res.ok) return null;
    const servers = sanitizeIceServers(await res.json());
    return servers.length > 0 ? { servers, ttl: TURN_TTL_SEC } : null;
  };
}

const ROOM_RE = /^[A-Za-z0-9_-]{8,64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const PUB_RE = /^[A-Za-z0-9_-]{87}$/;
const H = { co: "x-lch-rtc-co", by: "x-lch-rtc-by", pub: "x-lch-rtc-pub", name: "x-lch-rtc-name", purpose: "x-lch-rtc-purpose" } as const;

export interface RtcNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

/**
 * Worker の入口から呼ぶ：確かめた本人を見出しに付けて、会社ごとの部屋（Durable Object）へ WebSocket の接続を渡す。
 * 部屋の名前は「会社 ID:部屋の番号」なので、別の会社の部屋には入れない
 */
export function rtcRoomRequest(p: { request: Request; namespace: RtcNamespace; room: string; purpose: RtcPurpose; who: RtcPeer }): Promise<Response> | Response {
  if (p.request.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("websocket only\n", { status: 426 });
  if (!ROOM_RE.test(p.room) || !ID_RE.test(p.who.co) || !ID_RE.test(p.who.by) || !PUB_RE.test(p.who.pub)) return new Response(null, { status: 400 });
  const headers = new Headers(p.request.headers);
  for (const k of Object.values(H)) headers.delete(k);
  headers.set(H.co, p.who.co);
  headers.set(H.by, p.who.by);
  headers.set(H.pub, p.who.pub);
  headers.set(H.purpose, p.purpose);
  if (p.who.name) headers.set(H.name, encodeURIComponent(p.who.name.slice(0, 64)));
  const stub = p.namespace.get(p.namespace.idFromName(`${p.who.co}:${p.room}`));
  return stub.fetch(new Request(p.request.url, { method: "GET", headers }));
}

interface CfSocket {
  accept(): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "message", fn: (ev: { data: unknown }) => void): void;
  addEventListener(type: "close" | "error", fn: () => void): void;
}
declare const WebSocketPair: { new (): { 0: CfSocket; 1: CfSocket } };

/** 映像・音声の部屋の Durable Object（1 つの会議・遠隔支援につき 1 つ） */
export class LchRtcRoomObject {
  private room: RtcRoom | undefined;
  private readonly env: { TURN_KEY_ID?: string; TURN_KEY_API_TOKEN?: string };
  constructor(_state: unknown, env?: { TURN_KEY_ID?: string; TURN_KEY_API_TOKEN?: string }) {
    this.env = env ?? {};
  }

  async fetch(request: Request): Promise<Response> {
    const h = request.headers;
    const co = h.get(H.co) ?? "", by = h.get(H.by) ?? "", pub = h.get(H.pub) ?? "";
    const purpose = h.get(H.purpose) === "assist" ? "assist" : "meeting";
    if (!ID_RE.test(co) || !ID_RE.test(by) || !PUB_RE.test(pub)) return new Response(null, { status: 400 });
    // 部屋の用途と会社は、最初に入った人のもので決まる
    const { TURN_KEY_ID, TURN_KEY_API_TOKEN } = this.env;
    this.room ??= createRtcRoom({ co, purpose, now: () => Date.now(), ...(TURN_KEY_ID && TURN_KEY_API_TOKEN ? { turn: cloudflareTurn(TURN_KEY_ID, TURN_KEY_API_TOKEN) } : {}) });
    const pair = new WebSocketPair();
    const client = pair[0], server = pair[1];
    server.accept();
    const name = h.get(H.name);
    const peer: RtcPeer = { co, by, pub, ...(name ? { name: decodeURIComponent(name) } : {}) };
    const sink = { send: (t: string) => server.send(t), close: (c: number, r: string) => server.close(c, r) };
    const room = this.room;
    if (!room.join(peer, sink).ok) return new Response(null, { status: 101, webSocket: client } as ResponseInit);
    server.addEventListener("message", (ev) => { if (typeof ev.data === "string") void room.receive(pub, ev.data); });
    const bye = () => room.leave(pub, sink);
    server.addEventListener("close", bye);
    server.addEventListener("error", bye);
    return new Response(null, { status: 101, webSocket: client } as ResponseInit);
  }
}
