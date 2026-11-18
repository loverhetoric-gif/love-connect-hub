// 映像・音声の部屋（規格書 第23章）。参加者の出入りを知らせ、つなぐための連絡（署名つき）を相手に渡すだけ。映像・音声は通さない。
// 置き場所に依存しない形で書き、Cloudflare では Durable Objects に置く（adapters/cloudflare/rtc.ts）。試験では偽の接続で動かす。
// 入ってよいか（ログイン・端末の証明・同じ会社か）は、部屋に入る前に土台が確かめて、確かめた本人（co・by・pub）を渡す。
// 部屋は連絡の中身を変えられない（署名は端から端まで。受け手が createRtcVerifier で確かめる）。送り手のなりすましだけは、ここでも止める。

import { type IceServer, RTC_MESSAGE_MAX } from "./rtc.ts";

export type RtcPurpose = "meeting" | "assist";

/** 部屋に入る本人（土台が確かめたもの） */
export interface RtcPeer {
  co: string;
  by: string;
  /** 端末の鍵（第21章の送るための鍵）の公開鍵 */
  pub: string;
  /** 画面に出す名前（64 文字まで） */
  name?: string;
}

/** 参加者へ送る口 */
export interface RtcSink {
  send(text: string): void;
  close(code: number, reason: string): void;
}

export const RTC_ROOM_LIMITS = Object.freeze({
  /** 直接つなぐ（全員が全員とつなぐ）会議の人数の上限。これより多い会議は、映像を配る中継（SFU）を使う（第23章 次の段階） */
  meetingPeers: 4,
  /** 遠隔支援は 2 人（支援する人と、支援される人） */
  assistPeers: 2,
  rateWindowMs: 10_000,
  rateCount: 400,
});

export const RTC_CLOSE = Object.freeze({ replaced: 4000, badRequest: 4400, forbidden: 4403, full: 4409, tooMany: 4429 });

export interface RtcRoomOptions {
  /** 部屋の会社（別の会社の人は入れない） */
  co: string;
  purpose: RtcPurpose;
  now: () => number;
  /** 中継（TURN）の許可を取る（無ければ直接だけでつなぐ） */
  turn?: () => Promise<{ servers: IceServer[]; ttl: number } | null>;
}

interface Member {
  peer: RtcPeer;
  sink: RtcSink;
  win: number;
  count: number;
}

/** 部屋の中核 */
export function createRtcRoom(o: RtcRoomOptions) {
  const members = new Map<string, Member>();
  const max = o.purpose === "assist" ? RTC_ROOM_LIMITS.assistPeers : RTC_ROOM_LIMITS.meetingPeers;
  let turnCache: { value: { servers: IceServer[]; ttl: number }; until: number } | null = null;
  const view = (p: RtcPeer) => ({ pub: p.pub, by: p.by, ...(p.name ? { name: p.name.slice(0, 64) } : {}) });
  const send = (m: Member, msg: unknown) => { try { m.sink.send(JSON.stringify(msg)); } catch { /* 切れた相手は leave で片付く */ } };

  return {
    get size() { return members.size; },
    /** 入る。同じ端末がもう一度入ったら、古い接続を閉じて置き換える */
    join(peer: RtcPeer, sink: RtcSink): { ok: true } | { ok: false; code: number; reason: string } {
      if (peer.co !== o.co) { sink.close(RTC_CLOSE.forbidden, "別の会社の部屋です"); return { ok: false, code: RTC_CLOSE.forbidden, reason: "別の会社の部屋です" }; }
      const old = members.get(peer.pub);
      if (!old && members.size >= max) { sink.close(RTC_CLOSE.full, "部屋がいっぱいです"); return { ok: false, code: RTC_CLOSE.full, reason: "部屋がいっぱいです" }; }
      if (old) { try { old.sink.close(RTC_CLOSE.replaced, "同じ端末が入り直しました"); } catch { /* なし */ } }
      const m: Member = { peer, sink, win: o.now(), count: 0 };
      members.set(peer.pub, m);
      send(m, { t: "welcome", purpose: o.purpose, me: view(peer), peers: [...members.values()].filter((x) => x !== m).map((x) => view(x.peer)) });
      if (!old) for (const x of members.values()) if (x !== m) send(x, { t: "presence", join: view(peer) });
      return { ok: true };
    },
    /** 出る（接続が切れたとき） */
    leave(pub: string, sink?: RtcSink) {
      const m = members.get(pub);
      if (!m || (sink && m.sink !== sink)) return;
      members.delete(pub);
      for (const x of members.values()) send(x, { t: "presence", leave: pub });
    },
    /** 参加者から届いた文字を処理する */
    async receive(pub: string, text: string): Promise<void> {
      const m = members.get(pub);
      if (!m) return;
      const now = o.now();
      if (now - m.win > RTC_ROOM_LIMITS.rateWindowMs) { m.win = now; m.count = 0; }
      if (++m.count > RTC_ROOM_LIMITS.rateCount) { members.delete(pub); m.sink.close(RTC_CLOSE.tooMany, "送る回数が多すぎます"); for (const x of members.values()) send(x, { t: "presence", leave: pub }); return; }
      if (text === "ping") { try { m.sink.send("pong"); } catch { /* なし */ } return; }
      if (text.length > RTC_MESSAGE_MAX) { send(m, { t: "error", code: "TOO_LARGE" }); return; }
      let d: { t?: unknown; to?: unknown; m?: unknown };
      try { d = JSON.parse(text) as typeof d; } catch { send(m, { t: "error", code: "BAD_JSON" }); return; }
      if (d && d.t === "turn") {
        if (!o.turn) { send(m, { t: "turn", servers: [], ttl: 0 }); return; }
        if (!turnCache || turnCache.until <= now) {
          const g = await o.turn().catch(() => null);
          // 許可は 12 時間だけ使い回す（期限 24 時間の半分）
          turnCache = g ? { value: g, until: now + (g.ttl * 1000) / 2 } : null;
        }
        send(m, { t: "turn", servers: turnCache?.value.servers ?? [], ttl: turnCache?.value.ttl ?? 0 });
        return;
      }
      if (!d || d.t !== "msg" || typeof d.to !== "string" || !d.m || typeof d.m !== "object" || Array.isArray(d.m)) { send(m, { t: "error", code: "BAD_REQUEST" }); return; }
      // 送り手のなりすましを止める（中身の署名は受け手が確かめる）
      if ((d.m as { from?: unknown }).from !== pub) { send(m, { t: "error", code: "FROM_MISMATCH" }); return; }
      const to = members.get(d.to);
      if (!to || to === m) { send(m, { t: "undeliverable", to: d.to }); return; }
      send(to, { t: "msg", from: pub, m: d.m });
    },
  };
}

export type RtcRoom = ReturnType<typeof createRtcRoom>;
