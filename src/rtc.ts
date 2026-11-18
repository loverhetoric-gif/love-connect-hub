// 映像・音声のリアルタイム通信（規格書 第23章）。WEB 会議と遠隔支援（リモートアシスタント）に使う。
// WARPHOLE.（iPhone から Mac を操作するアプリ）で実際に動いている作りを、共通の決まりにしたもの。
//  - 映像と音声は端末どうしで直接送る（WebRTC）。直接つながらないときだけ中継（TURN）を通す。土台・部屋は映像を通さない
//  - つなぐための連絡は、第21章の端末の鍵で署名する。連絡の中の SDP（暗号の鍵の指紋を含む）も署名に入るので、部屋や中継が割り込めない
//  - 回線が変わっても、つながったまま通り道を張り替える
//  - 映像は HEVC → H.264 High の順に優先し、回線と用途に合わせて送る量を抑える
//  - 操作は 2 本の道：確実に届ける ctl と、欠けたら捨てる mv
//  - 遠隔支援の操作は、支援される本人が承認の鍵（生体認証）で許したときだけ
// 外部部品は入れず、Web Crypto と文字の処理だけで書く。WebRTC そのものは各端末（ブラウザ・iPhone・Android）のものを使う。

import { canonicalJson, toBase64Url } from "./crypto.ts";
import { type AnyDedupe, createDedupe } from "./dedupe.ts";
import { type DeviceSigner, verifyDeviceSignature } from "./device.ts";

const enc = new TextEncoder();

// ---- 連絡（シグナリング） ----

/** 連絡の種類 */
export type RtcType = "offer" | "answer" | "ice" | "restart" | "bye" | "grant" | "revoke";

export type RtcScope = "view" | "point" | "control";

/** 署名つきの連絡。部屋を通して相手に届ける（部屋は中身を変えられない） */
export interface RtcMessage {
  v: 1;
  t: RtcType;
  /** 部屋の番号 */
  room: string;
  /** 送り手の端末の公開鍵 */
  from: string;
  /** 受け手の端末の公開鍵 */
  to: string;
  /** 時刻（ミリ秒） */
  ts: number;
  /** 使い捨ての番号（16 バイトの base64url） */
  n: string;
  b: Record<string, unknown>;
  /** 送り手の端末の鍵の署名（r||s の base64url） */
  sig: string;
}

export const RTC_SKEW_MS = 120_000;
export const RTC_NONCE_MS = 300_000;
/** 連絡 1 通の上限（部屋も同じ上限で断る） */
export const RTC_MESSAGE_MAX = 64 * 1024;
/** 遠隔操作の許可の最長（30 分） */
export const RTC_GRANT_MAX_MS = 30 * 60_000;

const ROOM_RE = /^[A-Za-z0-9_-]{8,64}$/;
const PUB_RE = /^[A-Za-z0-9_-]{87}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const SID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const TYPES: readonly RtcType[] = ["offer", "answer", "ice", "restart", "bye", "grant", "revoke"];
const SCOPES: readonly RtcScope[] = ["view", "point", "control"];

/** 署名する文：lch-rtc-v1 ＋ 署名を除いた連絡の正規化 JSON */
export function rtcSignedText(m: Omit<RtcMessage, "sig">): string {
  const { v, t, room, from, to, ts, n, b } = m;
  return "lch-rtc-v1\n" + canonicalJson({ v, t, room, from, to, ts, n, b });
}

/** 連絡を作って署名する */
export async function signRtc(signer: DeviceSigner, p: { t: RtcType; room: string; to: string; b: Record<string, unknown>; now: number }): Promise<RtcMessage> {
  const body: Omit<RtcMessage, "sig"> = { v: 1, t: p.t, room: p.room, from: signer.pub, to: p.to, ts: p.now, n: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), b: p.b };
  return { ...body, sig: toBase64Url(await signer.sign(enc.encode(rtcSignedText(body)))) };
}

export type RtcCode = "RTC_BAD" | "RTC_ROOM" | "RTC_TO" | "RTC_CLOCK" | "RTC_SIGNATURE" | "RTC_REPLAY" | "RTC_SDP" | "RTC_GRANT";
export type RtcCheck = { ok: true; msg: RtcMessage } | { ok: false; code: RtcCode; message: string };
const bad = (code: RtcCode, message: string): RtcCheck => ({ ok: false, code, message });

/** 本文の形を確かめる（種類ごと）。通れば undefined、通らなければ理由 */
function bodyProblem(t: RtcType, b: Record<string, unknown>): string | undefined {
  const sid = b.sid;
  if (typeof sid !== "string" || !SID_RE.test(sid)) return "接続の番号（sid）の形が違います";
  switch (t) {
    case "offer":
    case "answer": {
      if (typeof b.sdp !== "string" || b.sdp.length > 48 * 1024) return "SDP の形が違います";
      return sdpProblem(b.sdp);
    }
    case "ice":
      if (b.c !== null && (typeof b.c !== "string" || b.c.length > 1024)) return "経路の候補の形が違います";
      if (b.mid !== undefined && (typeof b.mid !== "string" || b.mid.length > 32)) return "経路の候補の形が違います";
      if (b.idx !== undefined && (typeof b.idx !== "number" || !Number.isInteger(b.idx) || b.idx < 0 || b.idx > 64)) return "経路の候補の形が違います";
      return undefined;
    case "grant":
      if (!SCOPES.includes(b.scope as RtcScope)) return "許す範囲の形が違います";
      if (typeof b.until !== "number" || !Number.isSafeInteger(b.until)) return "許可の期限の形が違います";
      return undefined;
    default:
      return undefined;
  }
}

export interface RtcVerifierOptions {
  /** 自分の端末の公開鍵（宛先がこれでない連絡は捨てる） */
  me: string;
  /** 自分が入っている部屋 */
  room: string;
  now: () => number;
  /** 使い捨ての番号の記憶（既定：手元に 5 分） */
  nonces?: AnyDedupe;
  skewMs?: number;
}

/** 受け取った連絡を確かめる：形・部屋・宛先・時刻（前後 2 分）・署名・使い回し（5 分）・SDP の暗号の指紋 */
export function createRtcVerifier(o: RtcVerifierOptions): { verify(raw: unknown): Promise<RtcCheck> } {
  const nonces = o.nonces ?? createDedupe({ windowMs: RTC_NONCE_MS, capacity: 50_000 });
  const skew = o.skewMs ?? RTC_SKEW_MS;
  return {
    async verify(raw) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return bad("RTC_BAD", "連絡の形が違います");
      const m = raw as RtcMessage;
      const keys = Object.keys(m).sort().join(",");
      if (keys !== "b,from,n,room,sig,t,to,ts,v") return bad("RTC_BAD", "連絡の形が違います");
      if (m.v !== 1 || !TYPES.includes(m.t) || typeof m.room !== "string" || !ROOM_RE.test(m.room)) return bad("RTC_BAD", "連絡の形が違います");
      if (typeof m.from !== "string" || !PUB_RE.test(m.from) || typeof m.to !== "string" || !PUB_RE.test(m.to)) return bad("RTC_BAD", "連絡の形が違います");
      if (typeof m.ts !== "number" || !Number.isSafeInteger(m.ts) || typeof m.n !== "string" || !NONCE_RE.test(m.n) || typeof m.sig !== "string") return bad("RTC_BAD", "連絡の形が違います");
      if (!m.b || typeof m.b !== "object" || Array.isArray(m.b)) return bad("RTC_BAD", "連絡の形が違います");
      if (m.room !== o.room) return bad("RTC_ROOM", "別の部屋の連絡です");
      if (m.to !== o.me) return bad("RTC_TO", "自分宛ての連絡ではありません");
      const now = o.now();
      if (Math.abs(now - m.ts) > skew) return bad("RTC_CLOCK", "時刻がずれています");
      const p = bodyProblem(m.t, m.b);
      // SDP の中身（暗号の鍵の指紋）の問題だけを RTC_SDP にする。そのほかの形の違いは RTC_BAD
      if (p) return bad((m.t === "offer" || m.t === "answer") && typeof m.b.sdp === "string" && sdpProblem(m.b.sdp) === p ? "RTC_SDP" : "RTC_BAD", p);
      if (!(await verifyDeviceSignature(m.from, m.sig, rtcSignedText(m)))) return bad("RTC_SIGNATURE", "署名が合いません");
      if (!(await nonces.first(m.room, `${m.from}\0${m.n}`, now))) return bad("RTC_REPLAY", "同じ連絡が使い回されました");
      return { ok: true, msg: m };
    },
  };
}

// ---- SDP（つなぎ方の取り決め） ----

/** SDP の暗号の鍵の指紋（a=fingerprint）を取り出す */
export function sdpFingerprints(sdp: string): { hash: string; value: string }[] {
  const out: { hash: string; value: string }[] = [];
  for (const line of sdp.split(/\r?\n/)) {
    const m = /^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/.exec(line);
    if (m) out.push({ hash: m[1]!.toLowerCase(), value: m[2]!.toUpperCase() });
  }
  return out;
}

/** SDP の安全の確かめ：暗号の鍵の指紋が 1 つ以上あり、すべて SHA-256 以上で、同じ鍵を指す */
export function sdpProblem(sdp: string): string | undefined {
  const fps = sdpFingerprints(sdp);
  if (fps.length === 0) return "暗号の鍵の指紋がありません";
  if (fps.some((f) => !["sha-256", "sha-384", "sha-512"].includes(f.hash))) return "弱い指紋（SHA-1 など）は使えません";
  if (new Set(fps.map((f) => f.hash + " " + f.value)).size !== 1) return "指紋が食い違っています";
  return undefined;
}

/** 映像の方式の優先順。HEVC は同じ画質で通信量が H.264 の約半分。AV1 は多くの端末で専用の部品が無く、圧縮の負担が大きいので後ろ */
export const RTC_VIDEO_ORDER: readonly string[] = Object.freeze(["H265", "H264", "VP9", "AV1", "VP8"]);

/** H.264 の型の優先（High → Main → Constrained Baseline） */
function h264Rank(fmtp: string | undefined): number {
  const m = /profile-level-id=([0-9A-Fa-f]{6})/.exec(fmtp ?? "");
  const p = m ? m[1]!.slice(0, 2).toLowerCase() : "42";
  return p === "64" ? 0 : p === "4d" ? 1 : 2;
}

/** 映像の方式を優先順に並べ替える（m=video の行だけ。並びに無い方式（送り直し・欠けの補いなど）は元の順で後ろに残す） */
export function preferVideoCodecs(sdp: string, order: readonly string[] = RTC_VIDEO_ORDER): string {
  const nl = sdp.includes("\r\n") ? "\r\n" : "\n";
  const lines = sdp.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    if (!lines[i]!.startsWith("m=video ")) { i++; continue; }
    let end = i + 1;
    while (end < lines.length && !lines[end]!.startsWith("m=")) end++;
    const head = lines[i]!.split(" ");
    const pts = head.slice(3);
    const name = new Map<string, string>();
    const fmtp = new Map<string, string>();
    for (let k = i + 1; k < end; k++) {
      const r = /^a=rtpmap:(\d+) ([^/]+)\//.exec(lines[k]!);
      if (r) name.set(r[1]!, r[2]!.toUpperCase());
      const f = /^a=fmtp:(\d+) (.*)$/.exec(lines[k]!);
      if (f) fmtp.set(f[1]!, f[2]!);
    }
    const rank = (pt: string) => {
      const c = order.indexOf(name.get(pt) ?? "");
      return c < 0 ? order.length : c;
    };
    const sorted = pts
      .map((pt, idx) => ({ pt, idx }))
      .sort((a, b) => rank(a.pt) - rank(b.pt) || (name.get(a.pt) === "H264" && name.get(b.pt) === "H264" ? h264Rank(fmtp.get(a.pt)) - h264Rank(fmtp.get(b.pt)) : 0) || a.idx - b.idx)
      .map((x) => x.pt);
    lines[i] = [...head.slice(0, 3), ...sorted].join(" ");
    i = end;
  }
  return lines.join(nl);
}

/** 音声（Opus）に、欠けの補い（useinbandfec）と無音の省略（usedtx）を入れる */
export function tuneOpus(sdp: string): string {
  const nl = sdp.includes("\r\n") ? "\r\n" : "\n";
  const lines = sdp.split(/\r?\n/);
  const opus = new Set<string>();
  for (const l of lines) {
    const r = /^a=rtpmap:(\d+) opus\//i.exec(l);
    if (r) opus.add(r[1]!);
  }
  return lines
    .map((l) => {
      const f = /^a=fmtp:(\d+) (.*)$/.exec(l);
      if (!f || !opus.has(f[1]!)) return l;
      const params = new Map(f[2]!.split(";").filter(Boolean).map((kv) => { const [k, v] = kv.split("="); return [k!.trim(), (v ?? "").trim()] as [string, string]; }));
      params.set("useinbandfec", "1");
      params.set("usedtx", "1");
      return `a=fmtp:${f[1]} ` + [...params].map(([k, v]) => `${k}=${v}`).join(";");
    })
    .join(nl);
}

// ---- 送る量の上限（用途と回線ごと） ----

export type RtcSource = "camera" | "screen";
export type RtcNetwork = "wifi" | "cellular" | "unknown";

export interface RtcBudget {
  /** 映像の上限（ビット毎秒） */
  maxBitrate: number;
  /** コマ数の上限 */
  maxFps: number;
  /** 長い辺の上限（画素） */
  maxLongEdge: number;
  /** 音声の上限（ビット毎秒） */
  audioBitrate: number;
  /** 映像の性質の指示（MediaStreamTrack.contentHint） */
  contentHint: "motion" | "detail" | "text";
  /** 回線が細いときに、どちらを守るか（RTCRtpSendParameters.degradationPreference） */
  degradation: "maintain-framerate" | "maintain-resolution";
}

/**
 * 送る量の上限。WARPHOLE の 5.6・5.7 の決まりと同じ考え方：
 * 画面（共有・遠隔支援）は文字を守る（解像度を保つ）。Wi-Fi は 60 コマまで 16Mbps・61 コマ以上 24Mbps、モバイル回線は長い辺 1920・60 コマ・6Mbps。
 * カメラ（会議）は動きを守る（コマ数を保つ）。Wi-Fi は 1280・30 コマ・2.5Mbps、モバイル回線は 960・30 コマ・1Mbps。
 * displayFps は、送る側と受ける側の画面のコマ数の小さい方（可変リフレッシュの画面は最大で数える）。回線が分からないときは Wi-Fi と同じ
 */
export function rtcBudget(p: { source: RtcSource; network: RtcNetwork; displayFps?: number }): RtcBudget {
  const cell = p.network === "cellular";
  const fps = Math.max(1, Math.min(240, Math.floor(p.displayFps ?? 60)));
  if (p.source === "screen") {
    if (cell) return { maxBitrate: 6_000_000, maxFps: Math.min(fps, 60), maxLongEdge: 1920, audioBitrate: 24_000, contentHint: "text", degradation: "maintain-resolution" };
    return { maxBitrate: fps > 60 ? 24_000_000 : 16_000_000, maxFps: Math.min(fps, 120), maxLongEdge: 3840, audioBitrate: 32_000, contentHint: "text", degradation: "maintain-resolution" };
  }
  if (cell) return { maxBitrate: 1_000_000, maxFps: Math.min(fps, 30), maxLongEdge: 960, audioBitrate: 24_000, contentHint: "motion", degradation: "maintain-framerate" };
  return { maxBitrate: 2_500_000, maxFps: Math.min(fps, 30), maxLongEdge: 1280, audioBitrate: 32_000, contentHint: "motion", degradation: "maintain-framerate" };
}

// ---- 操作の通り道（データチャネル） ----

/** 2 本の通り道。ctl は確実に順番どおり、mv は順番を守らず送り直さない（欠けたら捨てる） */
export const RTC_CHANNELS = Object.freeze({
  ctl: Object.freeze({ ordered: true }),
  mv: Object.freeze({ ordered: false, maxRetransmits: 0 }),
});

/** 信号 1 通の上限 */
export const RTC_SIGNAL_MAX = 16 * 1024;

/** 範囲ごとに、支援する人が送ってよい信号 */
const SUPPORTER_SIGNALS: Readonly<Record<RtcScope, readonly string[]>> = Object.freeze({
  view: ["st"],
  point: ["st", "pt"],
  control: ["st", "pt", "rm", "ma", "md", "mu", "sc", "kd", "ku", "tx", "rel"],
});
/** 欠けたら捨てる道に通してよい信号（位置だけ） */
const MV_SIGNALS: readonly string[] = ["rm", "ma", "cur", "pt"];

const num = (v: unknown, lo: number, hi: number) => typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi;

/**
 * 支援する人から届いた信号を確かめる（支援される端末が、再現する前に呼ぶ）。
 * 許された範囲（scope）の外の信号・道の違い・形の違い・大きすぎる信号は捨てる。パスワードを打つ信号は、遠隔支援では受け付けない
 */
export function checkAssistSignal(channel: "ctl" | "mv", scope: RtcScope | undefined, raw: string): { ok: true; signal: Record<string, unknown> } | { ok: false; reason: string } {
  if (raw.length > RTC_SIGNAL_MAX) return { ok: false, reason: "大きすぎる信号です" };
  let s: Record<string, unknown>;
  try {
    s = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "信号を読めません" };
  }
  if (!s || typeof s !== "object" || Array.isArray(s) || typeof s.k !== "string") return { ok: false, reason: "信号の形が違います" };
  const k = s.k;
  if (channel === "mv" && !MV_SIGNALS.includes(k)) return { ok: false, reason: "この道では送れない信号です" };
  if (!scope || !SUPPORTER_SIGNALS[scope].includes(k)) return { ok: false, reason: "許されていない操作です" };
  const okShape =
    k === "rm" ? num(s.dx, -10_000, 10_000) && num(s.dy, -10_000, 10_000)
    : k === "ma" || k === "pt" ? num(s.x, 0, 1) && num(s.y, 0, 1)
    : k === "md" || k === "mu" ? s.b === 0 || s.b === 1 || s.b === 2
    : k === "sc" ? num(s.dx, -100_000, 100_000) && num(s.dy, -100_000, 100_000)
    : k === "kd" || k === "ku" ? typeof s.c === "number" && Number.isInteger(s.c) && s.c >= 0 && s.c <= 0xffff
    : k === "tx" ? typeof s.s === "string" && s.s.length <= 4096
    : true;
  return okShape ? { ok: true, signal: s } : { ok: false, reason: "信号の形が違います" };
}

// ---- 遠隔操作の許可（本人の承認） ----

/**
 * 遠隔操作の許可を確かめる。許可は、支援される本人が承認の鍵（使うたびに生体認証。第21章）で署名した grant の連絡。
 * 確かめること：連絡の署名・送り手が本人の承認の鍵・宛先が支援する人・接続の番号・期限（今より後で、最長 30 分）
 */
export async function verifyControlGrant(p: {
  grant: RtcMessage;
  /** 支援される本人の承認の鍵（use = approve の公開鍵） */
  approverKeys: readonly string[];
  supporter: string;
  sid: string;
  now: number;
}): Promise<{ ok: true; scope: RtcScope; until: number } | { ok: false; code: RtcCode; message: string }> {
  const g = p.grant;
  if (!g || g.t !== "grant" || g.v !== 1 || !g.b || bodyProblem("grant", g.b)) return { ok: false, code: "RTC_GRANT", message: "許可の形が違います" };
  if (!p.approverKeys.includes(g.from)) return { ok: false, code: "RTC_GRANT", message: "本人の承認の鍵で署名されていません" };
  if (g.to !== p.supporter || g.b.sid !== p.sid) return { ok: false, code: "RTC_GRANT", message: "別の相手・別の接続への許可です" };
  const until = g.b.until as number;
  if (until <= p.now || until - g.ts > RTC_GRANT_MAX_MS || g.ts > p.now + RTC_SKEW_MS) return { ok: false, code: "RTC_GRANT", message: "許可の期限が切れているか、長すぎます" };
  if (!(await verifyDeviceSignature(g.from, g.sig, rtcSignedText(g)))) return { ok: false, code: "RTC_SIGNATURE", message: "署名が合いません" };
  return { ok: true, scope: g.b.scope as RtcScope, until };
}

// ---- 経路の張り替え（ICE リスタート） ----

export type RtcConnState = "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";

/**
 * 張り替えの決まり（WARPHOLE 5.9）：切れかけた（disconnected・failed）らすぐ張り替え、戻らなければ 5 秒ごとに繰り返し、20 秒戻らなければ終える。
 * 端末の回線が変わったら（Wi-Fi ⇄ モバイル回線）、切れる前に張り替える。張り替えは申し出（offer）を作り直して同じ sid で送る
 */
export function createRestartPolicy(o: { retryMs?: number; giveUpMs?: number } = {}) {
  const retryMs = o.retryMs ?? 5_000, giveUpMs = o.giveUpMs ?? 20_000;
  let since: number | undefined, last = 0, closed = false;
  return {
    /** 接続の状態が変わったとき。行うこと（restart・close）を返す */
    onState(state: RtcConnState, now: number): ("restart" | "close")[] {
      if (closed) return [];
      if (state === "connected") { since = undefined; return []; }
      if (state === "closed") { closed = true; return []; }
      if ((state === "disconnected" || state === "failed") && since === undefined) { since = now; last = now; return ["restart"]; }
      return [];
    },
    /** 端末の回線が変わったとき */
    onNetworkChange(now: number): ("restart" | "close")[] {
      if (closed) return [];
      last = now;
      return ["restart"];
    },
    /** 定期的に呼ぶ（1 秒ごとなど） */
    tick(now: number): ("restart" | "close")[] {
      if (closed || since === undefined) return [];
      if (now - since >= giveUpMs) { closed = true; return ["close"]; }
      if (now - last >= retryMs) { last = now; return ["restart"]; }
      return [];
    },
  };
}

// ---- 中継（TURN）の許可 ----

export interface IceServer {
  urls: string[];
  username?: string;
  credential?: string;
}

/** 中継の許可の期限（24 時間）。端末は 12 時間で取り直す */
export const TURN_TTL_SEC = 24 * 60 * 60;
const ICE_URL_RE = /^(stun|turn|turns):[A-Za-z0-9.\-:?=&_]{1,200}$/;

/** 中継の提供元の答えから、使える形の物だけを取り出す（形が違えば空。WARPHOLE の relay/src/turn.ts と同じ） */
export function sanitizeIceServers(raw: unknown): IceServer[] {
  const list = (raw as { iceServers?: unknown })?.iceServers;
  const items = Array.isArray(list) ? list : list && typeof list === "object" ? [list] : [];
  const out: IceServer[] = [];
  for (const item of items.slice(0, 8)) {
    if (!item || typeof item !== "object") continue;
    const { urls, username, credential } = item as Record<string, unknown>;
    const all = (Array.isArray(urls) ? urls : [urls]).filter((u): u is string => typeof u === "string" && ICE_URL_RE.test(u));
    if (all.length === 0) continue;
    const s: IceServer = { urls: all.slice(0, 8) };
    if (typeof username === "string" && username.length <= 512) s.username = username;
    if (typeof credential === "string" && credential.length <= 512) s.credential = credential;
    if (all.some((u) => u.startsWith("turn")) && (!s.username || !s.credential)) continue;
    out.push(s);
  }
  return out;
}

// ---- 計測 ----

export interface RtcStatsSummary {
  /** 経路：direct（直接）・relay（中継）・unknown */
  path: "direct" | "relay" | "unknown";
  local?: string;
  remote?: string;
  relayProtocol?: string;
  rttMs?: number;
  availableOutgoingBps?: number;
  out?: { codec?: string; impl?: string; fps?: number; width?: number; height?: number; nack?: number; pli?: number; limited?: string };
  in?: { codec?: string; impl?: string; fps?: number; width?: number; height?: number; dropped?: number; freezes?: number; jitterBufferMs?: number; lost?: number; jitterMs?: number };
}

type Stat = Record<string, unknown> & { type?: string; id?: string };
const n = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const s = (v: unknown) => (typeof v === "string" ? v : undefined);
function clean<T extends object>(o: T): T {
  for (const k of Object.keys(o) as (keyof T)[]) if (o[k] === undefined) delete o[k];
  return o;
}

/**
 * WebRTC の計測（RTCPeerConnection.getStats の中身）を、記録の形にまとめる（WARPHOLE 5.9 の計測と同じ項目）。
 * 外出先の不具合は、この記録（経路・往復の遅れ・使える帯域・方式・実装・コマ数・欠け・止まった回数）で直す
 */
export function summarizeRtcStats(reports: Iterable<Stat>): RtcStatsSummary {
  const all = [...reports];
  const byId = new Map(all.filter((r) => typeof r.id === "string").map((r) => [r.id as string, r]));
  const pair = all.find((r) => r.type === "candidate-pair" && (r.selected === true || r.nominated === true) && r.state === "succeeded");
  const local = pair ? byId.get(s(pair.localCandidateId) ?? "") : undefined;
  const remote = pair ? byId.get(s(pair.remoteCandidateId) ?? "") : undefined;
  const lt = s(local?.candidateType), rt = s(remote?.candidateType);
  const codec = (id: unknown) => s(byId.get(s(id) ?? "")?.mimeType)?.replace(/^video\//i, "");
  const outV = all.find((r) => r.type === "outbound-rtp" && r.kind === "video");
  const inV = all.find((r) => r.type === "inbound-rtp" && r.kind === "video");
  const sum: RtcStatsSummary = { path: !pair ? "unknown" : lt === "relay" || rt === "relay" ? "relay" : "direct" };
  if (lt) sum.local = lt;
  if (rt) sum.remote = rt;
  const rp = s(local?.relayProtocol);
  if (rp) sum.relayProtocol = rp;
  const rtt = n(pair?.currentRoundTripTime);
  if (rtt !== undefined) sum.rttMs = Math.round(rtt * 1000);
  const bw = n(pair?.availableOutgoingBitrate);
  if (bw !== undefined) sum.availableOutgoingBps = Math.round(bw);
  if (outV) sum.out = clean({ codec: codec(outV.codecId), impl: s(outV.encoderImplementation), fps: n(outV.framesPerSecond), width: n(outV.frameWidth), height: n(outV.frameHeight), nack: n(outV.nackCount), pli: n(outV.pliCount), limited: s(outV.qualityLimitationReason) });
  if (inV) {
    const jb = n(inV.jitterBufferDelay), jbc = n(inV.jitterBufferEmittedCount), jit = n(inV.jitter);
    sum.in = clean({ codec: codec(inV.codecId), impl: s(inV.decoderImplementation), fps: n(inV.framesPerSecond), width: n(inV.frameWidth), height: n(inV.frameHeight), dropped: n(inV.framesDropped), freezes: n(inV.freezeCount),
      jitterBufferMs: jb !== undefined && jbc ? Math.round((jb / jbc) * 1000) : undefined, lost: n(inV.packetsLost), jitterMs: jit !== undefined ? Math.round(jit * 1000) : undefined });
  }
  return sum;
}

/** 部屋の番号を作る（会議・遠隔支援ごとに新しく作る。推測できない 16 バイト） */
export function newRoomId(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}
/** 接続の番号を作る */
export function newSessionId(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(12)));
}
