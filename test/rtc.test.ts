// 映像・音声のリアルタイム通信（規格書 第23章）。WARPHOLE. の作りを共通の決まりにしたものを確かめる
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RTC_CHANNELS,
  checkAssistSignal,
  createRestartPolicy,
  createRtcRoom,
  createRtcVerifier,
  createWebDeviceKey,
  preferVideoCodecs,
  rtcBudget,
  sanitizeIceServers,
  sdpProblem,
  signRtc,
  summarizeRtcStats,
  tuneOpus,
  verifyControlGrant,
  type RtcSink,
} from "../src/index.ts";
import { cloudflareTurn, rtcRoomRequest } from "../adapters/cloudflare/rtc.ts";

const T0 = Date.UTC(2026, 10, 18, 12);
const ROOM = "room-abcdefgh";
const FP = "a=fingerprint:sha-256 " + Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, "0").toUpperCase()).join(":");
const SDP = ["v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "t=0 0", FP, "m=video 9 UDP/TLS/RTP/SAVPF 96", "a=rtpmap:96 VP8/90000", ""].join("\r\n");

async function pair() {
  const a = await createWebDeviceKey(), b = await createWebDeviceKey();
  return { a, b, vb: createRtcVerifier({ me: b.pub, room: ROOM, now: () => T0 }) };
}

test("連絡：端末の鍵で署名した申し出（SDP）は通り、部屋・宛先・時刻・書き換え・使い回しは断る", async () => {
  const { a, b, vb } = await pair();
  const offer = await signRtc(a, { t: "offer", room: ROOM, to: b.pub, b: { sid: "sid-12345678", sdp: SDP }, now: T0 });
  const ok = await vb.verify(structuredClone(offer));
  assert.equal(ok.ok, true);
  assert.equal((await vb.verify(structuredClone(offer))).ok ? "ok" : (await vb.verify(structuredClone(offer)) as { code: string }).code, "RTC_REPLAY", "同じ連絡は 1 回だけ");
  const code = async (m: unknown, v = createRtcVerifier({ me: b.pub, room: ROOM, now: () => T0 })) => { const r = await v.verify(m); return r.ok ? "ok" : r.code; };
  assert.equal(await code(offer, createRtcVerifier({ me: b.pub, room: "room-otherone", now: () => T0 })), "RTC_ROOM");
  assert.equal(await code(offer, createRtcVerifier({ me: a.pub, room: ROOM, now: () => T0 })), "RTC_TO");
  assert.equal(await code(offer, createRtcVerifier({ me: b.pub, room: ROOM, now: () => T0 + 121_000 })), "RTC_CLOCK");
  // 部屋や中継が SDP（暗号の鍵の指紋）を差し替えても通らない
  const swapped = { ...offer, b: { ...offer.b, sdp: SDP.replace(":01:02:", ":FF:02:") } };
  assert.equal(await code(swapped), "RTC_SIGNATURE");
  assert.equal(await code({ ...offer, extra: 1 }), "RTC_BAD");
  assert.equal(await code({ ...offer, b: { sdp: SDP } }), "RTC_BAD", "接続の番号が要る");
  const other = await createWebDeviceKey();
  assert.equal(await code({ ...offer, from: other.pub }), "RTC_SIGNATURE", "送り手のなりすまし");
});

test("SDP：暗号の鍵の指紋が無い・SHA-1・食い違いは断る", async () => {
  assert.equal(sdpProblem(SDP), undefined);
  assert.match(sdpProblem(SDP.replace(FP + "\r\n", "")) ?? "", /指紋がありません/);
  assert.match(sdpProblem(SDP.replace("sha-256", "sha-1")) ?? "", /弱い指紋/);
  assert.match(sdpProblem(SDP + FP.replace(":01:02:", ":AA:02:") + "\r\n") ?? "", /食い違って/);
  const { a, b } = await pair();
  const weak = await signRtc(a, { t: "answer", room: ROOM, to: b.pub, b: { sid: "sid-12345678", sdp: SDP.replace("sha-256", "sha-1") }, now: T0 });
  const r = await createRtcVerifier({ me: b.pub, room: ROOM, now: () => T0 }).verify(weak);
  assert.equal(r.ok ? "ok" : r.code, "RTC_SDP");
});

test("映像の方式：HEVC → H.264（High → 基本）→ VP9 → AV1 → VP8 の順。送り直し・欠けの補いは後ろに残す", () => {
  const sdp = ["v=0", "m=audio 9 UDP/TLS/RTP/SAVPF 111", "a=rtpmap:111 opus/48000/2", "a=fmtp:111 minptime=10", "m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 102 104 106 45 120",
    "a=rtpmap:96 VP8/90000", "a=rtpmap:97 rtx/90000", "a=rtpmap:98 VP9/90000", "a=rtpmap:102 H264/90000", "a=fmtp:102 profile-level-id=42e01f", "a=rtpmap:104 H264/90000",
    "a=fmtp:104 profile-level-id=640c34", "a=rtpmap:106 H265/90000", "a=rtpmap:45 AV1/90000", "a=rtpmap:120 flexfec-03/90000", ""].join("\r\n");
  const out = preferVideoCodecs(sdp);
  assert.match(out, /m=video 9 UDP\/TLS\/RTP\/SAVPF 106 104 102 98 45 96 97 120\r\n/);
  assert.match(out, /m=audio 9 UDP\/TLS\/RTP\/SAVPF 111\r\n/, "音声の行は変えない");
  const opus = tuneOpus(sdp);
  assert.match(opus, /a=fmtp:111 minptime=10;useinbandfec=1;usedtx=1/);
  assert.match(opus, /a=fmtp:102 profile-level-id=42e01f/, "映像の取り決めは変えない");
});

test("送る量の上限：画面は文字を守り、カメラは動きを守る。モバイル回線では抑える（WARPHOLE 5.6・5.7 と同じ）", () => {
  assert.deepEqual(rtcBudget({ source: "screen", network: "wifi", displayFps: 60 }), { maxBitrate: 16_000_000, maxFps: 60, maxLongEdge: 3840, audioBitrate: 32_000, contentHint: "text", degradation: "maintain-resolution" });
  assert.equal(rtcBudget({ source: "screen", network: "wifi", displayFps: 120 }).maxBitrate, 24_000_000, "61 コマ以上は 24Mbps");
  assert.equal(rtcBudget({ source: "screen", network: "unknown", displayFps: 120 }).maxFps, 120);
  const cell = rtcBudget({ source: "screen", network: "cellular", displayFps: 120 });
  assert.deepEqual([cell.maxBitrate, cell.maxFps, cell.maxLongEdge], [6_000_000, 60, 1920]);
  const cam = rtcBudget({ source: "camera", network: "cellular" });
  assert.deepEqual([cam.maxBitrate, cam.maxFps, cam.maxLongEdge, cam.degradation], [1_000_000, 30, 960, "maintain-framerate"]);
  assert.deepEqual(RTC_CHANNELS.mv, { ordered: false, maxRetransmits: 0 });
});

test("遠隔支援の信号：許された範囲の外・道の違い・形の違い・パスワードは捨てる", () => {
  const ok = (ch: "ctl" | "mv", sc: "view" | "point" | "control" | undefined, s: object) => checkAssistSignal(ch, sc, JSON.stringify(s)).ok;
  assert.equal(ok("ctl", "view", { k: "st", fr: 1 }), true);
  assert.equal(ok("mv", "view", { k: "pt", x: 0.5, y: 0.5 }), false, "見るだけでは指し示せない");
  assert.equal(ok("mv", "point", { k: "pt", x: 0.5, y: 0.5 }), true);
  assert.equal(ok("ctl", "point", { k: "md", b: 0 }), false, "指し示すだけでは押せない");
  assert.equal(ok("ctl", "control", { k: "md", b: 0 }), true);
  assert.equal(ok("ctl", "control", { k: "kd", c: 55 }), true);
  assert.equal(ok("mv", "control", { k: "kd", c: 55 }), false, "キーは確実な道だけ");
  assert.equal(ok("ctl", "control", { k: "pw", s: "x" }), false, "遠隔支援ではパスワードを打たせない");
  assert.equal(ok("ctl", undefined, { k: "md", b: 0 }), false, "許可が無ければ何も通さない");
  assert.equal(ok("mv", "control", { k: "ma", x: 2, y: 0 }), false);
  assert.equal(checkAssistSignal("ctl", "control", "{").ok, false);
  assert.equal(checkAssistSignal("ctl", "control", JSON.stringify({ k: "tx", s: "a".repeat(20_000) })).ok, false);
});

test("遠隔操作の許可：本人の承認の鍵で、その相手・その接続へ、30 分までの期限で出したものだけ", async () => {
  const approve = await createWebDeviceKey(), device = await createWebDeviceKey(), supporter = await createWebDeviceKey();
  const grant = (signer: typeof approve, b: Record<string, unknown>, to = supporter.pub) => signRtc(signer, { t: "grant", room: ROOM, to, b, now: T0 });
  const base = { approverKeys: [approve.pub], supporter: supporter.pub, sid: "sid-12345678", now: T0 + 1000 };
  const g = await grant(approve, { sid: "sid-12345678", scope: "control", until: T0 + 10 * 60_000 });
  assert.deepEqual(await verifyControlGrant({ ...base, grant: g }), { ok: true, scope: "control", until: T0 + 10 * 60_000 });
  const code = async (p: Parameters<typeof verifyControlGrant>[0]) => { const r = await verifyControlGrant(p); return r.ok ? "ok" : r.code + ":" + r.message; };
  assert.match(await code({ ...base, grant: await grant(device, { sid: "sid-12345678", scope: "control", until: T0 + 60_000 }) }), /承認の鍵/, "送るための鍵（生体認証なし）では許せない");
  assert.match(await code({ ...base, grant: await grant(approve, { sid: "sid-12345678", scope: "control", until: T0 + 60_000 }, device.pub) }), /別の相手/);
  assert.match(await code({ ...base, sid: "sid-87654321", grant: g }), /別の相手・別の接続/);
  assert.match(await code({ ...base, now: T0 + 11 * 60_000, grant: g }), /期限/);
  assert.match(await code({ ...base, grant: await grant(approve, { sid: "sid-12345678", scope: "control", until: T0 + 31 * 60_000 }) }), /長すぎ/);
  assert.match(await code({ ...base, grant: { ...g, b: { ...g.b, scope: "control", until: T0 + 20 * 60_000 } } }), /RTC_SIGNATURE/, "期限の書き換え");
});

test("張り替え：切れかけたらすぐ、戻らなければ 5 秒ごと、20 秒で終える。回線が変わったら切れる前に張り替える", () => {
  const p = createRestartPolicy();
  assert.deepEqual(p.onState("connected", 0), []);
  assert.deepEqual(p.onNetworkChange(1000), ["restart"]);
  assert.deepEqual(p.onState("disconnected", 2000), ["restart"]);
  assert.deepEqual(p.onState("failed", 2500), [], "続けて切れかけても二重に張り替えない");
  assert.deepEqual(p.tick(6000), []);
  assert.deepEqual(p.tick(7000), ["restart"]);
  assert.deepEqual(p.onState("connected", 8000), []);
  assert.deepEqual(p.tick(30_000), [], "戻ったら止める");
  assert.deepEqual(p.onState("failed", 40_000), ["restart"]);
  assert.deepEqual(p.tick(45_000), ["restart"]);
  assert.deepEqual(p.tick(60_000), ["close"]);
  assert.deepEqual(p.tick(70_000), []);
  assert.deepEqual(p.onNetworkChange(71_000), [], "終えたあとは何もしない");
});

test("中継の許可：使える形の物だけを取り出し、Cloudflare の答えから許可を作る", async () => {
  assert.deepEqual(sanitizeIceServers({ iceServers: [{ urls: ["stun:stun.cloudflare.com:3478"] }, { urls: "turn:turn.cloudflare.com:3478?transport=udp", username: "u", credential: "c" }, { urls: ["turn:x"] }, { urls: ["javascript:alert(1)"] }] }),
    [{ urls: ["stun:stun.cloudflare.com:3478"] }, { urls: ["turn:turn.cloudflare.com:3478?transport=udp"], username: "u", credential: "c" }]);
  let asked: { url: string; auth: string | null; body: string } | undefined;
  const fake = (async (url: string, init: RequestInit) => {
    asked = { url, auth: new Headers(init.headers).get("authorization"), body: String(init.body) };
    return new Response(JSON.stringify({ iceServers: [{ urls: ["turns:turn.cloudflare.com:443?transport=tcp"], username: "u", credential: "c" }] }), { status: 201 });
  }) as unknown as typeof fetch;
  const g = await cloudflareTurn("key1", "tok", fake)();
  assert.equal(asked?.url, "https://rtc.live.cloudflare.com/v1/turn/keys/key1/credentials/generate-ice-servers");
  assert.equal(asked?.auth, "Bearer tok");
  assert.deepEqual(JSON.parse(asked!.body), { ttl: 86400 });
  assert.equal(g?.servers.length, 1);
  assert.equal(await cloudflareTurn("k", "t", (async () => new Response("", { status: 500 })) as unknown as typeof fetch)(), null);
});

test("計測：経路（直接・中継）・遅れ・方式・実装・コマ・欠けを記録の形にまとめる", () => {
  const s = summarizeRtcStats([
    { type: "candidate-pair", id: "p", state: "succeeded", nominated: true, localCandidateId: "l", remoteCandidateId: "r", currentRoundTripTime: 0.042, availableOutgoingBitrate: 5_000_000 },
    { type: "local-candidate", id: "l", candidateType: "relay", relayProtocol: "udp" },
    { type: "remote-candidate", id: "r", candidateType: "srflx" },
    { type: "codec", id: "c1", mimeType: "video/H265" },
    { type: "outbound-rtp", kind: "video", codecId: "c1", encoderImplementation: "VideoToolbox", framesPerSecond: 60, frameWidth: 1920, frameHeight: 1260, nackCount: 3, pliCount: 1, qualityLimitationReason: "bandwidth" },
    { type: "inbound-rtp", kind: "video", codecId: "c1", decoderImplementation: "VideoToolbox", framesPerSecond: 59, framesDropped: 2, freezeCount: 0, jitterBufferDelay: 1.5, jitterBufferEmittedCount: 100, packetsLost: 4, jitter: 0.003 },
  ]);
  assert.deepEqual(s, { path: "relay", local: "relay", remote: "srflx", relayProtocol: "udp", rttMs: 42, availableOutgoingBps: 5_000_000,
    out: { codec: "H265", impl: "VideoToolbox", fps: 60, width: 1920, height: 1260, nack: 3, pli: 1, limited: "bandwidth" },
    in: { codec: "H265", impl: "VideoToolbox", fps: 59, dropped: 2, freezes: 0, jitterBufferMs: 15, lost: 4, jitterMs: 3 } });
  assert.deepEqual(summarizeRtcStats([]), { path: "unknown" });
});

// ---- 部屋 ----
function sink() {
  const got: string[] = []; let closed: [number, string] | undefined;
  const s: RtcSink & { got: string[]; last(): any; closed(): [number, string] | undefined } = {
    got, send: (t) => void got.push(t), close: (c, r) => { closed = [c, r]; },
    last: () => JSON.parse(got[got.length - 1]!), closed: () => closed,
  };
  return s;
}

test("部屋：出入りを知らせ、連絡を相手にだけ渡す。送り手のなりすまし・いない相手・別の会社・満員は断る", async () => {
  const room = createRtcRoom({ co: "CO_A", purpose: "assist", now: () => T0 });
  const a = await createWebDeviceKey(), b = await createWebDeviceKey(), c = await createWebDeviceKey();
  const sa = sink(), sb = sink(), sc = sink(), sx = sink();
  assert.equal(room.join({ co: "CO_B", by: "x", pub: c.pub }, sx).ok, false);
  assert.equal(sx.closed()?.[0], 4403, "別の会社の部屋には入れない");
  room.join({ co: "CO_A", by: "emp-1", pub: a.pub, name: "山田" }, sa);
  assert.deepEqual(sa.last(), { t: "welcome", purpose: "assist", me: { pub: a.pub, by: "emp-1", name: "山田" }, peers: [] });
  room.join({ co: "CO_A", by: "emp-2", pub: b.pub }, sb);
  assert.deepEqual(sa.last(), { t: "presence", join: { pub: b.pub, by: "emp-2" } });
  assert.equal(sb.last().peers.length, 1);
  assert.equal(room.join({ co: "CO_A", by: "emp-3", pub: c.pub }, sc).ok, false);
  assert.equal(sc.closed()?.[0], 4409, "遠隔支援は 2 人まで");
  const offer = await signRtc(a, { t: "offer", room: ROOM, to: b.pub, b: { sid: "sid-12345678", sdp: SDP }, now: T0 });
  await room.receive(a.pub, JSON.stringify({ t: "msg", to: b.pub, m: offer }));
  assert.deepEqual(sb.last(), { t: "msg", from: a.pub, m: offer });
  await room.receive(a.pub, JSON.stringify({ t: "msg", to: b.pub, m: { ...offer, from: b.pub } }));
  assert.deepEqual(sa.last(), { t: "error", code: "FROM_MISMATCH" });
  await room.receive(a.pub, JSON.stringify({ t: "msg", to: c.pub, m: offer }));
  assert.deepEqual(sa.last(), { t: "undeliverable", to: c.pub });
  await room.receive(a.pub, "ping");
  assert.equal(sa.got[sa.got.length - 1], "pong");
  await room.receive(a.pub, "x".repeat(70_000));
  assert.deepEqual(sa.last(), { t: "error", code: "TOO_LARGE" });
  // 同じ端末が入り直したら、古い接続を閉じて置き換える（ほかの人には出入りを知らせない）
  const sa2 = sink();
  room.join({ co: "CO_A", by: "emp-1", pub: a.pub }, sa2);
  assert.equal(sa.closed()?.[0], 4000);
  room.leave(a.pub, sa);
  assert.equal(room.size, 2, "古い接続の切れでは出ない");
  room.leave(a.pub, sa2);
  assert.deepEqual(sb.last(), { t: "presence", leave: a.pub });
});

test("部屋：中継の許可は 12 時間だけ使い回す。送りすぎる相手は切る", async () => {
  let now = T0, calls = 0;
  const room = createRtcRoom({ co: "CO_A", purpose: "meeting", now: () => now, turn: async () => { calls++; return { servers: [{ urls: ["turn:t"], username: "u", credential: "c" }], ttl: 86400 }; } });
  const a = await createWebDeviceKey(); const sa = sink();
  room.join({ co: "CO_A", by: "e", pub: a.pub }, sa);
  await room.receive(a.pub, JSON.stringify({ t: "turn" }));
  await room.receive(a.pub, JSON.stringify({ t: "turn" }));
  assert.equal(calls, 1);
  assert.equal(sa.last().servers.length, 1);
  now += 13 * 3600_000;
  await room.receive(a.pub, JSON.stringify({ t: "turn" }));
  assert.equal(calls, 2);
  for (let i = 0; i < 401; i++) await room.receive(a.pub, "ping");
  assert.equal(sa.closed()?.[0], 4429);
  assert.equal(room.size, 0);
});

test("Cloudflare の部屋への受け渡し：本人の見出しは入口が付け直し、会社ごとの部屋へ渡す", async () => {
  let name = "", headers: Headers | undefined;
  const ns = { idFromName: (n: string) => { name = n; return n; }, get: () => ({ fetch: async (r: Request) => { headers = r.headers; return new Response("ok"); } }) };
  const a = await createWebDeviceKey();
  const req = new Request("https://hub.example/lch/v1/rtc/room-abcdefgh", { headers: { upgrade: "websocket", "x-lch-rtc-co": "EVIL" } });
  await rtcRoomRequest({ request: req, namespace: ns, room: "room-abcdefgh", purpose: "assist", who: { co: "CO_A", by: "emp-1", pub: a.pub, name: "山田" } });
  assert.equal(name, "CO_A:room-abcdefgh");
  assert.equal(headers?.get("x-lch-rtc-co"), "CO_A", "送り手が付けた見出しは使わない");
  assert.equal(headers?.get("x-lch-rtc-purpose"), "assist");
  assert.equal(decodeURIComponent(headers?.get("x-lch-rtc-name") ?? ""), "山田");
  const noWs = await rtcRoomRequest({ request: new Request("https://hub.example/x"), namespace: ns, room: "room-abcdefgh", purpose: "meeting", who: { co: "CO_A", by: "e", pub: a.pub } });
  assert.equal(noWs.status, 426);
  const badRoom = await rtcRoomRequest({ request: req, namespace: ns, room: "short", purpose: "meeting", who: { co: "CO_A", by: "e", pub: a.pub } });
  assert.equal(badRoom.status, 400);
});

test("相互の確認の見本（test/vectors/rtc.json）：TypeScript が署名した連絡が、今の決まりで通る（Swift・Kotlin も同じ見本を確かめる）", async () => {
  const { readFileSync } = await import("node:fs");
  const { rtcSignedText } = await import("../src/index.ts");
  const v = JSON.parse(readFileSync(new URL("./vectors/rtc.json", import.meta.url), "utf8"));
  assert.equal(rtcSignedText(v.offer), v.offerSignedText);
  const r = await createRtcVerifier({ me: v.me, room: v.room, now: () => v.now }).verify(v.offer);
  assert.equal(r.ok, true);
  const g = await verifyControlGrant({ grant: v.grant, approverKeys: v.approverKeys, supporter: v.supporter, sid: "sid-vector01", now: v.now + 1000 });
  assert.deepEqual(g, { ok: true, scope: "point", until: v.now + 600_000 });
});
