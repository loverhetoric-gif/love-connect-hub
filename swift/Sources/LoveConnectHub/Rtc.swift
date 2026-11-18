import Foundation
#if canImport(CryptoKit)
import CryptoKit

// 映像・音声のリアルタイム通信（規格書 第23章）。src/rtc.ts と同じ決まり。
// WebRTC そのもの（映像の送受信）は、アプリが入れる WebRTC の部品を使う。ここは、つなぐための連絡の署名と確かめ・SDP の確かめと並べ替え・
// 送る量の上限・遠隔支援の信号と許可の確かめ・張り替えの決まりだけを持つ。

/// 正規化 JSON（キーを並べ替え、空白なし。src/crypto.ts の canonicalJson と同じ文字になる）
public func hubCanonicalJSON(_ v: JSONValue) -> String {
    switch v {
    case .null: return "null"
    case let .bool(b): return b ? "true" : "false"
    case let .number(n):
        if n.rounded() == n, abs(n) < 9_007_199_254_740_992 { return String(Int64(n)) }
        return String(n)
    case let .string(s): return jsQuote(s)
    case let .array(a): return "[" + a.map(hubCanonicalJSON).joined(separator: ",") + "]"
    case let .object(o):
        // JavaScript の sort と同じく、UTF-16 の並びで比べる
        let keys = o.keys.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        return "{" + keys.map { jsQuote($0) + ":" + hubCanonicalJSON(o[$0]!) }.joined(separator: ",") + "}"
    }
}

/// JavaScript の JSON.stringify と同じ文字の書き方
func jsQuote(_ s: String) -> String {
    var out = "\""
    for u in s.unicodeScalars {
        switch u {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        case "\u{08}": out += "\\b"
        case "\u{0C}": out += "\\f"
        default:
            if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
        }
    }
    return out + "\""
}

public enum HubRtc {
    public static let skewMs = 120_000
    public static let nonceMs = 300_000
    public static let grantMaxMs = 30 * 60_000
    public static let signalMax = 16 * 1024
    static let types: Set<String> = ["offer", "answer", "ice", "restart", "bye", "grant", "revoke"]
    static let scopes: Set<String> = ["view", "point", "control"]

    /// 署名する文：lch-rtc-v1 ＋ 署名を除いた連絡の正規化 JSON
    public static func signedText(_ m: [String: JSONValue]) -> String {
        var rest: [String: JSONValue] = [:]
        for k in ["v", "t", "room", "from", "to", "ts", "n", "b"] { if let v = m[k] { rest[k] = v } }
        return "lch-rtc-v1\n" + hubCanonicalJSON(.object(rest))
    }

    /// 連絡を作って署名する（src/rtc.ts の signRtc と同じ）
    public static func sign(key: HubDeviceKey, t: String, room: String, to: String, b: [String: JSONValue], now: Int) throws -> [String: JSONValue] {
        var n = Data(count: 16)
        let ok = n.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard ok == errSecSuccess else { throw DraftError(code: "RANDOM", field: "", message: "乱数を作れません") }
        var m: [String: JSONValue] = ["v": 1, "t": .string(t), "room": .string(room), "from": .string(key.publicKey), "to": .string(to), "ts": .number(Double(now)), "n": .string(b64u(n)), "b": .object(b)]
        m["sig"] = .string(b64u(try key.sign(Data(signedText(m).utf8))))
        return m
    }

    /// 端末の公開鍵（base64url の 65 バイト）で、r||s の署名を確かめる
    public static func verifySignature(pub: String, sig: String, message: String) -> Bool {
        guard let p = b64uDecode(pub), p.count == 65, let s = b64uDecode(sig), s.count == 64,
              let key = try? P256.Signing.PublicKey(x963Representation: p),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: s) else { return false }
        return key.isValidSignature(signature, for: Data(message.utf8))
    }

    // ---- SDP ----

    /// SDP の安全の確かめ：暗号の鍵の指紋が 1 つ以上あり、すべて SHA-256 以上で、同じ鍵を指す。通れば nil
    public static func sdpProblem(_ sdp: String) -> String? {
        var fps: [String] = []
        for line in sdp.components(separatedBy: "\n") {
            let l = line.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
            guard l.hasPrefix("a=fingerprint:") else { continue }
            let parts = l.dropFirst("a=fingerprint:".count).split(separator: " ")
            guard parts.count == 2 else { continue }
            let hash = parts[0].lowercased()
            if !["sha-256", "sha-384", "sha-512"].contains(hash) { return "弱い指紋（SHA-1 など）は使えません" }
            fps.append(hash + " " + parts[1].uppercased())
        }
        if fps.isEmpty { return "暗号の鍵の指紋がありません" }
        if Set(fps).count != 1 { return "指紋が食い違っています" }
        return nil
    }

    public static let videoOrder = ["H265", "H264", "VP9", "AV1", "VP8"]

    /// 映像の方式を優先順に並べ替える（src/rtc.ts の preferVideoCodecs と同じ）
    public static func preferVideoCodecs(_ sdp: String, order: [String] = videoOrder) -> String {
        let nl = sdp.contains("\r\n") ? "\r\n" : "\n"
        var lines = sdp.components(separatedBy: nl)
        var i = 0
        while i < lines.count {
            guard lines[i].hasPrefix("m=video ") else { i += 1; continue }
            var end = i + 1
            while end < lines.count, !lines[end].hasPrefix("m=") { end += 1 }
            let head = lines[i].split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            let pts = Array(head.dropFirst(3))
            var name: [String: String] = [:], fmtp: [String: String] = [:]
            for k in (i + 1)..<end {
                let l = lines[k]
                if l.hasPrefix("a=rtpmap:"), let sp = l.firstIndex(of: " ") {
                    let pt = String(l[l.index(l.startIndex, offsetBy: 9)..<sp])
                    name[pt] = String(l[l.index(after: sp)...].split(separator: "/").first ?? "").uppercased()
                } else if l.hasPrefix("a=fmtp:"), let sp = l.firstIndex(of: " ") {
                    fmtp[String(l[l.index(l.startIndex, offsetBy: 7)..<sp])] = String(l[l.index(after: sp)...])
                }
            }
            func rank(_ pt: String) -> Int { order.firstIndex(of: name[pt] ?? "") ?? order.count }
            func h264(_ pt: String) -> Int {
                guard let f = fmtp[pt], let r = f.range(of: "profile-level-id=") else { return 2 }
                let p = f[r.upperBound...].prefix(2).lowercased()
                return p == "64" ? 0 : p == "4d" ? 1 : 2
            }
            let sorted = pts.enumerated().sorted { a, b in
                let ra = rank(a.element), rb = rank(b.element)
                if ra != rb { return ra < rb }
                if name[a.element] == "H264", name[b.element] == "H264", h264(a.element) != h264(b.element) { return h264(a.element) < h264(b.element) }
                return a.offset < b.offset
            }.map(\.element)
            lines[i] = (head.prefix(3) + sorted).joined(separator: " ")
            i = end
        }
        return lines.joined(separator: nl)
    }

    // ---- 送る量の上限（src/rtc.ts の rtcBudget と同じ） ----

    public struct Budget: Equatable, Sendable {
        public let maxBitrate: Int, maxFps: Int, maxLongEdge: Int, audioBitrate: Int
        /// "motion" "detail" "text"
        public let contentHint: String
        /// "maintain-framerate" "maintain-resolution"
        public let degradation: String
    }

    /// source："camera" か "screen"。network："wifi" "cellular" "unknown"
    public static func budget(source: String, network: String, displayFps: Int = 60) -> Budget {
        let cell = network == "cellular"
        let fps = max(1, min(240, displayFps))
        if source == "screen" {
            if cell { return Budget(maxBitrate: 6_000_000, maxFps: min(fps, 60), maxLongEdge: 1920, audioBitrate: 24_000, contentHint: "text", degradation: "maintain-resolution") }
            return Budget(maxBitrate: fps > 60 ? 24_000_000 : 16_000_000, maxFps: min(fps, 120), maxLongEdge: 3840, audioBitrate: 32_000, contentHint: "text", degradation: "maintain-resolution")
        }
        if cell { return Budget(maxBitrate: 1_000_000, maxFps: min(fps, 30), maxLongEdge: 960, audioBitrate: 24_000, contentHint: "motion", degradation: "maintain-framerate") }
        return Budget(maxBitrate: 2_500_000, maxFps: min(fps, 30), maxLongEdge: 1280, audioBitrate: 32_000, contentHint: "motion", degradation: "maintain-framerate")
    }

    // ---- 遠隔支援の信号（src/rtc.ts の checkAssistSignal と同じ） ----

    static let supporterSignals: [String: Set<String>] = [
        "view": ["st"], "point": ["st", "pt"],
        "control": ["st", "pt", "rm", "ma", "md", "mu", "sc", "kd", "ku", "tx", "rel"],
    ]
    static let mvSignals: Set<String> = ["rm", "ma", "cur", "pt"]

    /// 支援する人から届いた信号を確かめる。channel は "ctl" か "mv"。通れば信号、通らなければ nil
    public static func checkAssistSignal(channel: String, scope: String?, raw: String) -> [String: Any]? {
        guard raw.utf16.count <= signalMax, let d = raw.data(using: .utf8),
              let s = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any], let k = s["k"] as? String else { return nil }
        if channel == "mv", !mvSignals.contains(k) { return nil }
        guard let scope, supporterSignals[scope]?.contains(k) == true else { return nil }
        func num(_ v: Any?, _ lo: Double, _ hi: Double) -> Bool {
            guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
            let x = n.doubleValue
            return x.isFinite && x >= lo && x <= hi
        }
        let ok: Bool
        switch k {
        case "rm": ok = num(s["dx"], -10_000, 10_000) && num(s["dy"], -10_000, 10_000)
        case "ma", "pt": ok = num(s["x"], 0, 1) && num(s["y"], 0, 1)
        case "md", "mu": ok = [0, 1, 2].contains((s["b"] as? NSNumber)?.intValue ?? -1) && num(s["b"], 0, 2)
        case "sc": ok = num(s["dx"], -100_000, 100_000) && num(s["dy"], -100_000, 100_000)
        case "kd", "ku": ok = num(s["c"], 0, 0xffff) && (s["c"] as? NSNumber).map { $0.doubleValue.rounded() == $0.doubleValue } == true
        case "tx": ok = (s["s"] as? String).map { $0.utf16.count <= 4096 } ?? false
        default: ok = true
        }
        return ok ? s : nil
    }

    // ---- 遠隔操作の許可（src/rtc.ts の verifyControlGrant と同じ） ----

    public struct Grant: Equatable, Sendable { public let scope: String; public let until: Int }

    /// 支援される本人の承認の鍵で署名した grant を確かめる。通れば範囲と期限、通らなければ nil
    public static func verifyControlGrant(_ g: [String: JSONValue], approverKeys: [String], supporter: String, sid: String, now: Int) -> Grant? {
        guard case .string("grant")? = g["t"], case .number(1)? = g["v"], case let .string(from)? = g["from"], case let .string(to)? = g["to"],
              case let .number(tsD)? = g["ts"], case let .object(b)? = g["b"], case let .string(sig)? = g["sig"],
              case let .string(gsid)? = b["sid"], case let .string(scope)? = b["scope"], case let .number(untilD)? = b["until"],
              scopes.contains(scope), approverKeys.contains(from), to == supporter, gsid == sid else { return nil }
        let until = Int(untilD), ts = Int(tsD)
        guard until > now, until - ts <= grantMaxMs, ts <= now + skewMs else { return nil }
        guard verifySignature(pub: from, sig: sig, message: signedText(g)) else { return nil }
        return Grant(scope: scope, until: until)
    }
}

/// 受け取った連絡の確かめ（src/rtc.ts の createRtcVerifier と同じ）。使い捨ての番号は 5 分覚える
public final class HubRtcVerifier: @unchecked Sendable {
    public let me: String, room: String
    private let now: () -> Int
    private var seen: [String: Int] = [:]
    private let lock = NSLock()

    public init(me: String, room: String, now: @escaping () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }) {
        self.me = me; self.room = room; self.now = now
    }

    /// 通れば nil、通らなければ拒否の名前（RTC_BAD・RTC_ROOM・RTC_TO・RTC_CLOCK・RTC_SDP・RTC_SIGNATURE・RTC_REPLAY）
    public func check(_ m: [String: JSONValue]) -> String? {
        guard Set(m.keys) == ["v", "t", "room", "from", "to", "ts", "n", "b", "sig"],
              case .number(1)? = m["v"], case let .string(t)? = m["t"], HubRtc.types.contains(t),
              case let .string(r)? = m["room"], case let .string(from)? = m["from"], case let .string(to)? = m["to"],
              case let .number(tsD)? = m["ts"], case let .string(n)? = m["n"], n.count == 22, case let .string(sig)? = m["sig"],
              case let .object(b)? = m["b"], from.count == 87, to.count == 87 else { return "RTC_BAD" }
        if r != room { return "RTC_ROOM" }
        if to != me { return "RTC_TO" }
        let nowMs = now()
        if abs(nowMs - Int(tsD)) > HubRtc.skewMs { return "RTC_CLOCK" }
        guard case let .string(sid)? = b["sid"], (8...64).contains(sid.count) else { return "RTC_BAD" }
        if t == "offer" || t == "answer" {
            guard case let .string(sdp)? = b["sdp"], sdp.utf16.count <= 48 * 1024 else { return "RTC_BAD" }
            if HubRtc.sdpProblem(sdp) != nil { return "RTC_SDP" }
        }
        if !HubRtc.verifySignature(pub: from, sig: sig, message: HubRtc.signedText(m)) { return "RTC_SIGNATURE" }
        lock.lock(); defer { lock.unlock() }
        seen = seen.filter { nowMs - $0.value < HubRtc.nonceMs }
        let key = from + "\u{0}" + n
        if seen[key] != nil { return "RTC_REPLAY" }
        seen[key] = nowMs
        return nil
    }
}

/// 張り替えの決まり（src/rtc.ts の createRestartPolicy と同じ）。返す値は "restart" か "close"
public final class HubRestartPolicy: @unchecked Sendable {
    private let retryMs: Int, giveUpMs: Int
    private var since: Int?, last = 0, closed = false
    public init(retryMs: Int = 5_000, giveUpMs: Int = 20_000) { self.retryMs = retryMs; self.giveUpMs = giveUpMs }

    /// state："connected" "disconnected" "failed" "closed" など
    public func onState(_ state: String, now: Int) -> [String] {
        if closed { return [] }
        if state == "connected" { since = nil; return [] }
        if state == "closed" { closed = true; return [] }
        if state == "disconnected" || state == "failed", since == nil { since = now; last = now; return ["restart"] }
        return []
    }
    public func onNetworkChange(now: Int) -> [String] {
        if closed { return [] }
        last = now
        return ["restart"]
    }
    public func tick(now: Int) -> [String] {
        guard !closed, let since else { return [] }
        if now - since >= giveUpMs { closed = true; return ["close"] }
        if now - last >= retryMs { last = now; return ["restart"] }
        return []
    }
}

func b64uDecode(_ s: String) -> Data? {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    return Data(base64Encoded: t)
}
#endif
