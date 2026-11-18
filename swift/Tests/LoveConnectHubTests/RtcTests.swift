import XCTest
@testable import LoveConnectHub

#if canImport(CryptoKit)
/// 映像・音声のリアルタイム通信（規格書 第23章）。TypeScript 版と同じ決まりか、TypeScript が署名した見本で確かめる
final class RtcTests: XCTestCase {
    private func vector() throws -> [String: JSONValue] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../test/vectors/rtc.json")
        guard case let .object(o) = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: url)) else { throw NSError(domain: "vector", code: 1) }
        return o
    }
    private func obj(_ v: JSONValue?) -> [String: JSONValue] { if case let .object(o)? = v { return o }; return [:] }
    private func str(_ v: JSONValue?) -> String { if case let .string(s)? = v { return s }; return "" }
    private func int(_ v: JSONValue?) -> Int { if case let .number(n)? = v { return Int(n) }; return 0 }

    func testSignedTextMatchesTypeScript() throws {
        let v = try vector()
        XCTAssertEqual(HubRtc.signedText(obj(v["offer"])), str(v["offerSignedText"]), "改行・引用符・日本語・制御文字を含む SDP でも同じ文になる")
        XCTAssertEqual(HubRtc.signedText(obj(v["grant"])), str(v["grantSignedText"]))
    }

    func testVerifiesTypeScriptOffer() throws {
        let v = try vector()
        let now = int(v["now"])
        let ver = HubRtcVerifier(me: str(v["me"]), room: str(v["room"]), now: { now })
        XCTAssertNil(ver.check(obj(v["offer"])))
        XCTAssertEqual(ver.check(obj(v["offer"])), "RTC_REPLAY")
        var swapped = obj(v["offer"]); var b = obj(swapped["b"]); b["sdp"] = .string(str(b["sdp"]).replacingOccurrences(of: ":01:02:", with: ":FF:02:")); swapped["b"] = .object(b)
        XCTAssertEqual(HubRtcVerifier(me: str(v["me"]), room: str(v["room"]), now: { now }).check(swapped), "RTC_SIGNATURE")
        XCTAssertEqual(HubRtcVerifier(me: str(v["me"]), room: "room-otherone", now: { now }).check(obj(v["offer"])), "RTC_ROOM")
        XCTAssertEqual(HubRtcVerifier(me: str(v["me"]), room: str(v["room"]), now: { now + 121_000 }).check(obj(v["offer"])), "RTC_CLOCK")
    }

    func testVerifiesTypeScriptGrant() throws {
        let v = try vector()
        let now = int(v["now"]) + 1000
        let keys: [String] = { if case let .array(a)? = v["approverKeys"] { return a.map { str($0) } }; return [] }()
        XCTAssertEqual(HubRtc.verifyControlGrant(obj(v["grant"]), approverKeys: keys, supporter: str(v["supporter"]), sid: "sid-vector01", now: now), HubRtc.Grant(scope: "point", until: int(v["now"]) + 600_000))
        XCTAssertNil(HubRtc.verifyControlGrant(obj(v["grant"]), approverKeys: [], supporter: str(v["supporter"]), sid: "sid-vector01", now: now), "承認の鍵の一覧に無い")
        XCTAssertNil(HubRtc.verifyControlGrant(obj(v["grant"]), approverKeys: keys, supporter: str(v["supporter"]), sid: "sid-vector01", now: now + 700_000), "期限切れ")
    }

    func testSignAndVerifyRoundTrip() throws {
        let a = SoftwareDeviceKey(), b = SoftwareDeviceKey()
        let m = try HubRtc.sign(key: a, t: "ice", room: "room-abcdefgh", to: b.publicKey, b: ["sid": "sid-12345678", "c": "candidate:1 1 udp 1 1.2.3.4 9 typ host", "mid": "0", "idx": 0], now: 1_000)
        XCTAssertNil(HubRtcVerifier(me: b.publicKey, room: "room-abcdefgh", now: { 1_000 }).check(m))
        XCTAssertEqual(HubRtcVerifier(me: a.publicKey, room: "room-abcdefgh", now: { 1_000 }).check(m), "RTC_TO")
    }

    func testSdpAndCodecs() {
        let fp = "a=fingerprint:sha-256 AA:BB"
        XCTAssertNil(HubRtc.sdpProblem("v=0\r\n\(fp)\r\n"))
        XCTAssertNotNil(HubRtc.sdpProblem("v=0\r\n"))
        XCTAssertNotNil(HubRtc.sdpProblem("v=0\r\na=fingerprint:sha-1 AA\r\n"))
        XCTAssertNotNil(HubRtc.sdpProblem("v=0\r\n\(fp)\r\na=fingerprint:sha-256 CC:DD\r\n"))
        let sdp = ["m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 102 104 106 45 120", "a=rtpmap:96 VP8/90000", "a=rtpmap:97 rtx/90000", "a=rtpmap:98 VP9/90000", "a=rtpmap:102 H264/90000",
                   "a=fmtp:102 profile-level-id=42e01f", "a=rtpmap:104 H264/90000", "a=fmtp:104 profile-level-id=640c34", "a=rtpmap:106 H265/90000", "a=rtpmap:45 AV1/90000", "a=rtpmap:120 flexfec-03/90000", ""].joined(separator: "\r\n")
        XCTAssertTrue(HubRtc.preferVideoCodecs(sdp).hasPrefix("m=video 9 UDP/TLS/RTP/SAVPF 106 104 102 98 45 96 97 120\r\n"), "src/rtc.ts と同じ並び")
    }

    func testBudgetSignalsAndRestart() {
        XCTAssertEqual(HubRtc.budget(source: "screen", network: "wifi", displayFps: 120).maxBitrate, 24_000_000)
        XCTAssertEqual(HubRtc.budget(source: "screen", network: "cellular", displayFps: 120).maxLongEdge, 1920)
        XCTAssertEqual(HubRtc.budget(source: "camera", network: "cellular").maxBitrate, 1_000_000)
        XCTAssertNotNil(HubRtc.checkAssistSignal(channel: "mv", scope: "point", raw: #"{"k":"pt","x":0.5,"y":0.2}"#))
        XCTAssertNil(HubRtc.checkAssistSignal(channel: "ctl", scope: "point", raw: #"{"k":"md","b":0}"#), "指し示すだけでは押せない")
        XCTAssertNil(HubRtc.checkAssistSignal(channel: "ctl", scope: "control", raw: #"{"k":"pw","s":"x"}"#), "パスワードは打たせない")
        XCTAssertNil(HubRtc.checkAssistSignal(channel: "mv", scope: "control", raw: #"{"k":"kd","c":5}"#))
        XCTAssertNil(HubRtc.checkAssistSignal(channel: "ctl", scope: "control", raw: #"{"k":"md","b":true}"#))
        let p = HubRestartPolicy()
        XCTAssertEqual(p.onState("disconnected", now: 0), ["restart"])
        XCTAssertEqual(p.tick(now: 5_000), ["restart"])
        XCTAssertEqual(p.tick(now: 20_000), ["close"])
        XCTAssertEqual(p.onNetworkChange(now: 21_000), [])
    }
}
#endif
