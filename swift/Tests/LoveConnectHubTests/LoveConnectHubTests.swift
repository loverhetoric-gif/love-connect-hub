import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import LoveConnectHub

/// 偽の通信の口。決めた順に応答を返し、届いた要求を覚える
final class FakeTransport: HubTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var replies: [(Int, String, [String: String])]
    private(set) var requests: [URLRequest] = []
    init(_ replies: [(Int, String, [String: String])]) { self.replies = replies }
    func post(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let r: (Int, String, [String: String])? = lock.withLock {
            requests.append(request)
            return replies.isEmpty ? nil : replies.removeFirst()
        }
        guard let (status, body, headers) = r else { throw URLError(.notConnectedToInternet) }
        if status == 0 { throw URLError(.timedOut) }
        let res = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        return (Data(body.utf8), res)
    }
    var count: Int { lock.withLock { requests.count } }
    func body(_ i: Int) -> [String: Any] {
        lock.withLock { (try? JSONSerialization.jsonObject(with: requests[i].httpBody ?? Data())) as? [String: Any] ?? [:] }
    }
    func auth(_ i: Int) -> String? { lock.withLock { requests[i].value(forHTTPHeaderField: "authorization") } }
}

final class TokenBox: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var asked: [Bool] = []
    func get(_ refresh: Bool) -> String { lock.withLock { asked.append(refresh) }; return refresh ? "fresh-token" : "old-token" }
}

let hub = URL(string: "https://hub.example/lch/v1/user")!

func client(_ t: FakeTransport, _ box: TokenBox = TokenBox(), now: @escaping @Sendable () -> Int = { 1_000 }) throws -> HubUserClient {
    try HubUserClient(url: hub, token: { box.get($0) }, transport: t, sleep: { _ in }, random: { 0.5 }, now: now)
}

final class DraftTests: XCTestCase {
    func testValidDraftHasNoStampedFields() throws {
        let d = Draft(lane: .record, format: "record.attendance.clockin", id: "clk-00000001", body: ["kind": "in"])
        XCTAssertNil(d.check())
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(d)) as! [String: Any]
        XCTAssertEqual(Set(json.keys), ["v", "l", "f", "id", "b"])
        for k in ["co", "by", "at", "sig", "e"] { XCTAssertNil(json[k]) }
    }

    func testRejectsBeforeSending() {
        let cases: [(Draft, String, String)] = [
            (Draft(lane: .key, format: "key.vault.token", ref: "ut:x"), "LANE_NOT_ALLOWED", "l"),
            (Draft(lane: .record, format: "event.work.x"), "BAD_FIELD", "f"),
            (Draft(lane: .record, format: "record"), "BAD_FIELD", "f"),
            (Draft(lane: .record, format: "record.Work.x"), "BAD_FIELD", "f"),
            (Draft(lane: .record, format: "record.work.x", id: "short"), "BAD_FIELD", "id"),
            (Draft(lane: .record, format: "record.work.x", classification: .open), "CLASS_TOO_LOW", "c"),
            (Draft(lane: .sync, format: "sync.comms.msg", seq: 1), "MISSING_FIELD", "bv"),
            (Draft(lane: .media, format: "media.expense.receipt", body: "x", ref: "r", length: 1, hash: String(repeating: "a", count: 64)), "BODY_FORBIDDEN", "b"),
            (Draft(lane: .api, format: "api.transit.search", body: 1, ref: "r"), "BODY_AND_REF", "b"),
            (Draft(lane: .event, format: "event.work.x", body: .string(String(repeating: "あ", count: 6000))), "BODY_TOO_LARGE", "b"),
            (Draft(lane: .record, format: "record.work.x", deadlineMs: 700_000), "BAD_FIELD", "dl"),
            (Draft(lane: .media, format: "media.expense.receipt", ref: "r", length: 1, hash: "XYZ"), "BAD_FIELD", "h"),
        ]
        for (d, code, field) in cases {
            let e = d.check()
            XCTAssertEqual(e?.code, code, d.f)
            XCTAssertEqual(e?.field, field, d.f)
        }
    }

    func testTaskIdMakesVersion2AndIsChecked() throws {
        // 作業 ID を付けると第2版、付けなければ第1版のまま（規格書 第22章）
        let plain = Draft(lane: .record, format: "record.attendance.clockin", id: "clk-00000001")
        XCTAssertEqual(plain.v, 1)
        let tagged = Draft(lane: .record, format: "record.attendance.clockin", id: "clk-00000001", task: "w-Ab12Cd34")
        XCTAssertEqual(tagged.v, 2)
        XCTAssertNil(tagged.check())
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(tagged)) as! [String: Any]
        XCTAssertEqual(json["tk"] as? String, "w-Ab12Cd34")
        XCTAssertEqual(json["v"] as? Int, 2)
        let plainJson = try JSONSerialization.jsonObject(with: JSONEncoder().encode(plain)) as! [String: Any]
        XCTAssertNil(plainJson["tk"])
        XCTAssertEqual(plainJson["v"] as? Int, 1)
        for bad in ["w-12", "W-Ab12Cd34", "w-Ab12_d34", "w-Ab12Cd345"] {
            XCTAssertEqual(Draft(lane: .record, format: "record.a.b", task: bad).check()?.field, "tk", bad)
        }
        var old = tagged
        old.v = 1
        XCTAssertEqual(old.check()?.code, "UNKNOWN_FIELD")
        old.v = 3
        XCTAssertEqual(old.check()?.code, "BAD_VERSION")
    }

    func testIdsAreUniqueAndUrlSafe() {
        let ids = (0..<200).map { _ in newMessageId() }
        XCTAssertEqual(Set(ids).count, 200)
        for id in ids { XCTAssertEqual(id.count, 22); XCTAssertNil(id.rangeOfCharacter(from: CharacterSet(charactersIn: "+/="))) }
    }

    func testLanesMatchSpec() {
        XCTAssertEqual(Lane.allCases.map(\.profile.priority), Array(0...7))
        XCTAssertEqual(Lane.record.profile.inlineMax, 65536)
        XCTAssertEqual(Lane.key.profile.minClass, .secret)
        XCTAssertEqual(Lane.media.profile.required, ["ref", "len", "h"])
    }
}

final class ClientTests: XCTestCase {
    func testSendsBearerTokenAndReturnsReply() async throws {
        let t = FakeTransport([(200, #"{"ok":true,"id":"clk-00000001","at":5,"b":{"saved":true}}"#, [:])])
        let r = try await client(t).send(Draft(lane: .record, format: "record.attendance.clockin", id: "clk-00000001", body: ["kind": "in"]))
        XCTAssertEqual(r, .delivered(id: "clk-00000001", at: 5, body: ["saved": true], duplicate: false, attempts: 1))
        XCTAssertEqual(t.auth(0), "Bearer old-token")
        XCTAssertEqual(t.requests[0].value(forHTTPHeaderField: "content-type"), "application/json")
    }

    func testRefreshesTokenOnceWhenExpired() async throws {
        let box = TokenBox()
        let t = FakeTransport([
            (401, #"{"ok":false,"code":"TOKEN_EXPIRED"}"#, [:]),
            (202, #"{"ok":true,"id":"clk-00000002","at":7}"#, [:]),
        ])
        let r = try await client(t, box).send(Draft(lane: .record, format: "record.attendance.clockin", id: "clk-00000002"))
        XCTAssertEqual(r, .delivered(id: "clk-00000002", at: 7, body: nil, duplicate: false, attempts: 1))
        XCTAssertEqual(box.asked, [false, true])
        XCTAssertEqual(t.auth(1), "Bearer fresh-token")
    }

    func testDoesNotLoopOnRepeatedExpiry() async throws {
        let t = FakeTransport([
            (401, #"{"code":"TOKEN_EXPIRED"}"#, [:]),
            (401, #"{"code":"TOKEN_EXPIRED"}"#, [:]),
        ])
        let r = try await client(t).send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r, .failed(status: 401, code: "TOKEN_EXPIRED", attempts: 1))
        XCTAssertEqual(t.count, 2)
    }

    func testRetriesTemporaryFailuresWithSameId() async throws {
        let t = FakeTransport([(503, "", [:]), (0, "", [:]), (202, #"{"ok":true}"#, [:])])
        let r = try await client(t).send(Draft(lane: .record, format: "record.attendance.clockin", id: "same-id-0001"))
        XCTAssertEqual(r, .delivered(id: "same-id-0001", at: nil, body: nil, duplicate: false, attempts: 3))
        XCTAssertEqual((0..<3).map { t.body($0)["id"] as? String }, Array(repeating: "same-id-0001", count: 3))
    }

    func testDuplicateMeansDelivered() async throws {
        let t = FakeTransport([(409, #"{"ok":false,"code":"DUPLICATE"}"#, [:])])
        let r = try await client(t).send(Draft(lane: .record, format: "record.attendance.clockin", id: "dup-00000001"))
        XCTAssertEqual(r, .delivered(id: "dup-00000001", at: nil, body: nil, duplicate: true, attempts: 1))
    }

    func testDoesNotRetryRejections() async throws {
        let t = FakeTransport([(403, #"{"ok":false,"code":"FORMAT_NOT_ALLOWED"}"#, [:])])
        let r = try await client(t).send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r, .failed(status: 403, code: "FORMAT_NOT_ALLOWED", attempts: 1))
        XCTAssertEqual(t.count, 1)
    }

    func testStopsAtDeadline() async throws {
        // 締め切り 300 ミリ秒、待ち時間 150 ミリ秒（200 の半分＋ばらつき）。時計は 1 回目のあと 200 進む
        let clock = Clock()
        let t = FakeTransport([(503, "", [:]), (503, "", [:]), (503, "", [:])])
        let c = try HubUserClient(url: hub, token: { _ in "t" }, transport: t, sleep: { ms in clock.advance(ms) }, random: { 0.5 }, now: { clock.now })
        let r = await c.send(Draft(lane: .record, format: "record.attendance.clockin", deadlineMs: 300))
        XCTAssertEqual(r, .failed(status: 503, code: nil, attempts: 2))
    }

    func testInvalidDraftIsNotSent() async throws {
        let t = FakeTransport([])
        let r = try await client(t).send(Draft(lane: .key, format: "key.vault.token", ref: "ut:x"))
        guard case let .invalid(e) = r else { return XCTFail("送ってはいけない") }
        XCTAssertEqual(e.code, "LANE_NOT_ALLOWED")
        XCTAssertEqual(t.count, 0)
    }

    func testOnlyHttps() {
        XCTAssertThrowsError(try HubUserClient(url: URL(string: "http://hub.example/x")!, token: { _ in "" }))
        XCTAssertNoThrow(try HubUserClient(url: URL(string: "http://localhost:8787/x")!, token: { _ in "" }))
    }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var t = 1_000
    var now: Int { lock.withLock { t } }
    func advance(_ ms: Int) { lock.withLock { t += ms } }
}

#if canImport(CryptoKit)
/// 端末の鍵（規格書 第21章）
final class DeviceKeyTests: XCTestCase {
    func testProofHeaderShape() throws {
        let key = SoftwareDeviceKey()
        XCTAssertEqual(key.publicKeyRaw.count, 65)
        XCTAssertEqual(key.publicKeyRaw.first, 0x04)
        XCTAssertEqual(key.publicKey.count, 87)
        let h = try hubDeviceProof(key: key, method: "POST", path: "/lch/v1/user", token: "t", body: Data("{}".utf8), now: 1_000)
        let parts = h.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 5)
        XCTAssertEqual(parts[0], "v1")
        XCTAssertEqual(parts[1], key.publicKey)
        XCTAssertEqual(parts[2], "1000")
        XCTAssertEqual(parts[3].count, 22)
        XCTAssertEqual(parts[4].count, 86)
        XCTAssertFalse(h.contains("=") || h.contains("+") || h.contains("/"))
    }

    func testSendsNewProofOnEveryRetry() async throws {
        let t = FakeTransport([(503, "{}", [:]), (202, #"{"ok":true,"id":"x","at":5}"#, [:])])
        let c = try HubUserClient(url: hub, token: { _ in "tok" }, device: SoftwareDeviceKey(), transport: t, sleep: { _ in }, random: { 0.5 }, now: { 1_000 })
        let r = await c.send(Draft(lane: .record, format: "record.attendance.clockin", id: "same-id-01"))
        guard case .delivered = r else { return XCTFail("\(r)") }
        let p0 = t.requests[0].value(forHTTPHeaderField: "lch-device"), p1 = t.requests[1].value(forHTTPHeaderField: "lch-device")
        XCTAssertNotNil(p0)
        XCTAssertNotEqual(p0, p1, "送り直しでは番号が変わる")
        XCTAssertEqual(t.body(0)["id"] as? String, t.body(1)["id"] as? String, "下書きの番号は同じ")
    }

    func testPairingRequestShape() throws {
        let key = SoftwareDeviceKey()
        let b = try hubPairingRequest(key: key, co: "CO_A", by: "emp-1", use: "device", code: "c")
        XCTAssertEqual(Set(b.keys), ["pub", "use", "code", "sig"])
        XCTAssertEqual(b["pub"], key.publicKey)
        XCTAssertEqual(b["sig"]?.count, 86)
    }

    func testAppAttestClientDataHashMatchesTypeScript() {
        // src/appattest.ts の appAttestClientDataHash と同じ値になること
        let h = hubAppAttestClientDataHash(co: "CO_A", by: "emp-1", use: "approve", pub: "PUB")
        XCTAssertEqual(h.map { String(format: "%02x", $0) }.joined(), "92176b126fb96921487fd63660f7a2a4afa7dad8523196c54132533456676cc1")
    }
}
#endif

/// 本物の受け口（TypeScript）との相互の確認。LCH_INTEROP_URL と LCH_INTEROP_TOKEN があるときだけ動く
final class InteropTests: XCTestCase {
    func testTalksToTypeScriptGateway() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let u = env["LCH_INTEROP_URL"], let tok = env["LCH_INTEROP_TOKEN"], let url = URL(string: u) else {
            throw XCTSkip("相互の確認の受け口がありません")
        }
        let c = try HubUserClient(url: url, token: { _ in tok })
        let id = newMessageId()
        let r = await c.send(Draft(lane: .record, format: "record.attendance.clockin", id: id, body: ["kind": "in", "minutes": 480]))
        guard case let .delivered(gotId, at, body, dup, _) = r else { return XCTFail("届かなかった：\(r)") }
        XCTAssertEqual(gotId, id)
        XCTAssertNotNil(at)
        XCTAssertFalse(dup)
        // 会社と送り手は、トークンから土台が付けたもの
        XCTAssertEqual(body, ["echo": ["kind": "in", "minutes": 480], "by": "swift-user", "co": "CO_TEST"])
        // 同じ番号の送り直しは、届いたものとして扱われる
        let again = await c.send(Draft(lane: .record, format: "record.attendance.clockin", id: id, body: ["kind": "in", "minutes": 480]))
        XCTAssertEqual(again, .delivered(id: id, at: nil, body: nil, duplicate: true, attempts: 1))
        // 作業 ID を付けた下書きは第2版で届き、作業 ID はそのまま正式な封筒に入る（規格書 第22章）
        let tagged = await c.send(Draft(lane: .record, format: "record.attendance.clockin", body: ["kind": "out"], task: "w-Sw1ftT4k"))
        guard case let .delivered(_, _, tbody, _, _) = tagged else { return XCTFail("作業 ID の付いた下書きが届かなかった：\(tagged)") }
        XCTAssertEqual(tbody, ["echo": ["kind": "out"], "by": "swift-user", "co": "CO_TEST", "tk": "w-Sw1ftT4k", "v": 2])
        // 許可表に無い形式は断られる
        let denied = await c.send(Draft(lane: .record, format: "record.attendance.other"))
        XCTAssertEqual(denied, .failed(status: 403, code: "FORMAT_NOT_ALLOWED", attempts: 1))
        // トークンが違えば断られる
        let bad = try HubUserClient(url: url, token: { _ in tok + "x" })
        let r2 = await bad.send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r2, .failed(status: 401, code: "TOKEN_INVALID", attempts: 1))
    }

    #if canImport(CryptoKit)
    /// 端末の鍵：登録してから、端末の証明つきで送る（本物の受け口が署名を確かめる）
    func testDeviceKeyWithTypeScriptGateway() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let u = env["LCH_INTEROP_URL"], let tok = env["LCH_INTEROP_TOKEN"], let code = env["LCH_INTEROP_CODE"], let base = URL(string: u) else {
            throw XCTSkip("相互の確認の受け口がありません")
        }
        let deviceUrl = base.deletingLastPathComponent().appendingPathComponent("device")
        let userDevice = base.deletingLastPathComponent().appendingPathComponent("user-device")
        let key = SoftwareDeviceKey()
        // 登録していない端末は断られる
        let before = try HubUserClient(url: userDevice, token: { _ in tok }, device: key)
        let r0 = await before.send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r0, .failed(status: 403, code: "DEVICE_UNKNOWN", attempts: 1))
        // 合言葉で登録する
        let e = await HubUserClient.enroll(url: deviceUrl, token: tok, device: key, co: "CO_TEST", by: "swift-user", code: code)
        guard case .delivered = e else { return XCTFail("登録できなかった：\(e)") }
        // 同じ合言葉の 2 回目は断られる
        let e2 = await HubUserClient.enroll(url: deviceUrl, token: tok, device: SoftwareDeviceKey(), co: "CO_TEST", by: "swift-user", code: code)
        XCTAssertEqual(e2, .failed(status: 403, code: "PAIR_CODE", attempts: 1))
        // 登録した端末から送れる
        let r1 = await before.send(Draft(lane: .record, format: "record.attendance.clockin", body: ["kind": "in"]))
        guard case let .delivered(_, _, body, _, _) = r1 else { return XCTFail("届かなかった：\(r1)") }
        XCTAssertEqual(body, ["echo": ["kind": "in"], "by": "swift-user", "co": "CO_TEST"])
        // 端末の証明が無ければ、正しいトークンでも断られる
        let noDevice = try HubUserClient(url: userDevice, token: { _ in tok })
        let r2 = await noDevice.send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r2, .failed(status: 401, code: "DEVICE_MISSING", attempts: 1))
    }
    #endif
}
