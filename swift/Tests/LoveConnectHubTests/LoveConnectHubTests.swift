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
        // 許可表に無い形式は断られる
        let denied = await c.send(Draft(lane: .record, format: "record.attendance.other"))
        XCTAssertEqual(denied, .failed(status: 403, code: "FORMAT_NOT_ALLOWED", attempts: 1))
        // トークンが違えば断られる
        let bad = try HubUserClient(url: url, token: { _ in tok + "x" })
        let r2 = await bad.send(Draft(lane: .record, format: "record.attendance.clockin"))
        XCTAssertEqual(r2, .failed(status: 401, code: "TOKEN_INVALID", attempts: 1))
    }
}
