import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// 通信の口（差し替えられる。テストでは偽物を使う）
public protocol HubTransport: Sendable {
    func post(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// 標準の URLSession を使う通信の口。転送（リダイレクト）は追わない
public struct URLSessionTransport: HubTransport {
    public init() {}
    public func post(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, res) = try await URLSession.shared.data(for: request)
        guard let http = res as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }
}

/// 送った結果
public enum HubSendResult: Sendable, Equatable {
    /// 届いた。duplicate は、前の送信がすでに届いていたとき
    case delivered(id: String, at: Int?, body: JSONValue?, duplicate: Bool, attempts: Int)
    /// 断られた・届かなかった。code は土台の拒否の名前（分かるとき）
    case failed(status: Int, code: String?, attempts: Int)
    /// 送る前に止めた（下書きの誤り）
    case invalid(DraftError)
}

/// やり直しの決まり（規格書 第15章と同じ）
public struct RetryPolicy: Sendable {
    public var attempts = 4
    public var baseMs = 200
    public var maxMs = 5000
    public init() {}

    /// やり直してよい状態か。0 は通信できなかったとき
    public static func isRetryable(_ status: Int) -> Bool {
        status == 0 || status == 408 || status == 425 || status == 429 || (500...599).contains(status) && status != 501
    }
}

private struct Reply: Decodable {
    var ok: Bool?
    var code: String?
    var id: String?
    var at: Int?
    var b: JSONValue?
}

/// アプリ側の送り口（規格書 第18章）。src/user.ts の createUserClient と同じ動きにする。
/// - 署名用・暗号化用の鍵は持たない。ログインのトークンだけを付ける
/// - 一時的な失敗だけを、同じ番号でやり直す
/// - 期限切れ（TOKEN_EXPIRED）のときだけ、トークンを取り直して一度だけ送り直す
/// - 受け取り済み（409 DUPLICATE）は、届いたものとして扱う
public final class HubUserClient: Sendable {
    public typealias TokenProvider = @Sendable (_ refresh: Bool) async throws -> String

    private let url: URL
    private let token: TokenProvider
    private let transport: HubTransport
    private let retry: RetryPolicy
    private let sleep: @Sendable (Int) async -> Void
    private let random: @Sendable () -> Double
    private let now: @Sendable () -> Int

    public init(
        url: URL, token: @escaping TokenProvider, transport: HubTransport = URLSessionTransport(), retry: RetryPolicy = RetryPolicy(),
        sleep: @escaping @Sendable (Int) async -> Void = { ms in try? await Task.sleep(nanoseconds: UInt64(ms) * 1_000_000) },
        random: @escaping @Sendable () -> Double = { Double.random(in: 0..<1) },
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }
    ) throws {
        let host = url.host ?? ""
        let local = host == "localhost" || host == "127.0.0.1"
        guard url.scheme == "https" || (local && url.scheme == "http") else {
            throw DraftError(code: "INSECURE_URL", field: "url", message: "送り先は https にしてください")
        }
        self.url = url; self.token = token; self.transport = transport; self.retry = retry
        self.sleep = sleep; self.random = random; self.now = now
    }

    public func send(_ draft: Draft) async -> HubSendResult {
        if let e = draft.check() { return .invalid(e) }
        let enc = JSONEncoder()
        enc.outputFormatting = [.withoutEscapingSlashes]
        guard let body = try? enc.encode(draft) else {
            return .invalid(DraftError(code: "BAD_JSON", field: "", message: "下書きを JSON にできません"))
        }
        let dl = draft.dl ?? draft.l.profile.deadlineMs
        let deadline = dl > 0 ? now() + dl : nil
        var refreshed = false
        var lastStatus = 0
        var lastCode: String?
        var made = 0

        for attempt in 1...max(1, retry.attempts) {
            made = attempt
            var status = 0
            var retryAfter: Int?
            do {
                // 期限切れのときだけ、同じ回のうちにトークンを取り直して一度だけ送り直す
                while true {
                    var req = URLRequest(url: url)
                    req.httpMethod = "POST"
                    req.setValue("application/json", forHTTPHeaderField: "content-type")
                    req.setValue("Bearer \(try await token(refreshed))", forHTTPHeaderField: "authorization")
                    req.httpBody = body
                    let (data, res) = try await transport.post(req)
                    status = res.statusCode
                    let reply = (try? JSONDecoder().decode(Reply.self, from: data)) ?? Reply()
                    lastCode = reply.code
                    if status == 401, reply.code == "TOKEN_EXPIRED", !refreshed { refreshed = true; continue }
                    if status == 409, reply.code == "DUPLICATE" {
                        return .delivered(id: draft.id, at: nil, body: nil, duplicate: true, attempts: attempt)
                    }
                    if (200...299).contains(status) {
                        return .delivered(id: draft.id, at: reply.at, body: reply.b, duplicate: false, attempts: attempt)
                    }
                    if let s = res.value(forHTTPHeaderField: "retry-after"), let n = Int(s) { retryAfter = n }
                    break
                }
            } catch {
                status = 0
            }
            lastStatus = status
            if !RetryPolicy.isRetryable(status) || attempt == retry.attempts { break }
            // 待ち時間：倍々の上限まで、ばらつきあり。相手の指示があればそれ以上待つ。締め切りを越える待ちはしない
            let cap = min(retry.maxMs, retry.baseMs << (attempt - 1))
            var wait = cap / 2 + Int(random() * Double(cap / 2))
            if let r = retryAfter, r >= 0 { wait = max(wait, min(r * 1000, retry.maxMs)) }
            if let d = deadline, now() + wait >= d { break }
            await sleep(wait)
        }
        return .failed(status: lastStatus, code: lastCode, attempts: made)
    }
}
