import Foundation

/// 下書き（規格書 第18章）。アプリが送るもの。
/// 会社（co）・送り手（by）・時刻（at）・署名（sig）・暗号方式（e）は土台が付けるので、この型には無い。
public struct Draft: Codable, Sendable, Equatable {
    public var v: Int = specVersion
    public var l: Lane
    public var f: String
    /// 一意の番号。やり直しでも同じ番号を使う（二重の実行を防ぐ）
    public var id: String
    public var c: Classification?
    public var dl: Int?
    public var ap: Bool?
    public var ret: Int?
    public var sq: Int?
    public var bv: Int?
    public var ref: String?
    public var len: Int?
    public var h: String?
    public var b: JSONValue?

    public init(
        lane: Lane, format: String, id: String = newMessageId(), body: JSONValue? = nil,
        classification: Classification? = nil, deadlineMs: Int? = nil, needsApproval: Bool? = nil,
        retentionSec: Int? = nil, seq: Int? = nil, baseVersion: Int? = nil,
        ref: String? = nil, length: Int? = nil, hash: String? = nil
    ) {
        l = lane; f = format; self.id = id; b = body
        c = classification; dl = deadlineMs; ap = needsApproval; ret = retentionSec
        sq = seq; bv = baseVersion; self.ref = ref; len = length; h = hash
    }
}

/// 送る前に見つけた誤り。土台の拒否の名前と同じ名前を使う
public struct DraftError: Error, Sendable, Equatable {
    public let code: String
    public let field: String
    public let message: String
}

/// 一意の番号（乱数 16 バイトの base64url）。暗号として安全な乱数を使う
public func newMessageId() -> String {
    var g = SystemRandomNumberGenerator()
    let bytes = (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &g) }
    return Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func whole(_ s: String, _ pattern: String) -> Bool {
    guard let re = try? NSRegularExpression(pattern: "^(?:\(pattern))$") else { return false }
    return re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
}

private let formatPattern = "[a-z][a-z0-9]*(?:\\.[a-z0-9][a-z0-9_-]*){1,7}"
private let idPattern = "[A-Za-z0-9_-]{8,64}"
private let refPattern = "[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,512}"
private let hashPattern = "[0-9a-f]{64}"

extension Draft {
    /// 送る前の検査。土台でも同じ検査をするが、通らないものは送らずに止める（通信と待ち時間を無駄にしない）
    public func check() -> DraftError? {
        func no(_ code: String, _ field: String, _ msg: String) -> DraftError { DraftError(code: code, field: field, message: msg) }
        let p = l.profile
        if v != specVersion { return no("BAD_VERSION", "v", "対応していない規格版です") }
        if l == .key { return no("LANE_NOT_ALLOWED", "l", "このレーンは利用者の口から使えません") }
        if !whole(f, formatPattern) || !f.hasPrefix("\(l.rawValue).") {
            return no("BAD_FIELD", "f", "形式の名前が正しくありません（レーン名.ハブID.名前）")
        }
        if !whole(id, idPattern) { return no("BAD_FIELD", "id", "一意の番号が正しくありません") }
        if let dl, !(0...600_000).contains(dl) { return no("BAD_FIELD", "dl", "締め切りが正しくありません") }
        if let ret, !(0...(10 * 365 * 86400)).contains(ret) { return no("BAD_FIELD", "ret", "保存期間が正しくありません") }
        for (name, value) in [("sq", sq), ("bv", bv), ("len", len)] {
            if let value, value < 0 { return no("BAD_FIELD", name, "0 以上の整数にしてください") }
        }
        if let ref, !whole(ref, refPattern) { return no("BAD_FIELD", "ref", "置き場所が正しくありません") }
        if let h, !whole(h, hashPattern) { return no("BAD_FIELD", "h", "ハッシュが正しくありません") }
        let present: [String: Bool] = ["sq": sq != nil, "bv": bv != nil, "ref": ref != nil, "len": len != nil, "h": h != nil]
        for k in p.required where present[k] != true { return no("MISSING_FIELD", k, "このレーンでは必須の項目です：\(k)") }
        if let c, c < p.minClass { return no("CLASS_TOO_LOW", "c", "このレーンの機密度の下限を下回っています") }
        if let b {
            if p.inlineMax == 0 { return no("BODY_FORBIDDEN", "b", "このレーンでは本文を直接運べません") }
            if ref != nil { return no("BODY_AND_REF", "b", "本文と置き場所は、どちらか一方だけです") }
            let enc = JSONEncoder()
            enc.outputFormatting = [.withoutEscapingSlashes]
            if let data = try? enc.encode(b), data.count > p.inlineMax {
                return no("BODY_TOO_LARGE", "b", "本文が大きすぎます。置き場所（ref）で渡してください")
            }
        }
        return nil
    }
}
