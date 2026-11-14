// 8 本のレーンの定義。規格書 docs/規格.md の第3章（src/lanes.ts）と同じ値を保つ。
// 値を変えるのは規格版を上げる変更（第10章）。

/// 規格版
public let specVersion = 1

/// 機密度 0:公開 1:社内 2:機密 3:極秘
public enum Classification: Int, Codable, Sendable, Comparable {
    case open = 0
    case internalUse = 1
    case confidential = 2
    case secret = 3

    public static func < (a: Classification, b: Classification) -> Bool { a.rawValue < b.rawValue }
}

/// レーンの性質
public struct LaneProfile: Sendable {
    /// 処理の優先度。小さいほど先
    public let priority: Int
    /// 本文をそのまま入れてよい上限（バイト）。0 は本文の直接持ち込み禁止
    public let inlineMax: Int
    /// 締め切りの既定値（ミリ秒）。0 は締め切りなし
    public let deadlineMs: Int
    /// 必ず付ける項目
    public let required: [String]
    /// 機密度の下限
    public let minClass: Classification
}

public enum Lane: String, Codable, Sendable, CaseIterable {
    case key, stream, sync, api, ai, record, event, media

    public var profile: LaneProfile {
        let kib = 1024
        switch self {
        case .key: return LaneProfile(priority: 0, inlineMax: 0, deadlineMs: 2000, required: ["ref"], minClass: .secret)
        case .stream: return LaneProfile(priority: 1, inlineMax: 16 * kib, deadlineMs: 1000, required: ["sq"], minClass: .open)
        case .sync: return LaneProfile(priority: 2, inlineMax: 64 * kib, deadlineMs: 3000, required: ["sq", "bv"], minClass: .open)
        case .api: return LaneProfile(priority: 3, inlineMax: 256 * kib, deadlineMs: 10000, required: [], minClass: .open)
        case .ai: return LaneProfile(priority: 4, inlineMax: 256 * kib, deadlineMs: 120_000, required: [], minClass: .internalUse)
        case .record: return LaneProfile(priority: 5, inlineMax: 64 * kib, deadlineMs: 5000, required: [], minClass: .internalUse)
        case .event: return LaneProfile(priority: 6, inlineMax: 16 * kib, deadlineMs: 0, required: [], minClass: .open)
        case .media: return LaneProfile(priority: 7, inlineMax: 0, deadlineMs: 0, required: ["ref", "len", "h"], minClass: .open)
        }
    }
}
