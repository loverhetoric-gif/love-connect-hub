import Foundation
#if canImport(CryptoKit)
import CryptoKit
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// 端末の鍵（規格書 第21章）。WARPHOLE. と同じく、秘密の部分は端末の外へ出さない。
/// 封筒の署名・暗号化には使わない（土台の鍵はアプリに持たせない。第18章）。端末であることの証明と、本人の承認だけに使う。
public protocol HubDeviceKey: Sendable {
    /// 非圧縮形式 65 バイトの公開鍵
    var publicKeyRaw: Data { get }
    /// r||s の 64 バイトの署名
    func sign(_ message: Data) throws -> Data
}

extension HubDeviceKey {
    /// 公開鍵の base64url（87 字）
    public var publicKey: String { b64u(publicKeyRaw) }
}

func b64u(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func sha256Hex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

/// Secure Enclave（取り出せない金庫）の端末の鍵。iPhone・iPad・Apple シリコンの Mac で使う。
/// dataRepresentation は、その端末の金庫でしか使えない参照（暗号化されている）。キーチェーンかファイルに保存して持ち越す。
/// 鍵は本当に無いときだけ作る。あるのに読めないときは作り直さない（作り直すと登録が外れる。WARPHOLE. の決まりと同じ）
public struct SecureEnclaveDeviceKey: HubDeviceKey, @unchecked Sendable {
    private let key: SecureEnclave.P256.Signing.PrivateKey
    public var publicKeyRaw: Data { key.publicKey.x963Representation }
    /// 保存用の参照（秘密ではないが、その端末でしか使えない）
    public var dataRepresentation: Data { key.dataRepresentation }

    /// 新しく作る。承認の鍵（use: approve）は requireBiometry を true にし、署名のたびに Face ID・Touch ID を求める
    public static func create(requireBiometry: Bool) throws -> SecureEnclaveDeviceKey {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometry { flags.insert(.biometryCurrentSet) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return SecureEnclaveDeviceKey(key: try SecureEnclave.P256.Signing.PrivateKey(accessControl: access))
    }

    /// 保存した参照から読み直す
    public init(dataRepresentation: Data) throws {
        key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
    }

    private init(key: SecureEnclave.P256.Signing.PrivateKey) { self.key = key }

    public func sign(_ message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }

    /// この端末で使えるか（Secure Enclave の無い端末・シミュレーターでは使えない）
    public static var isAvailable: Bool { SecureEnclave.isAvailable }
}

/// ソフトウェアの端末の鍵（試験用・Secure Enclave の無い環境用）。本番の端末では SecureEnclaveDeviceKey を使う
public struct SoftwareDeviceKey: HubDeviceKey {
    private let key: P256.Signing.PrivateKey
    public init() { key = P256.Signing.PrivateKey() }
    public init(rawRepresentation: Data) throws { key = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation) }
    public var publicKeyRaw: Data { key.publicKey.x963Representation }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

/// 送るたびの証明（lch-device 見出しの値）。src/device.ts の deviceProofHeader と同じ
public func hubDeviceProof(key: HubDeviceKey, method: String, path: String, token: String, body: Data, now: Int) throws -> String {
    var n = Data(count: 16)
    let ok = n.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
    guard ok == errSecSuccess else { throw DraftError(code: "RANDOM", field: "", message: "乱数を作れません") }
    let nonce = b64u(n)
    let msg = ["lch-device-v1", method.uppercased(), path, String(now), nonce, sha256Hex(Data(token.utf8)), sha256Hex(body), key.publicKey].joined(separator: "\n")
    return "v1.\(key.publicKey).\(now).\(nonce).\(b64u(try key.sign(Data(msg.utf8))))"
}

/// 登録の本文（code は別の画面の QR などで受け取った使い捨ての合言葉）。src/device.ts の pairingRequest と同じ
public func hubPairingRequest(key: HubDeviceKey, co: String, by: String, use: String, code: String) throws -> [String: String] {
    let msg = ["lch-pair-v1", co, by, use, key.publicKey, sha256Hex(Data(code.utf8))].joined(separator: "\n")
    return ["pub": key.publicKey, "use": use, "code": code, "sig": b64u(try key.sign(Data(msg.utf8)))]
}
#endif
