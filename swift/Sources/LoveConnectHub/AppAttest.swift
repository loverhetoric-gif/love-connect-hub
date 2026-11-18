import Foundation
#if canImport(CryptoKit)
import CryptoKit
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// App Attest に渡す clientDataHash（src/appattest.ts の appAttestClientDataHash と同じ）。
/// 会社・本人・使い道・登録する端末の鍵に結び付け、別の登録に使い回せないようにする
public func hubAppAttestClientDataHash(co: String, by: String, use: String, pub: String) -> Data {
    Data(SHA256.hash(data: Data(["lch-appattest-v1", co, by, use, pub].joined(separator: "\n").utf8)))
}

#if canImport(DeviceCheck)
/// Apple の App Attest（規格書 第21章）。「Apple の本物の端末の上の、このアプリ」が端末の鍵を登録していることを、土台に示す。
/// 登録の本文の att に添える。App Attest の鍵は登録のたびに新しく作る（使い回すと signCount が 0 でなくなり、土台が断る）
public enum HubAppAttest {
    /// この端末で使えるか（シミュレーター・古い端末では使えない）
    public static var isSupported: Bool { DCAppAttestService.shared.isSupported }

    /// 登録の本文に添える att を作る（{ platform: "apple", keyId, attestation }）。Apple の窓口との通信があるので、画面の外で呼ぶ
    public static func attestation(device: HubDeviceKey, co: String, by: String, use: String) async throws -> [String: String] {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw DraftError(code: "APPATTEST_UNSUPPORTED", field: "", message: "この端末では App Attest を使えません") }
        let keyId = try await service.generateKey()
        let hash = hubAppAttestClientDataHash(co: co, by: by, use: use, pub: device.publicKey)
        let object = try await service.attestKey(keyId, clientDataHash: hash)
        return ["platform": "apple", "keyId": keyId, "attestation": b64u(object)]
    }
}
#endif
#endif
