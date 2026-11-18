package jp.loverhetoric.lch

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

// 端末の鍵（規格書 第21章）。WARPHOLE. と同じく、秘密の部分は端末の外へ出さない。
// 封筒の署名・暗号化には使わない（土台の鍵はアプリに持たせない。第18章）。端末であることの証明と、本人の承認だけに使う。

/** 端末の鍵 */
interface HubDeviceKey {
    /** 非圧縮形式 65 バイトの公開鍵 */
    val publicKeyRaw: ByteArray

    /** r||s の 64 バイトの署名。承認の鍵は、生体認証を済ませてから呼ぶ（AndroidKeystoreDeviceKey.signWithBiometric） */
    fun sign(message: ByteArray): ByteArray
}

/** 公開鍵の base64url（87 字） */
val HubDeviceKey.publicKey: String get() = b64u(publicKeyRaw)

internal fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

/** EC の公開鍵を 65 バイトの非圧縮形式にする */
internal fun uncompressed(pub: ECPublicKey): ByteArray {
    fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }
    return byteArrayOf(0x04) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
}

/** Java の ECDSA の署名（DER）を、r||s の 64 バイトにする（Web Crypto・CryptoKit と同じ形） */
fun derToRaw(der: ByteArray): ByteArray {
    fun fail(): Nothing = throw IllegalArgumentException("署名の形が違います")
    var i = 0
    fun len(): Int {
        val b = der[i++].toInt() and 0xff
        if (b < 0x80) return b
        val n = b and 0x7f
        if (n !in 1..2) fail()
        var v = 0
        repeat(n) { v = (v shl 8) or (der[i++].toInt() and 0xff) }
        return v
    }
    if (der.size < 8 || der[i++] != 0x30.toByte()) fail()
    len()
    val out = ByteArray(64)
    for (k in 0..1) {
        if (der[i++] != 0x02.toByte()) fail()
        val l = len()
        var bytes = der.copyOfRange(i, i + l)
        i += l
        while (bytes.size > 32 && bytes[0] == 0.toByte()) bytes = bytes.copyOfRange(1, bytes.size)
        if (bytes.size > 32) fail()
        System.arraycopy(bytes, 0, out, k * 32 + (32 - bytes.size), bytes.size)
    }
    return out
}

/** ソフトウェアの端末の鍵（試験用・金庫の無い環境用）。本番の Android では AndroidKeystoreDeviceKey を使う */
class SoftwareDeviceKey : HubDeviceKey {
    private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val priv: PrivateKey = pair.private
    override val publicKeyRaw: ByteArray = uncompressed(pair.public as ECPublicKey)
    override fun sign(message: ByteArray): ByteArray =
        derToRaw(Signature.getInstance("SHA256withECDSA").apply { initSign(priv); update(message) }.sign())
}

/** 送るたびの証明（lch-device 見出しの値）。src/device.ts の deviceProofHeader と同じ */
fun hubDeviceProof(key: HubDeviceKey, method: String, path: String, token: String, body: ByteArray, now: Long): String {
    val nonce = b64u(randomBytes(16))
    val pub = key.publicKey
    val msg = listOf("lch-device-v1", method.uppercase(), path, now.toString(), nonce, sha256Hex(token.toByteArray()), sha256Hex(body), pub).joinToString("\n")
    return "v1.$pub.$now.$nonce.${b64u(key.sign(msg.toByteArray()))}"
}

/** 登録の文（src/device.ts の pairingMessage と同じ）。承認の鍵は、この文を signWithBiometric で署名する */
fun hubPairingMessage(pub: String, co: String, by: String, use: String, code: String): ByteArray {
    require(use == "device" || use == "approve") { "use は device か approve です" }
    return listOf("lch-pair-v1", co, by, use, pub, sha256Hex(code.toByteArray())).joinToString("\n").toByteArray()
}

/** 署名済みの登録の本文 */
fun hubPairingRequest(pub: String, use: String, code: String, signature: ByteArray): Map<String, String> =
    linkedMapOf("pub" to pub, "use" to use, "code" to code, "sig" to b64u(signature))

/** 登録の本文（送るための鍵用。code は別の画面の QR などで受け取った使い捨ての合言葉）。src/device.ts の pairingRequest と同じ */
fun hubPairingRequest(key: HubDeviceKey, co: String, by: String, use: String, code: String): Map<String, String> {
    val pub = key.publicKey
    return hubPairingRequest(pub, use, code, key.sign(hubPairingMessage(pub, co, by, use, code)))
}

/**
 * 承認の文（src/device.ts の approvalMessage と同じ）。canonicalEnvelopeHash は、封筒（sig を除く）の正規化 JSON の SHA-256（16 進）。
 * 承認する封筒は土台から受け取り、ハッシュも土台が示したものを、画面に中身を見せたうえで使う。
 */
fun hubApprovalMessage(co: String, envelopeId: String, canonicalEnvelopeHash: String, ts: Long): ByteArray =
    listOf("lch-approve-v1", co, envelopeId, canonicalEnvelopeHash, ts.toString()).joinToString("\n").toByteArray()
