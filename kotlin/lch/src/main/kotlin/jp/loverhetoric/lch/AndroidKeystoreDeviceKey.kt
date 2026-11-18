package jp.loverhetoric.lch

import android.app.Activity
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executor

/**
 * Android Keystore の端末の鍵（規格書 第21章）。秘密の部分は Keystore の外へ出ない。StrongBox（専用の金庫の部品）があればそこに作る。
 *
 * - 送るための鍵（use = device）：生体認証は求めない。端末の画面ロックが外れているときだけ使える
 * - 承認の鍵（use = approve）：署名のたびに、クラス 3（強い）の生体認証（指紋・顔・虹彩）を求める。PIN・パターンでは代われない。
 *   指紋・顔を登録し直すと鍵は使えなくなる（そのときは新しく作って登録し直す）
 *
 * 鍵は本当に無いときだけ作る。あるのに読めないときは作り直さずに止まる（作り直すと登録が外れる。WARPHOLE. の決まりと同じ）。
 */
class AndroidKeystoreDeviceKey private constructor(val alias: String, val use: String) : HubDeviceKey {
    private fun entry(): KeyStore.PrivateKeyEntry =
        keystore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: throw IllegalStateException("端末の鍵を読めません（作り直しはしません）")

    override val publicKeyRaw: ByteArray get() = uncompressed(entry().certificate.publicKey as ECPublicKey)

    /** 送るための鍵の署名。承認の鍵は signWithBiometric を使う（生体認証なしでは Keystore が断る） */
    override fun sign(message: ByteArray): ByteArray {
        check(use == "device") { "承認の鍵は signWithBiometric で署名します" }
        return derToRaw(Signature.getInstance(ALG).apply { initSign(entry().privateKey); update(message) }.sign())
    }

    /**
     * 承認の鍵の署名。BiometricPrompt で本人を確かめてから、その場で署名する（鍵の使用は、この 1 回の認証に結び付く）。
     * 結果は executor の上で onResult に返す。取り消し・失敗は Result.failure。
     */
    fun signWithBiometric(
        activity: Activity,
        message: ByteArray,
        title: String,
        subtitle: String?,
        cancelText: String,
        executor: Executor,
        onResult: (Result<ByteArray>) -> Unit,
    ): CancellationSignal {
        val signature = Signature.getInstance(ALG).apply { initSign(entry().privateKey as PrivateKey) }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .apply { if (subtitle != null) setSubtitle(subtitle) }
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(cancelText, executor) { _, _ -> onResult(Result.failure(SecurityException("承認を取り消しました"))) }
            .setConfirmationRequired(true)
            .build()
        val cancel = CancellationSignal()
        prompt.authenticate(BiometricPrompt.CryptoObject(signature), cancel, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onResult(runCatching {
                    val s = result.cryptoObject?.signature ?: throw SecurityException("生体認証の結果に署名がありません")
                    s.update(message)
                    derToRaw(s.sign())
                })
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onResult(Result.failure(SecurityException(errString.toString())))
            }
        })
        return cancel
    }

    companion object {
        private const val ALG = "SHA256withECDSA"
        private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        /** この端末に強い生体認証があり、登録されているか（承認の鍵を作る前に確かめる） */
        fun canUseBiometric(activity: Activity): Boolean =
            activity.getSystemService(BiometricManager::class.java)?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

        /** この端末に StrongBox があるか */
        fun hasStrongBox(activity: Activity): Boolean = activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        /**
         * 読み込む。無いときだけ作る。use は device（送るための鍵）か approve（承認の鍵）。
         * 同じ名前の鍵があるのに読めないときは、作り直さずに例外にする
         */
        fun loadOrCreate(alias: String, use: String): AndroidKeystoreDeviceKey {
            require(use == "device" || use == "approve") { "use は device か approve です" }
            val ks = keystore()
            if (ks.containsAlias(alias)) {
                if (ks.getEntry(alias, null) !is KeyStore.PrivateKeyEntry) throw IllegalStateException("端末の鍵を読めません（作り直しはしません）")
                return AndroidKeystoreDeviceKey(alias, use)
            }
            try {
                generate(alias, use, strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                generate(alias, use, strongBox = false)
            }
            return AndroidKeystoreDeviceKey(alias, use)
        }

        private fun generate(alias: String, use: String, strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(strongBox)
                .setUnlockedDeviceRequired(true)
                .apply {
                    if (use == "approve") {
                        // 署名のたびに強い生体認証（0 秒＝毎回）。PIN・パターンでは代われない。登録し直すと使えなくなる
                        setUserAuthenticationRequired(true)
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        setInvalidatedByBiometricEnrollment(true)
                    }
                }
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()
        }
    }
}
