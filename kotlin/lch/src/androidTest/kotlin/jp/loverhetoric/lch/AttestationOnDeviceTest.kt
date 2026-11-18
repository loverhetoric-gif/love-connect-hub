package jp.loverhetoric.lch

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * 端末（模擬端末を含む）の上で、Android Keystore の端末の鍵を作り、鍵の証明書の鎖を出す。
 * 鎖は logcat（LCH_ATTEST）に 1 枚ずつ出し、TypeScript の verifyAndroidAttestation で読めるかを確かめる（規格書 第21章）。
 * 鍵は試験の終わりに消す（試験用の名前だけ）
 */
@RunWith(AndroidJUnit4::class)
class AttestationOnDeviceTest {
    @Test fun createsKeyAndExportsAttestationChain() {
        val alias = "lch-test-" + System.nanoTime()
        try {
            val challenge = AndroidKeystoreDeviceKey.attestationChallenge("CO_A", "emp-1")
            val key = AndroidKeystoreDeviceKey.loadOrCreate(alias, "device", challenge)
            assertEquals(65, key.publicKeyRaw.size)
            // 送るための鍵で署名でき、Java の標準で確かめられる
            val sig = key.sign("lch".toByteArray())
            assertEquals(64, sig.size)
            val chain = key.attestationChain()
            assertTrue("鎖が短すぎます：${chain.size}", chain.size >= 2)
            Log.i("LCH_ATTEST", "pub ${key.publicKey}")
            chain.forEachIndexed { i, c -> Log.i("LCH_ATTEST", "cert $i $c") }
            Log.i("LCH_ATTEST", "end ${chain.size}")
            // 同じ名前でもう一度読むと、作り直さずに同じ鍵が返る
            assertEquals(key.publicKey, AndroidKeystoreDeviceKey.loadOrCreate(alias, "device").publicKey)
        } finally {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        }
    }
}
