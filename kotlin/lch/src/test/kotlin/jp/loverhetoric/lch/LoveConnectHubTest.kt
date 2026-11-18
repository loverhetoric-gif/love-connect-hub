package jp.loverhetoric.lch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.URL
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.interfaces.ECPublicKey
import java.math.BigInteger
import java.util.Base64

/** 偽の通信の口。決めた順に返事を返し、届いた要求を覚える */
class FakeTransport(private val replies: MutableList<HttpReply>) : HubTransport {
    val requests = mutableListOf<Pair<Map<String, String>, String>>()
    override fun post(url: URL, headers: Map<String, String>, body: ByteArray): HttpReply {
        requests += headers to body.toString(Charsets.UTF_8)
        if (replies.isEmpty()) throw java.io.IOException("つながりません")
        val r = replies.removeAt(0)
        if (r.status == 0) throw java.io.IOException("時間切れ")
        return r
    }
}

const val HUB = "https://hub.example/lch/v1/user"
fun reply(status: Int, body: String = "{}") = HttpReply(status, emptyMap(), body)
fun client(t: FakeTransport, device: HubDeviceKey? = null, asked: MutableList<Boolean> = mutableListOf()) =
    HubUserClient(HUB, { r -> asked += r; if (r) "fresh-token" else "old-token" }, device, t, sleep = {}, random = { 0.5 }, now = { 1_000 })

class DraftTest {
    @Test fun jsonRoundTrip() {
        val v = linkedMapOf("a" to "改行\nと\"引用\"", "n" to 480, "x" to listOf(true, null, 1.5), "o" to mapOf("k" to "v"))
        val s = Json.encode(v)
        assertEquals("""{"a":"改行\nと\"引用\"","n":480,"x":[true,null,1.5],"o":{"k":"v"}}""", s)
        assertEquals(mapOf("a" to "改行\nと\"引用\"", "n" to 480L, "x" to listOf(true, null, 1.5), "o" to mapOf("k" to "v")), Json.parse(s))
    }

    @Test fun draftHasNoStampedFieldsAndChecksLikeSwift() {
        val d = Draft(Lane.RECORD, "record.attendance.clockin", id = "abcdefgh", body = mapOf("kind" to "in"))
        assertNull(d.check())
        val m = Json.parse(d.toJson()) as Map<*, *>
        assertEquals(setOf("v", "l", "f", "id", "b"), m.keys)
        assertEquals("LANE_NOT_ALLOWED", Draft(Lane.KEY, "key.a.b", ref = "env:X").check()?.code)
        assertEquals("BAD_FIELD", Draft(Lane.RECORD, "api.a.b").check()?.code)
        assertEquals("MISSING_FIELD", Draft(Lane.SYNC, "sync.a.b", seq = 1).check()?.code)
        assertEquals("CLASS_TOO_LOW", Draft(Lane.AI, "ai.a.b", classification = 0).check()?.code)
        assertEquals("BODY_FORBIDDEN", Draft(Lane.MEDIA, "media.a.b", body = "x", ref = "r", length = 1, hash = "a".repeat(64)).check()?.code)
        val id = newMessageId()
        assertTrue(Regex("[A-Za-z0-9_-]{22}").matches(id))
    }

    @Test fun taskIdMakesVersion2AndIsChecked() {
        // 作業 ID を付けると第2版、付けなければ第1版のまま（規格書 第22章）
        val plain = Json.parse(Draft(Lane.RECORD, "record.a.b", id = "abcdefgh").toJson()) as Map<*, *>
        assertEquals(1L, plain["v"]); assertTrue("tk" !in plain.keys)
        val d = Draft(Lane.RECORD, "record.a.b", id = "abcdefgh", task = "w-Ab12Cd34")
        assertNull(d.check())
        val m = Json.parse(d.toJson()) as Map<*, *>
        assertEquals(2L, m["v"]); assertEquals("w-Ab12Cd34", m["tk"])
        for (bad in listOf("w-12", "W-Ab12Cd34", "w-Ab12_d34", "w-Ab12Cd345")) assertEquals(bad, "tk", Draft(Lane.RECORD, "record.a.b", task = bad).check()?.field)
    }
}

class DeviceKeyTest {
    @Test fun rawSignatureIsVerifiableAsP1363() {
        val key = SoftwareDeviceKey()
        assertEquals(65, key.publicKeyRaw.size)
        assertEquals(0x04.toByte(), key.publicKeyRaw[0])
        assertEquals(87, key.publicKey.length)
        val msg = "lch-test".toByteArray()
        repeat(50) {
            val sig = key.sign(msg)
            assertEquals(64, sig.size)
            // Web Crypto・CryptoKit と同じ r||s の形（P1363）として、Java の標準でも確かめられる
            val pub = KeyFactory.getInstance("EC").generatePublic(
                ECPublicKeySpec(ECPoint(BigInteger(1, key.publicKeyRaw.copyOfRange(1, 33)), BigInteger(1, key.publicKeyRaw.copyOfRange(33, 65))),
                    (java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey).params)
            )
            assertTrue(Signature.getInstance("SHA256withECDSAinP1363Format").apply { initVerify(pub); update(msg) }.verify(sig))
        }
    }

    @Test fun proofHeaderShape() {
        val key = SoftwareDeviceKey()
        val p = hubDeviceProof(key, "post", "/lch/v1/user", "t", "{}".toByteArray(), 1_000).split(".")
        assertEquals(listOf("v1", key.publicKey, "1000"), p.take(3))
        assertEquals(22, p[3].length)
        assertEquals(86, p[4].length)
        val req = hubPairingRequest(key, "CO_A", "emp-1", "device", "c")
        assertEquals(setOf("pub", "use", "code", "sig"), req.keys)
        assertEquals(86, req["sig"]!!.length)
    }
}

class UserClientTest {
    @Test fun sendsNewProofOnEveryRetryWithSameId() {
        val t = FakeTransport(mutableListOf(reply(503), reply(202, """{"ok":true,"id":"x","at":5}""")))
        val r = client(t, SoftwareDeviceKey()).send(Draft(Lane.RECORD, "record.attendance.clockin", id = "same-id-01"))
        assertEquals(HubSendResult.Delivered("same-id-01", 5, null, false, 2), r)
        val (h0, b0) = t.requests[0]
        val (h1, b1) = t.requests[1]
        assertNotNull(h0[HubUserClient.DEVICE_HEADER])
        assertNotEquals(h0[HubUserClient.DEVICE_HEADER], h1[HubUserClient.DEVICE_HEADER])
        assertEquals(b0, b1)
        assertEquals("Bearer old-token", h0["authorization"])
    }

    @Test fun refreshesTokenOnlyOnceAndTreatsDuplicateAsDelivered() {
        val asked = mutableListOf<Boolean>()
        val t = FakeTransport(mutableListOf(reply(401, """{"code":"TOKEN_EXPIRED"}"""), reply(409, """{"code":"DUPLICATE"}""")))
        val r = client(t, asked = asked).send(Draft(Lane.RECORD, "record.attendance.clockin", id = "same-id-02"))
        assertEquals(HubSendResult.Delivered("same-id-02", null, null, true, 1), r)
        assertEquals(listOf(false, true), asked)
        val t2 = FakeTransport(mutableListOf(reply(403, """{"code":"DEVICE_UNKNOWN"}""")))
        assertEquals(HubSendResult.Failed(403, "DEVICE_UNKNOWN", 1), client(t2).send(Draft(Lane.RECORD, "record.attendance.clockin")))
    }

    @Test fun onlyHttps() {
        val e = runCatching { HubUserClient("http://hub.example/lch/v1/user", { "t" }) }.exceptionOrNull()
        assertEquals("INSECURE_URL", (e as DraftError).code)
        HubUserClient("http://localhost:8787/lch/v1/user", { "t" })
    }
}

/** 本物の受け口（TypeScript の swift/Interop/server.ts）との相互の確認。LCH_INTEROP_URL などがあるときだけ動く */
class InteropTest {
    @Test fun androidKeyWithTypeScriptGateway() {
        val base = System.getenv("LCH_INTEROP_URL"); val tok = System.getenv("LCH_INTEROP_TOKEN"); val code = System.getenv("LCH_INTEROP_CODE")
        assumeTrue(base != null && tok != null && code != null)
        val root = base!!.removeSuffix("/user")
        val key = SoftwareDeviceKey()
        val c = HubUserClient("$root/user-device", { tok!! }, key)
        assertEquals(HubSendResult.Failed(403, "DEVICE_UNKNOWN", 1), c.send(Draft(Lane.RECORD, "record.attendance.clockin")))
        val e = HubUserClient.enroll("$root/device", tok!!, key, "CO_TEST", "swift-user", code!!)
        assertTrue("登録できなかった：$e", e is HubSendResult.Delivered)
        val r = c.send(Draft(Lane.RECORD, "record.attendance.clockin", body = mapOf("kind" to "in")))
        assertTrue("届かなかった：$r", r is HubSendResult.Delivered)
        assertEquals(mapOf("echo" to mapOf("kind" to "in"), "by" to "swift-user", "co" to "CO_TEST"), (r as HubSendResult.Delivered).body)
        // 作業 ID を付けた下書きは第2版で届き、作業 ID はそのまま正式な封筒に入る（規格書 第22章）
        val t = c.send(Draft(Lane.RECORD, "record.attendance.clockin", body = mapOf("kind" to "out"), task = "w-K0tl1nTk"))
        assertTrue("作業 ID の付いた下書きが届かなかった：$t", t is HubSendResult.Delivered)
        assertEquals(mapOf("echo" to mapOf("kind" to "out"), "by" to "swift-user", "co" to "CO_TEST", "tk" to "w-K0tl1nTk", "v" to 2L), (t as HubSendResult.Delivered).body)
        assertEquals(HubSendResult.Failed(401, "DEVICE_MISSING", 1), HubUserClient("$root/user-device", { tok }).send(Draft(Lane.RECORD, "record.attendance.clockin")))
    }
}
