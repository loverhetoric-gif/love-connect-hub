package jp.loverhetoric.lch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 映像・音声のリアルタイム通信（規格書 第23章）。TypeScript 版と同じ決まりか、TypeScript が署名した見本で確かめる（Swift 版の RtcTests と同じ） */
class RtcTest {
    @Suppress("UNCHECKED_CAST")
    private val v: Map<String, Any?> by lazy {
        val f = listOf("../../test/vectors/rtc.json", "../test/vectors/rtc.json").map(::File).first { it.exists() }
        Json.parse(f.readText()) as Map<String, Any?>
    }
    @Suppress("UNCHECKED_CAST") private fun obj(k: String) = v[k] as Map<String, Any?>
    private val now get() = (v["now"] as Number).toLong()

    @Test fun signedTextMatchesTypeScript() {
        assertEquals("改行・引用符・日本語・制御文字を含む SDP でも同じ文になる", v["offerSignedText"], HubRtc.signedText(obj("offer")))
        assertEquals(v["grantSignedText"], HubRtc.signedText(obj("grant")))
    }

    @Test fun verifiesTypeScriptOffer() {
        val ver = HubRtcVerifier(v["me"] as String, v["room"] as String) { now }
        assertNull(ver.check(obj("offer")))
        assertEquals("RTC_REPLAY", ver.check(obj("offer")))
        @Suppress("UNCHECKED_CAST") val b = (obj("offer")["b"] as Map<String, Any?>).toMutableMap()
        b["sdp"] = (b["sdp"] as String).replace(":01:02:", ":FF:02:")
        assertEquals("RTC_SIGNATURE", HubRtcVerifier(v["me"] as String, v["room"] as String) { now }.check(obj("offer").toMutableMap().apply { put("b", b) }))
        assertEquals("RTC_ROOM", HubRtcVerifier(v["me"] as String, "room-otherone") { now }.check(obj("offer")))
        assertEquals("RTC_CLOCK", HubRtcVerifier(v["me"] as String, v["room"] as String) { now + 121_000 }.check(obj("offer")))
    }

    @Test fun verifiesTypeScriptGrant() {
        @Suppress("UNCHECKED_CAST") val keys = v["approverKeys"] as List<String>
        assertEquals(HubRtc.Grant("point", now + 600_000), HubRtc.verifyControlGrant(obj("grant"), keys, v["supporter"] as String, "sid-vector01", now + 1000))
        assertNull("承認の鍵の一覧に無い", HubRtc.verifyControlGrant(obj("grant"), emptyList(), v["supporter"] as String, "sid-vector01", now + 1000))
        assertNull("期限切れ", HubRtc.verifyControlGrant(obj("grant"), keys, v["supporter"] as String, "sid-vector01", now + 700_000))
    }

    @Test fun signAndVerifyRoundTrip() {
        val a = SoftwareDeviceKey(); val b = SoftwareDeviceKey()
        val m = HubRtc.sign(a, "ice", "room-abcdefgh", b.publicKey, mapOf("sid" to "sid-12345678", "c" to "candidate:1 1 udp 1 1.2.3.4 9 typ host", "mid" to "0", "idx" to 0), 1_000)
        assertNull(HubRtcVerifier(b.publicKey, "room-abcdefgh") { 1_000 }.check(m))
        assertEquals("RTC_TO", HubRtcVerifier(a.publicKey, "room-abcdefgh") { 1_000 }.check(m))
    }

    @Test fun sdpAndCodecs() {
        assertNull(HubRtc.sdpProblem("v=0\r\na=fingerprint:sha-256 AA:BB\r\n"))
        assertNotNull(HubRtc.sdpProblem("v=0\r\n"))
        assertNotNull(HubRtc.sdpProblem("v=0\r\na=fingerprint:sha-1 AA\r\n"))
        val sdp = listOf("m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 102 104 106 45 120", "a=rtpmap:96 VP8/90000", "a=rtpmap:97 rtx/90000", "a=rtpmap:98 VP9/90000", "a=rtpmap:102 H264/90000",
            "a=fmtp:102 profile-level-id=42e01f", "a=rtpmap:104 H264/90000", "a=fmtp:104 profile-level-id=640c34", "a=rtpmap:106 H265/90000", "a=rtpmap:45 AV1/90000", "a=rtpmap:120 flexfec-03/90000", "").joinToString("\r\n")
        assertTrue("src/rtc.ts と同じ並び", HubRtc.preferVideoCodecs(sdp).startsWith("m=video 9 UDP/TLS/RTP/SAVPF 106 104 102 98 45 96 97 120\r\n"))
    }

    @Test fun budgetSignalsAndRestart() {
        assertEquals(24_000_000, HubRtc.budget("screen", "wifi", 120).maxBitrate)
        assertEquals(1920, HubRtc.budget("screen", "cellular", 120).maxLongEdge)
        assertEquals(1_000_000, HubRtc.budget("camera", "cellular").maxBitrate)
        assertNotNull(HubRtc.checkAssistSignal("mv", "point", """{"k":"pt","x":0.5,"y":0.2}"""))
        assertNull("指し示すだけでは押せない", HubRtc.checkAssistSignal("ctl", "point", """{"k":"md","b":0}"""))
        assertNull("パスワードは打たせない", HubRtc.checkAssistSignal("ctl", "control", """{"k":"pw","s":"x"}"""))
        assertNull(HubRtc.checkAssistSignal("mv", "control", """{"k":"kd","c":5}"""))
        assertNull(HubRtc.checkAssistSignal("ctl", "control", """{"k":"md","b":true}"""))
        val p = HubRestartPolicy()
        assertEquals(listOf("restart"), p.onState("disconnected", 0))
        assertEquals(listOf("restart"), p.tick(5_000))
        assertEquals(listOf("close"), p.tick(20_000))
        assertEquals(emptyList<String>(), p.onNetworkChange(21_000))
    }
}
