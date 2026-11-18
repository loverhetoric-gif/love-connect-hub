package jp.loverhetoric.lch

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

// 映像・音声のリアルタイム通信（規格書 第23章）。src/rtc.ts・swift/ の Rtc.swift と同じ決まり。
// WebRTC そのもの（映像の送受信）は、アプリが入れる WebRTC の部品を使う。ここは、つなぐための連絡の署名と確かめ・SDP の確かめと並べ替え・
// 送る量の上限・遠隔支援の信号と許可の確かめ・張り替えの決まりだけを持つ。値は Json と同じく Map・List・String・Number・Boolean・null。

/** 正規化 JSON（キーを並べ替え、空白なし。src/crypto.ts の canonicalJson と同じ文字になる） */
fun hubCanonicalJson(v: Any?): String = when (v) {
    is Map<*, *> -> v.keys.map { it as String }.sorted().joinToString(",", "{", "}") { k -> Json.encode(k) + ":" + hubCanonicalJson(v[k]) }
    is List<*> -> v.joinToString(",", "[", "]") { hubCanonicalJson(it) }
    else -> Json.encode(v)
}

object HubRtc {
    const val SKEW_MS = 120_000L
    const val NONCE_MS = 300_000L
    const val GRANT_MAX_MS = 30 * 60_000L
    const val SIGNAL_MAX = 16 * 1024
    private val TYPES = setOf("offer", "answer", "ice", "restart", "bye", "grant", "revoke")
    private val SCOPES = setOf("view", "point", "control")
    val VIDEO_ORDER = listOf("H265", "H264", "VP9", "AV1", "VP8")

    /** 署名する文：lch-rtc-v1 ＋ 署名を除いた連絡の正規化 JSON */
    fun signedText(m: Map<String, Any?>): String =
        "lch-rtc-v1\n" + hubCanonicalJson(listOf("v", "t", "room", "from", "to", "ts", "n", "b").filter { m.containsKey(it) }.associateWith { m[it] })

    /** 連絡を作って署名する（src/rtc.ts の signRtc と同じ） */
    fun sign(key: HubDeviceKey, t: String, room: String, to: String, b: Map<String, Any?>, now: Long): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1, "t" to t, "room" to room, "from" to key.publicKey, "to" to to, "ts" to now, "n" to b64u(randomBytes(16)), "b" to b)
        m["sig"] = b64u(key.sign(signedText(m).toByteArray()))
        return m
    }

    /** 端末の公開鍵（base64url の 65 バイト）で、r||s の署名を確かめる */
    fun verifySignature(pub: String, sig: String, message: String): Boolean = runCatching {
        val p = Base64.getUrlDecoder().decode(pub); val s = Base64.getUrlDecoder().decode(sig)
        if (p.size != 65 || p[0] != 0x04.toByte() || s.size != 64) return false
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, p.copyOfRange(1, 33)), BigInteger(1, p.copyOfRange(33, 65))), params))
        fun der(x: ByteArray): ByteArray { val b = BigInteger(1, x).toByteArray(); return byteArrayOf(0x02, b.size.toByte()) + b }
        val r = der(s.copyOfRange(0, 32)); val ss = der(s.copyOfRange(32, 64))
        Signature.getInstance("SHA256withECDSA").apply { initVerify(key); update(message.toByteArray()) }.verify(byteArrayOf(0x30, (r.size + ss.size).toByte()) + r + ss)
    }.getOrDefault(false)

    /** SDP の安全の確かめ：暗号の鍵の指紋が 1 つ以上あり、すべて SHA-256 以上で、同じ鍵を指す。通れば null */
    fun sdpProblem(sdp: String): String? {
        val fps = mutableListOf<String>()
        for (line in sdp.split("\n")) {
            val l = line.trimEnd('\r')
            if (!l.startsWith("a=fingerprint:")) continue
            val parts = l.removePrefix("a=fingerprint:").split(" ")
            if (parts.size != 2) continue
            val hash = parts[0].lowercase()
            if (hash !in setOf("sha-256", "sha-384", "sha-512")) return "弱い指紋（SHA-1 など）は使えません"
            fps += hash + " " + parts[1].uppercase()
        }
        if (fps.isEmpty()) return "暗号の鍵の指紋がありません"
        if (fps.toSet().size != 1) return "指紋が食い違っています"
        return null
    }

    /** 映像の方式を優先順に並べ替える（src/rtc.ts の preferVideoCodecs と同じ） */
    fun preferVideoCodecs(sdp: String, order: List<String> = VIDEO_ORDER): String {
        val nl = if (sdp.contains("\r\n")) "\r\n" else "\n"
        val lines = sdp.split(nl).toMutableList()
        var i = 0
        while (i < lines.size) {
            if (!lines[i].startsWith("m=video ")) { i++; continue }
            var end = i + 1
            while (end < lines.size && !lines[end].startsWith("m=")) end++
            val head = lines[i].split(" ")
            val name = mutableMapOf<String, String>(); val fmtp = mutableMapOf<String, String>()
            for (k in i + 1 until end) {
                Regex("^a=rtpmap:(\\d+) ([^/]+)/").find(lines[k])?.let { name[it.groupValues[1]] = it.groupValues[2].uppercase() }
                Regex("^a=fmtp:(\\d+) (.*)$").find(lines[k])?.let { fmtp[it.groupValues[1]] = it.groupValues[2] }
            }
            fun rank(pt: String) = order.indexOf(name[pt] ?: "").let { if (it < 0) order.size else it }
            fun h264(pt: String): Int {
                val p = Regex("profile-level-id=([0-9A-Fa-f]{6})").find(fmtp[pt] ?: "")?.groupValues?.get(1)?.take(2)?.lowercase() ?: "42"
                return if (p == "64") 0 else if (p == "4d") 1 else 2
            }
            val sorted = head.drop(3).withIndex().sortedWith(compareBy<IndexedValue<String>>({ rank(it.value) },
                { if (name[it.value] == "H264") h264(it.value) else 0 }, { it.index })).map { it.value }
            lines[i] = (head.take(3) + sorted).joinToString(" ")
            i = end
        }
        return lines.joinToString(nl)
    }

    /** 送る量の上限（src/rtc.ts の rtcBudget と同じ） */
    data class Budget(val maxBitrate: Int, val maxFps: Int, val maxLongEdge: Int, val audioBitrate: Int, val contentHint: String, val degradation: String)

    /** source："camera" か "screen"。network："wifi" "cellular" "unknown" */
    fun budget(source: String, network: String, displayFps: Int = 60): Budget {
        val cell = network == "cellular"
        val fps = displayFps.coerceIn(1, 240)
        return if (source == "screen") {
            if (cell) Budget(6_000_000, minOf(fps, 60), 1920, 24_000, "text", "maintain-resolution")
            else Budget(if (fps > 60) 24_000_000 else 16_000_000, minOf(fps, 120), 3840, 32_000, "text", "maintain-resolution")
        } else {
            if (cell) Budget(1_000_000, minOf(fps, 30), 960, 24_000, "motion", "maintain-framerate")
            else Budget(2_500_000, minOf(fps, 30), 1280, 32_000, "motion", "maintain-framerate")
        }
    }

    private val SUPPORTER = mapOf("view" to setOf("st"), "point" to setOf("st", "pt"),
        "control" to setOf("st", "pt", "rm", "ma", "md", "mu", "sc", "kd", "ku", "tx", "rel"))
    private val MV = setOf("rm", "ma", "cur", "pt")

    /** 支援する人から届いた信号を確かめる（src/rtc.ts の checkAssistSignal と同じ）。channel は "ctl" か "mv"。通れば信号、通らなければ null */
    fun checkAssistSignal(channel: String, scope: String?, raw: String): Map<*, *>? {
        if (raw.length > SIGNAL_MAX) return null
        val s = runCatching { Json.parse(raw) as? Map<*, *> }.getOrNull() ?: return null
        val k = s["k"] as? String ?: return null
        if (channel == "mv" && k !in MV) return null
        if (scope == null || SUPPORTER[scope]?.contains(k) != true) return null
        fun num(v: Any?, lo: Double, hi: Double) = (v as? Number)?.toDouble()?.let { it.isFinite() && it >= lo && it <= hi } == true
        val ok = when (k) {
            "rm" -> num(s["dx"], -10_000.0, 10_000.0) && num(s["dy"], -10_000.0, 10_000.0)
            "ma", "pt" -> num(s["x"], 0.0, 1.0) && num(s["y"], 0.0, 1.0)
            "md", "mu" -> (s["b"] as? Number)?.toDouble()?.let { it == 0.0 || it == 1.0 || it == 2.0 } == true
            "sc" -> num(s["dx"], -100_000.0, 100_000.0) && num(s["dy"], -100_000.0, 100_000.0)
            "kd", "ku" -> (s["c"] as? Number)?.toDouble()?.let { it == Math.floor(it) && it >= 0 && it <= 0xffff } == true
            "tx" -> (s["s"] as? String)?.let { it.length <= 4096 } == true
            else -> true
        }
        return if (ok) s else null
    }

    data class Grant(val scope: String, val until: Long)

    /** 支援される本人の承認の鍵で署名した grant を確かめる（src/rtc.ts の verifyControlGrant と同じ）。通れば範囲と期限、通らなければ null */
    fun verifyControlGrant(g: Map<String, Any?>, approverKeys: List<String>, supporter: String, sid: String, now: Long): Grant? {
        if (g["t"] != "grant" || (g["v"] as? Number)?.toInt() != 1) return null
        val from = g["from"] as? String ?: return null
        val b = g["b"] as? Map<*, *> ?: return null
        val scope = b["scope"] as? String ?: return null
        val until = (b["until"] as? Number)?.toLong() ?: return null
        val ts = (g["ts"] as? Number)?.toLong() ?: return null
        if (scope !in SCOPES || from !in approverKeys || g["to"] != supporter || b["sid"] != sid) return null
        if (until <= now || until - ts > GRANT_MAX_MS || ts > now + SKEW_MS) return null
        if (!verifySignature(from, g["sig"] as? String ?: return null, signedText(g))) return null
        return Grant(scope, until)
    }

    internal fun isType(t: Any?) = t in TYPES
}

/** 受け取った連絡の確かめ（src/rtc.ts の createRtcVerifier と同じ）。使い捨ての番号は 5 分覚える */
class HubRtcVerifier(val me: String, val room: String, private val now: () -> Long = { System.currentTimeMillis() }) {
    private val seen = LinkedHashMap<String, Long>()

    /** 通れば null、通らなければ拒否の名前（RTC_BAD・RTC_ROOM・RTC_TO・RTC_CLOCK・RTC_SDP・RTC_SIGNATURE・RTC_REPLAY） */
    @Synchronized fun check(m: Map<String, Any?>): String? {
        if (m.keys != setOf("v", "t", "room", "from", "to", "ts", "n", "b", "sig")) return "RTC_BAD"
        val from = m["from"] as? String; val to = m["to"] as? String; val n = m["n"] as? String; val sig = m["sig"] as? String
        val ts = (m["ts"] as? Number)?.toLong(); val b = m["b"] as? Map<*, *>
        if ((m["v"] as? Number)?.toInt() != 1 || !HubRtc.isType(m["t"]) || from?.length != 87 || to?.length != 87 || n?.length != 22 || sig == null || ts == null || b == null) return "RTC_BAD"
        if (m["room"] != room) return "RTC_ROOM"
        if (to != me) return "RTC_TO"
        val t = now()
        if (Math.abs(t - ts) > HubRtc.SKEW_MS) return "RTC_CLOCK"
        val sid = b["sid"] as? String
        if (sid == null || sid.length !in 8..64) return "RTC_BAD"
        if (m["t"] == "offer" || m["t"] == "answer") {
            val sdp = b["sdp"] as? String ?: return "RTC_BAD"
            if (HubRtc.sdpProblem(sdp) != null) return "RTC_SDP"
        }
        if (!HubRtc.verifySignature(from, sig, HubRtc.signedText(m))) return "RTC_SIGNATURE"
        seen.entries.removeIf { t - it.value >= HubRtc.NONCE_MS }
        val key = from + "\u0000" + n
        if (seen.containsKey(key)) return "RTC_REPLAY"
        seen[key] = t
        return null
    }
}

/** 張り替えの決まり（src/rtc.ts の createRestartPolicy と同じ）。返す値は "restart" か "close" */
class HubRestartPolicy(private val retryMs: Long = 5_000, private val giveUpMs: Long = 20_000) {
    private var since: Long? = null; private var last = 0L; private var closed = false
    @Synchronized fun onState(state: String, now: Long): List<String> {
        if (closed) return emptyList()
        if (state == "connected") { since = null; return emptyList() }
        if (state == "closed") { closed = true; return emptyList() }
        if ((state == "disconnected" || state == "failed") && since == null) { since = now; last = now; return listOf("restart") }
        return emptyList()
    }
    @Synchronized fun onNetworkChange(now: Long): List<String> { if (closed) return emptyList(); last = now; return listOf("restart") }
    @Synchronized fun tick(now: Long): List<String> {
        val s = since ?: return emptyList()
        if (closed) return emptyList()
        if (now - s >= giveUpMs) { closed = true; return listOf("close") }
        if (now - last >= retryMs) { last = now; return listOf("restart") }
        return emptyList()
    }
}
