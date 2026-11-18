package jp.loverhetoric.lch

import java.security.SecureRandom
import java.util.Base64

// 8 本のレーンと下書き（規格書 第3章・第18章）。src/lanes.ts・swift/ と同じ値を保つ。

const val SPEC_VERSION = 1

/** レーンの性質 */
data class LaneProfile(val priority: Int, val inlineMax: Int, val deadlineMs: Int, val required: List<String>, val minClass: Int)

enum class Lane(val profile: LaneProfile) {
    KEY(LaneProfile(0, 0, 2000, listOf("ref"), 3)),
    STREAM(LaneProfile(1, 16 * 1024, 1000, listOf("sq"), 0)),
    SYNC(LaneProfile(2, 64 * 1024, 3000, listOf("sq", "bv"), 0)),
    API(LaneProfile(3, 256 * 1024, 10_000, emptyList(), 0)),
    AI(LaneProfile(4, 256 * 1024, 120_000, emptyList(), 1)),
    RECORD(LaneProfile(5, 64 * 1024, 5000, emptyList(), 1)),
    EVENT(LaneProfile(6, 16 * 1024, 0, emptyList(), 0)),
    MEDIA(LaneProfile(7, 0, 0, listOf("ref", "len", "h"), 0));

    val wire: String get() = name.lowercase()
}

/** 送る前に見つけた誤り。土台の拒否の名前と同じ名前を使う */
data class DraftError(val code: String, val field: String, override val message: String) : Exception(message)

private val random = SecureRandom()

internal fun b64u(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

/** 一意の番号（乱数 16 バイトの base64url） */
fun newMessageId(): String = ByteArray(16).also { random.nextBytes(it) }.let(::b64u)

internal fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

/**
 * 下書き。会社（co）・送り手（by）・時刻（at）・署名（sig）・暗号方式（e）は土台が付けるので、この型には無い。
 * 本文（body）は Map・List・文字・数・真偽・null で書く。
 */
data class Draft(
    val lane: Lane,
    val format: String,
    val id: String = newMessageId(),
    val body: Any? = null,
    val classification: Int? = null,
    val deadlineMs: Int? = null,
    val needsApproval: Boolean? = null,
    val retentionSec: Int? = null,
    val seq: Long? = null,
    val baseVersion: Long? = null,
    val ref: String? = null,
    val length: Long? = null,
    val hash: String? = null,
) {
    /** 送る形（JSON の文字）。土台は受け取った文字のまま本文のハッシュを求めるので、送るのはこの文字だけ */
    fun toJson(): String {
        val m = LinkedHashMap<String, Any?>()
        m["v"] = SPEC_VERSION; m["l"] = lane.wire; m["f"] = format; m["id"] = id
        classification?.let { m["c"] = it }; deadlineMs?.let { m["dl"] = it }; needsApproval?.let { m["ap"] = it }
        retentionSec?.let { m["ret"] = it }; seq?.let { m["sq"] = it }; baseVersion?.let { m["bv"] = it }
        ref?.let { m["ref"] = it }; length?.let { m["len"] = it }; hash?.let { m["h"] = it }
        if (body != null) m["b"] = body
        return Json.encode(m)
    }

    /** 送る前の検査（Swift 版の Draft.check と同じ） */
    fun check(): DraftError? {
        val p = lane.profile
        fun no(code: String, field: String, msg: String) = DraftError(code, field, msg)
        if (lane == Lane.KEY) return no("LANE_NOT_ALLOWED", "l", "このレーンは利用者の口から使えません")
        if (!FORMAT.matches(format) || !format.startsWith("${lane.wire}.")) return no("BAD_FIELD", "f", "形式の名前が正しくありません（レーン名.ハブID.名前）")
        if (!ID.matches(id)) return no("BAD_FIELD", "id", "一意の番号が正しくありません")
        if (deadlineMs != null && deadlineMs !in 0..600_000) return no("BAD_FIELD", "dl", "締め切りが正しくありません")
        if (retentionSec != null && retentionSec !in 0..(10 * 365 * 86400)) return no("BAD_FIELD", "ret", "保存期間が正しくありません")
        if (classification != null && classification !in 0..3) return no("BAD_FIELD", "c", "機密度は 0〜3 です")
        for ((name, v) in listOf("sq" to seq, "bv" to baseVersion, "len" to length)) if (v != null && v < 0) return no("BAD_FIELD", name, "0 以上の整数にしてください")
        if (ref != null && !REF.matches(ref)) return no("BAD_FIELD", "ref", "置き場所が正しくありません")
        if (hash != null && !HASH.matches(hash)) return no("BAD_FIELD", "h", "ハッシュが正しくありません")
        val present = mapOf("sq" to (seq != null), "bv" to (baseVersion != null), "ref" to (ref != null), "len" to (length != null), "h" to (hash != null))
        for (k in p.required) if (present[k] != true) return no("MISSING_FIELD", k, "このレーンでは必須の項目です：$k")
        if (classification != null && classification < p.minClass) return no("CLASS_TOO_LOW", "c", "このレーンの機密度の下限を下回っています")
        if (body != null) {
            if (p.inlineMax == 0) return no("BODY_FORBIDDEN", "b", "このレーンでは本文を直接運べません")
            if (ref != null) return no("BODY_AND_REF", "b", "本文と置き場所は、どちらか一方だけです")
            val size = try { Json.encode(body).toByteArray(Charsets.UTF_8).size } catch (e: IllegalArgumentException) { return no("BAD_JSON", "b", "本文を JSON にできません") }
            if (size > p.inlineMax) return no("BODY_TOO_LARGE", "b", "本文が大きすぎます。置き場所（ref）で渡してください")
        }
        return null
    }

    private companion object {
        val FORMAT = Regex("[a-z][a-z0-9]*(?:\\.[a-z0-9][a-z0-9_-]*){1,7}")
        val ID = Regex("[A-Za-z0-9_-]{8,64}")
        val REF = Regex("[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{1,512}")
        val HASH = Regex("[0-9a-f]{64}")
    }
}
