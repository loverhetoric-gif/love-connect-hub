package jp.loverhetoric.lch

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

// アプリ側の送り口（規格書 第18章・第21章）。src/user.ts の createUserClient・swift/ の HubUserClient と同じ動きにする。
// - 署名用・暗号化用の鍵は持たない。ログインのトークンだけを付ける（端末の鍵は、端末の証明にだけ使う）
// - 一時的な失敗だけを、同じ番号でやり直す
// - 期限切れ（TOKEN_EXPIRED）のときだけ、トークンを取り直して一度だけ送り直す
// - 受け取り済み（409 DUPLICATE）は、届いたものとして扱う
// 通信は止めて待つ形（呼ぶのは画面の外の作業用のスレッドから）

/** 届いた返事 */
data class HttpReply(val status: Int, val headers: Map<String, String>, val body: String)

/** 通信の口（差し替えられる。試験では偽物を使う） */
fun interface HubTransport {
    @Throws(IOException::class)
    fun post(url: URL, headers: Map<String, String>, body: ByteArray): HttpReply
}

/** 標準の HttpURLConnection を使う通信の口。転送（リダイレクト）は追わない */
object UrlConnectionTransport : HubTransport {
    override fun post(url: URL, headers: Map<String, String>, body: ByteArray): HttpReply {
        val c = url.openConnection() as HttpURLConnection
        try {
            c.requestMethod = "POST"
            c.instanceFollowRedirects = false
            c.connectTimeout = 10_000
            c.readTimeout = 30_000
            c.doOutput = true
            headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            c.outputStream.use { it.write(body) }
            val status = c.responseCode
            val text = (if (status >= 400) c.errorStream else c.inputStream)?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
            val h = c.headerFields.filterKeys { it != null }.mapKeys { it.key.lowercase() }.mapValues { it.value.firstOrNull() ?: "" }
            return HttpReply(status, h, text)
        } finally {
            c.disconnect()
        }
    }
}

/** 送った結果 */
sealed class HubSendResult {
    /** 届いた。duplicate は、前の送信がすでに届いていたとき */
    data class Delivered(val id: String, val at: Long?, val body: Any?, val duplicate: Boolean, val attempts: Int) : HubSendResult()
    /** 断られた・届かなかった。code は土台の拒否の名前（分かるとき） */
    data class Failed(val status: Int, val code: String?, val attempts: Int) : HubSendResult()
    /** 送る前に止めた（下書きの誤り） */
    data class Invalid(val error: DraftError) : HubSendResult()
}

/** やり直しの決まり（規格書 第15章と同じ） */
data class RetryPolicy(val attempts: Int = 4, val baseMs: Long = 200, val maxMs: Long = 5000) {
    companion object {
        fun isRetryable(status: Int): Boolean = status == 0 || status == 408 || status == 425 || status == 429 || (status in 500..599 && status != 501)
    }
}

class HubUserClient(
    url: String,
    private val token: (refresh: Boolean) -> String,
    /** 端末の鍵（規格書 第21章）。渡すと、送るたびにトークンと本文に結び付いた端末の証明（lch-device）を付ける */
    private val device: HubDeviceKey? = null,
    private val transport: HubTransport = UrlConnectionTransport,
    private val retry: RetryPolicy = RetryPolicy(),
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
    private val random: () -> Double = { Math.random() },
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    private val target: URL = checkedUrl(url)

    fun send(draft: Draft): HubSendResult {
        draft.check()?.let { return HubSendResult.Invalid(it) }
        val json = draft.toJson()
        val body = json.toByteArray(Charsets.UTF_8)
        val dl = draft.deadlineMs ?: draft.lane.profile.deadlineMs
        val deadline = if (dl > 0) now() + dl else null
        var refreshed = false
        var lastStatus = 0
        var lastCode: String? = null
        var made = 0
        for (attempt in 1..maxOf(1, retry.attempts)) {
            made = attempt
            var status: Int
            var retryAfter: Long? = null
            try {
                while (true) {
                    val tok = token(refreshed)
                    val headers = linkedMapOf("content-type" to "application/json", "authorization" to "Bearer $tok")
                    // 端末の証明は、送り直しのたびに新しい時刻・番号で作り直す（下書きの番号は同じ）
                    if (device != null) headers[DEVICE_HEADER] = hubDeviceProof(device, "POST", target.path, tok, body, now())
                    val res = transport.post(target, headers, body)
                    status = res.status
                    val reply = runCatching { Json.parse(res.body) as? Map<*, *> }.getOrNull().orEmpty()
                    lastCode = reply["code"] as? String
                    if (status == 401 && lastCode == "TOKEN_EXPIRED" && !refreshed) { refreshed = true; continue }
                    if (status == 409 && lastCode == "DUPLICATE") return HubSendResult.Delivered(draft.id, null, null, true, attempt)
                    if (status in 200..299) return HubSendResult.Delivered(draft.id, (reply["at"] as? Number)?.toLong(), reply["b"], false, attempt)
                    retryAfter = res.headers["retry-after"]?.toLongOrNull()
                    break
                }
            } catch (e: IOException) {
                status = 0
            }
            lastStatus = status
            if (!RetryPolicy.isRetryable(status) || attempt == retry.attempts) break
            // 待ち時間：倍々の上限まで、ばらつきあり。相手の指示があればそれ以上待つ。締め切りを越える待ちはしない
            val cap = minOf(retry.maxMs, retry.baseMs shl (attempt - 1))
            var wait = cap / 2 + (random() * (cap / 2)).toLong()
            if (retryAfter != null && retryAfter >= 0) wait = maxOf(wait, minOf(retryAfter * 1000, retry.maxMs))
            if (deadline != null && now() + wait >= deadline) break
            sleep(wait)
        }
        return HubSendResult.Failed(lastStatus, lastCode, made)
    }

    companion object {
        const val DEVICE_HEADER = "lch-device"

        private fun checkedUrl(url: String): URL {
            val u = URI(url)
            val local = u.host == "localhost" || u.host == "127.0.0.1"
            if (!(u.scheme == "https" || (local && u.scheme == "http"))) throw DraftError("INSECURE_URL", "url", "送り先は https にしてください")
            return u.toURL()
        }

        /**
         * 端末を登録する（規格書 第21章）。code は別の画面の QR などで受け取った使い捨ての合言葉。co・by はログインした本人のもの。
         * 承認の鍵（use = approve）の登録は、AndroidKeystoreDeviceKey.signWithBiometric で署名した本文を enrollSigned で送る
         */
        fun enroll(url: String, token: String, device: HubDeviceKey, co: String, by: String, code: String, use: String = "device", transport: HubTransport = UrlConnectionTransport): HubSendResult {
            val req: MutableMap<String, Any?> = LinkedHashMap(hubPairingRequest(device, co, by, use, code))
            // Android Keystore の鍵は、鍵の証明書の鎖も送る（土台が金庫の部品で作られたことを確かめる。規格書 第21章）
            if (device is AndroidKeystoreDeviceKey) req["att"] = linkedMapOf("platform" to "android", "chain" to device.attestationChain())
            return enrollSigned(url, token, req, device.publicKey, transport)
        }

        /** 署名済みの登録の本文を送る（承認の鍵は、signWithBiometric で署名した本文に att を添えて送る） */
        fun enrollSigned(url: String, token: String, request: Map<String, Any?>, pub: String, transport: HubTransport = UrlConnectionTransport): HubSendResult {
            val target = try { checkedUrl(url) } catch (e: DraftError) { return HubSendResult.Invalid(e) }
            return try {
                val res = transport.post(target, mapOf("content-type" to "application/json", "authorization" to "Bearer $token"), Json.encode(request).toByteArray(Charsets.UTF_8))
                if (res.status in 200..299) HubSendResult.Delivered(pub, null, null, false, 1)
                else HubSendResult.Failed(res.status, runCatching { (Json.parse(res.body) as? Map<*, *>)?.get("code") as? String }.getOrNull(), 1)
            } catch (e: IOException) {
                HubSendResult.Failed(0, null, 1)
            }
        }
    }
}
