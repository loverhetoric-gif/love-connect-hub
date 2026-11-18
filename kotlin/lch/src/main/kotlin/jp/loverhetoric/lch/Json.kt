package jp.loverhetoric.lch

// 小さな JSON の読み書き（外部部品を入れないため）。下書きと返事に要る分だけ。
// 値は Map<String, Any?>・List<Any?>・String・Number・Boolean・null。

/** JSON の文字にする。項目の順は渡した Map の順のまま */
object Json {
    fun encode(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is String -> str(sb, v)
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int, is Long, is Short, is Byte -> sb.append(v.toString())
            is Double -> sb.append(if (v.isFinite()) num(v) else "null")
            is Float -> sb.append(if (v.isFinite()) num(v.toDouble()) else "null")
            is Number -> sb.append(v.toString())
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, x) in v) {
                    if (!first) sb.append(',')
                    first = false
                    str(sb, k as String)
                    sb.append(':')
                    write(sb, x)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, x -> if (i > 0) sb.append(','); write(sb, x) }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("JSON にできない値です")
        }
    }

    private fun num(d: Double): String = if (d == Math.floor(d) && Math.abs(d) < 1e15) d.toLong().toString() else d.toString()

    private fun str(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ') sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }

    /** JSON の文字を読む。形が違えば IllegalArgumentException */
    fun parse(s: String): Any? {
        val p = Parser(s)
        val v = p.value()
        p.ws()
        if (p.i != s.length) throw IllegalArgumentException("JSON の後ろに余計な文字があります")
        return v
    }

    private class Parser(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i] in " \t\r\n") i++ }
        fun value(): Any? {
            ws()
            if (i >= s.length) throw IllegalArgumentException("JSON が途中で切れています")
            return when (val c = s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> string()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c.isDigit()) number() else throw IllegalArgumentException("JSON として読めません")
            }
        }
        fun lit(w: String, v: Any?): Any? { if (!s.startsWith(w, i)) throw IllegalArgumentException("JSON として読めません"); i += w.length; return v }
        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; ws()
            if (i < s.length && s[i] == '}') { i++; return m }
            while (true) {
                ws(); val k = string(); ws()
                if (i >= s.length || s[i] != ':') throw IllegalArgumentException("JSON として読めません")
                i++; m[k] = value(); ws()
                if (i < s.length && s[i] == ',') { i++; continue }
                if (i < s.length && s[i] == '}') { i++; return m }
                throw IllegalArgumentException("JSON として読めません")
            }
        }
        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; ws()
            if (i < s.length && s[i] == ']') { i++; return l }
            while (true) {
                l.add(value()); ws()
                if (i < s.length && s[i] == ',') { i++; continue }
                if (i < s.length && s[i] == ']') { i++; return l }
                throw IllegalArgumentException("JSON として読めません")
            }
        }
        fun string(): String {
            if (i >= s.length || s[i] != '"') throw IllegalArgumentException("JSON として読めません")
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (i >= s.length) break
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> sb.append(e)
                            'n' -> sb.append('\n'); 'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C')
                            'u' -> { if (i + 4 > s.length) break; sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                            else -> throw IllegalArgumentException("JSON として読めません")
                        }
                    }
                    else -> sb.append(c)
                }
            }
            throw IllegalArgumentException("JSON が途中で切れています")
        }
        fun number(): Number {
            val start = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val t = s.substring(start, i)
            return t.toLongOrNull() ?: t.toDoubleOrNull() ?: throw IllegalArgumentException("JSON の数として読めません")
        }
    }
}
