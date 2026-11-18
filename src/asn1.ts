// DER（ASN.1 の決まった書き方）を読む小さな部品。証明書と鍵の証明書（規格書 第21章）を読むためだけに使う。
// 外部部品は入れない。長さは 4 バイトまで、入れ子は呼ぶ側が 1 段ずつたどる。読めないものは例外にする（推し量って読まない）。

/** 読んだ 1 つの値（タグ・長さ・中身） */
export interface Der {
  /** 0 汎用・1 応用・2 文脈・3 私用 */
  cls: number;
  constructed: boolean;
  /** タグの番号（31 以上も読む） */
  tag: number;
  /** 値全体（タグと長さを含む） */
  raw: Uint8Array;
  /** 中身 */
  value: Uint8Array;
}

export class DerError extends Error {}

/** 1 つの値を読む。end を返して、続きを読めるようにする */
export function readDer(buf: Uint8Array, offset = 0): { der: Der; end: number } {
  let i = offset;
  const need = (n: number) => {
    if (i + n > buf.length) throw new DerError("途中で切れています");
  };
  need(2);
  const first = buf[i++]!;
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    for (let n = 0; ; n++) {
      need(1);
      const b = buf[i++]!;
      if (n === 0 && b === 0x80) throw new DerError("タグの書き方が違います");
      tag = tag * 128 + (b & 0x7f);
      if (tag > 0xffffff) throw new DerError("タグが大きすぎます");
      if ((b & 0x80) === 0) break;
    }
  }
  need(1);
  let len = buf[i++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new DerError("長さの書き方が違います");
    need(n);
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!;
  }
  need(len);
  const value = buf.subarray(i, i + len);
  return { der: { cls, constructed, tag, raw: buf.subarray(offset, i + len), value }, end: i + len };
}

/** 入れ子の中身を順に読む */
export function derChildren(d: Der): Der[] {
  if (!d.constructed) throw new DerError("入れ子ではありません");
  const out: Der[] = [];
  let i = 0;
  while (i < d.value.length) {
    const r = readDer(d.value, i);
    out.push(r.der);
    i = r.end;
  }
  return out;
}

/** 1 つだけの値として読む（後ろに余りがあれば例外） */
export function parseDer(buf: Uint8Array): Der {
  const r = readDer(buf, 0);
  if (r.end !== buf.length) throw new DerError("後ろに余計なものがあります");
  return r.der;
}

export function expectTag(d: Der | undefined, tag: number, cls = 0): Der {
  if (!d || d.tag !== tag || d.cls !== cls) throw new DerError(`形が違います（${cls}:${tag} のはず）`);
  return d;
}

/** OBJECT IDENTIFIER を「1.2.840…」の形にする */
export function derOid(d: Der): string {
  expectTag(d, 6);
  const v = d.value;
  if (v.length === 0) throw new DerError("OID が空です");
  const parts: number[] = [];
  let n = 0;
  for (let k = 0; k < v.length; k++) {
    n = n * 128 + (v[k]! & 0x7f);
    if ((v[k]! & 0x80) === 0) {
      if (parts.length === 0) parts.push(n < 80 ? Math.floor(n / 40) : 2, n < 80 ? n % 40 : n - 80);
      else parts.push(n);
      n = 0;
    }
  }
  return parts.join(".");
}

/** INTEGER・ENUMERATED を数にする（安全な整数の範囲だけ） */
export function derInt(d: Der): number {
  if (!(d.cls === 0 && (d.tag === 2 || d.tag === 10))) throw new DerError("整数ではありません");
  if (d.value.length === 0 || d.value.length > 7) throw new DerError("整数の大きさが違います");
  let n = d.value[0]! & 0x80 ? -1 : 0;
  for (const b of d.value) n = n * 256 + b;
  if (!Number.isSafeInteger(n)) throw new DerError("整数が大きすぎます");
  return n;
}

/** INTEGER の中身を 16 進にする（証明書の番号用。先頭の 0 は落とす） */
export function derIntHex(d: Der): string {
  expectTag(d, 2);
  let v = d.value;
  while (v.length > 1 && v[0] === 0) v = v.subarray(1);
  return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function derBool(d: Der): boolean {
  expectTag(d, 1);
  if (d.value.length !== 1) throw new DerError("真偽の形が違います");
  return d.value[0] !== 0;
}

/** BIT STRING の中身（余りのビットが 0 のものだけ） */
export function derBits(d: Der): Uint8Array {
  expectTag(d, 3);
  if (d.value.length === 0 || d.value[0] !== 0) throw new DerError("ビット列の形が違います");
  return d.value.subarray(1);
}

/** UTCTime・GeneralizedTime をミリ秒にする */
export function derTime(d: Der): number {
  const s = new TextDecoder().decode(d.value);
  let m: RegExpMatchArray | null;
  if (d.tag === 23 && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const y = Number(m[1]);
    return Date.UTC(y < 50 ? 2000 + y : 1900 + y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (d.tag === 24 && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  throw new DerError("時刻の形が違います");
}
