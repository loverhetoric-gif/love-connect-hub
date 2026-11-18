// CBOR（RFC 8949）を読む小さな部品。Apple の App Attest の証明（attestation object）を読むためだけに使う（規格書 第21章）。
// 外部部品は入れない。長さの決まったものだけを読み、長さ不定・浮動小数・タグ付きの値は例外にする（推し量って読まない）。

export class CborError extends Error {}

/** 読んだ値。マップは Map（キーは文字列か数）、バイト列は Uint8Array */
export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | Map<string | number, CborValue>;

const MAX_DEPTH = 16;

/** 1 つの値だけを読む（後ろに余りがあれば例外） */
export function decodeCbor(buf: Uint8Array): CborValue {
  let i = 0;
  const need = (n: number) => {
    if (n < 0 || i + n > buf.length) throw new CborError("途中で切れています");
  };
  const arg = (info: number): number => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : -1;
    if (n < 0) throw new CborError("長さ不定の値は読みません");
    need(n);
    let v = 0;
    for (let k = 0; k < n; k++) v = v * 256 + buf[i++]!;
    if (!Number.isSafeInteger(v)) throw new CborError("数が大きすぎます");
    return v;
  };
  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new CborError("入れ子が深すぎます");
    need(1);
    const first = buf[i++]!;
    const major = first >> 5;
    const info = first & 0x1f;
    switch (major) {
      case 0: return arg(info);
      case 1: return -1 - arg(info);
      case 2: {
        const n = arg(info);
        need(n);
        const v = buf.subarray(i, i + n);
        i += n;
        return v;
      }
      case 3: {
        const n = arg(info);
        need(n);
        const v = new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(i, i + n));
        i += n;
        return v;
      }
      case 4: {
        const n = arg(info);
        if (n > buf.length - i) throw new CborError("途中で切れています");
        const out: CborValue[] = [];
        for (let k = 0; k < n; k++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = arg(info);
        if (n * 2 > buf.length - i) throw new CborError("途中で切れています");
        const out = new Map<string | number, CborValue>();
        for (let k = 0; k < n; k++) {
          const key = item(depth + 1);
          if (typeof key !== "string" && typeof key !== "number") throw new CborError("マップのキーの形が違います");
          if (out.has(key)) throw new CborError("同じキーが 2 つあります");
          out.set(key, item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError("読まない種類の値です");
      default:
        throw new CborError("タグ付きの値は読みません");
    }
  };
  const v = item(0);
  if (i !== buf.length) throw new CborError("後ろに余計なものがあります");
  return v;
}
