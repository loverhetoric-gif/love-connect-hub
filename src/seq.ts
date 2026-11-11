// 続き物の番号。規格書 第15章。
// ストリーミング・AI の断片は、番号を「まとまり番号_順番」にして、同じまとまりを見分ける。
// （レコードの一括も同じ形。終わりは「まとまり番号_end」）

const GROUP_RE = /^[A-Za-z0-9-]{8,48}$/;
const SEQ_ID_RE = /^([A-Za-z0-9-]{8,48})_(\d{1,9}|end)$/;

/** 続き物の番号を作る */
export function seqId(group: string, sq: number | "end"): string {
  if (!GROUP_RE.test(group)) throw new Error("まとまり番号は英数字とハイフンの 8〜48 字です");
  if (sq !== "end" && (!Number.isInteger(sq) || sq < 0 || sq > 999_999_999)) throw new Error("順番が正しくありません");
  return `${group}_${sq}`;
}

/** 続き物の番号を読む。形が違えば undefined */
export function parseSeqId(id: string): { group: string; sq: number | "end" } | undefined {
  const m = SEQ_ID_RE.exec(id);
  if (!m) return undefined;
  return { group: m[1]!, sq: m[2] === "end" ? "end" : Number(m[2]) };
}
