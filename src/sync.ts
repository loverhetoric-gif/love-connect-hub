// 同期：版の照合と、ぶつかった変更のまとめ。規格書 第15章。
// 書き手は元の版（bv）を添える。今の版と同じなら書き込み、版を 1 つ上げる。
// 違えば、元の中身・相手の中身・自分の中身を項目ごとに比べ、
// 片方だけが変えた項目は自動でまとめ、両方が別の値に変えた項目だけを「ぶつかり」として返す。

import { canonicalJson } from "./crypto.ts";

export type VersionCheck =
  | { ok: true; next: number }
  | { ok: false; code: "VERSION_CONFLICT"; current: number };

/** 元の版が今の版と同じか確かめる */
export function checkVersion(current: number, bv: number | undefined): VersionCheck {
  if (bv === undefined || bv !== current) return { ok: false, code: "VERSION_CONFLICT", current };
  return { ok: true, next: current + 1 };
}

export type MergeResult =
  | { ok: true; merged: Record<string, unknown> }
  | { ok: false; code: "MERGE_CONFLICT"; fields: string[]; merged: Record<string, unknown> };

const same = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (a === undefined || b === undefined) return false;
  return canonicalJson(a) === canonicalJson(b);
};

/**
 * 項目ごとの三者まとめ。
 * base：両者が元にした中身、theirs：今の中身（先に書かれた分）、mine：これから書く中身。
 * 値が undefined の項目は「無い」として扱う（消した項目も比べられる）。
 * ぶつかった項目は theirs の値を残し、fields に名前を返す（勝手に上書きしない）。
 */
export function mergeFields(
  base: Readonly<Record<string, unknown>>,
  theirs: Readonly<Record<string, unknown>>,
  mine: Readonly<Record<string, unknown>>,
): MergeResult {
  const keys = new Set([...Object.keys(base), ...Object.keys(theirs), ...Object.keys(mine)]);
  const merged: Record<string, unknown> = {};
  const conflicts: string[] = [];
  for (const k of [...keys].sort()) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      conflicts.push(k);
      continue;
    }
    const b = base[k];
    const t = theirs[k];
    const m = mine[k];
    let v: unknown;
    if (same(t, m)) v = t; // 同じ値（両方とも変えていない、または同じ値に変えた）
    else if (same(b, t)) v = m; // 自分だけが変えた
    else if (same(b, m)) v = t; // 相手だけが変えた
    else {
      conflicts.push(k);
      v = t;
    }
    if (v !== undefined) merged[k] = v;
  }
  return conflicts.length ? { ok: false, code: "MERGE_CONFLICT", fields: conflicts, merged } : { ok: true, merged };
}
