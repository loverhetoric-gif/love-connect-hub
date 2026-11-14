// ハブの宣言から許可表を作る。規格書 第19章。
// 許可表は手で別に書かず、各ハブの定義書に書いた宣言から土台が組み立てる（書き忘れ・食い違いを起こさない）。
// どのハブがどの形式を持つかは、形式の 2 段目（レーン名.ハブID.名前）で決まる。

import type { CheckOptions } from "./envelope.ts";
import { type LaneName, isLane } from "./lanes.ts";

/** ハブの定義書に書く、封筒の宣言 */
export interface HubLanes {
  /** ハブ ID（小文字の英数字） */
  hub: string;
  /** このハブが出す形式（自分のハブ ID を 2 段目に持つものだけ） */
  emits?: readonly string[];
  /** このハブが受け取る形式（ほかのハブのイベントなど。どこかのハブが出すものだけ） */
  accepts?: readonly string[];
  /** 利用者の口（第18章）から受け付ける形式。自分が出す形式のうち、アプリから直接送ってよいものだけ */
  user?: readonly string[];
}

export interface HubTables {
  /** 封筒の入口の許可表（全ハブが出す形式） */
  all: NonNullable<CheckOptions["formats"]>;
  /** 利用者の口の許可表 */
  user: NonNullable<CheckOptions["formats"]>;
  /** 形式 → それを出すハブ */
  owner: ReadonlyMap<string, string>;
  /** 形式 → それを受け取るハブ（出すハブ自身は含めない） */
  subscribers: ReadonlyMap<string, readonly string[]>;
}

const HUB_RE = /^[a-z][a-z0-9]{0,31}$/;
const FORMAT_RE = /^[a-z][a-z0-9]*(?:\.[a-z0-9][a-z0-9_-]*){1,7}$/;

function laneOf(f: string): LaneName {
  const lane = f.split(".")[0];
  if (!FORMAT_RE.test(f) || !isLane(lane)) throw new Error(`形式の名前が正しくありません：${f}`);
  return lane;
}

function add(t: Partial<Record<LaneName, Set<string>>>, f: string): void {
  const lane = laneOf(f);
  (t[lane] ??= new Set()).add(f);
}

/**
 * 全ハブの宣言から、許可表・持ち主・受け手を作る。宣言に食い違いがあれば、動かす前に止める（例外）。
 * - ハブ ID の重複、形式の名前の誤り
 * - 自分のハブ ID を 2 段目に持たない形式を出す（ほかのハブの形式を名乗る）
 * - 誰も出さない形式を受け取る
 * - 自分が出さない形式、または鍵レーンの形式を利用者の口に開く
 */
export function buildHubTables(hubs: readonly HubLanes[]): HubTables {
  const all: Partial<Record<LaneName, Set<string>>> = {};
  const user: Partial<Record<LaneName, Set<string>>> = {};
  const owner = new Map<string, string>();
  const subs = new Map<string, string[]>();
  const ids = new Set<string>();

  for (const h of hubs) {
    if (!HUB_RE.test(h.hub)) throw new Error(`ハブ ID が正しくありません：${h.hub}`);
    if (ids.has(h.hub)) throw new Error(`ハブ ID が重複しています：${h.hub}`);
    ids.add(h.hub);
    for (const f of h.emits ?? []) {
      laneOf(f);
      if (f.split(".")[1] !== h.hub) throw new Error(`ハブ「${h.hub}」は自分の形式だけを出せます：${f}`);
      if (owner.has(f)) throw new Error(`形式が重複しています：${f}`);
      owner.set(f, h.hub);
      add(all, f);
    }
  }
  for (const h of hubs) {
    const mine = new Set(h.emits ?? []);
    for (const f of h.accepts ?? []) {
      laneOf(f);
      const o = owner.get(f);
      if (!o) throw new Error(`誰も出さない形式は受け取れません：${f}（${h.hub}）`);
      if (o === h.hub) continue;
      const list = subs.get(f) ?? [];
      if (!list.includes(h.hub)) list.push(h.hub);
      subs.set(f, list);
    }
    for (const f of h.user ?? []) {
      if (!mine.has(f)) throw new Error(`自分が出さない形式は利用者の口に開けません：${f}（${h.hub}）`);
      if (laneOf(f) === "key") throw new Error(`鍵レーンは利用者の口に開けません：${f}`);
      add(user, f);
    }
  }
  return { all, user, owner, subscribers: subs };
}
