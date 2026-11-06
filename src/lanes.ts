// 8 本のレーンの定義。規格書 docs/規格.md の第3章と同じ内容を保つ。
// 値を変えるのは規格版を上げる変更（第10章）。

export const SPEC_VERSION = 1;

export type LaneName =
  | "key"
  | "stream"
  | "sync"
  | "api"
  | "ai"
  | "record"
  | "event"
  | "media";

/** 届け方 */
export type Delivery =
  | "once" // 一往復（要求と応答）
  | "chunked" // 分割して送り、最後にハッシュで照合
  | "continuous" // 途切れなく流れる。古いものは捨ててよい
  | "incremental" // 少しずつ返ってくる
  | "bidirectional" // 双方向。元の版を添えて書く
  | "oneway"; // 一方向の知らせ

export interface LaneProfile {
  /** 届け方 */
  readonly delivery: Delivery;
  /** 処理の優先度。小さいほど先に処理する（0〜7） */
  readonly priority: number;
  /** 本文をそのまま入れてよい上限（バイト）。0 は本文の直接持ち込み禁止 */
  readonly inlineMax: number;
  /** 締め切りの既定値（ミリ秒）。0 は締め切りなし */
  readonly deadlineMs: number;
  /** 保存期間の既定値（秒）。0 は保存しない。null は保存先の決まりに従う */
  readonly retentionSec: number | null;
  /** 必ず付ける項目 */
  readonly required: readonly string[];
  /** 機密度の下限 */
  readonly minClass: Classification;
}

/** 機密度 0:公開 1:社内 2:機密 3:極秘 */
export type Classification = 0 | 1 | 2 | 3;

const KiB = 1024;

export const LANES: Readonly<Record<LaneName, LaneProfile>> = Object.freeze({
  // 鍵：値は運ばない。置き場所の参照だけを運ぶ
  key: Object.freeze({
    delivery: "once",
    priority: 0,
    inlineMax: 0,
    deadlineMs: 2000,
    retentionSec: 0,
    required: ["ref"],
    minClass: 3,
  }),
  // ストリーミング：遅れたものは価値がないので、締め切りを短くする
  stream: Object.freeze({
    delivery: "continuous",
    priority: 1,
    inlineMax: 16 * KiB,
    deadlineMs: 1000,
    retentionSec: 0,
    required: ["sq"],
    minClass: 0,
  }),
  // 同期：元の版（bv）を添え、ぶつかったら土台がまとめる
  sync: Object.freeze({
    delivery: "bidirectional",
    priority: 2,
    inlineMax: 64 * KiB,
    deadlineMs: 3000,
    retentionSec: 30 * 86400,
    required: ["sq", "bv"],
    minClass: 0,
  }),
  // API：二重実行を防ぐため、一意の番号（id）で重複を弾く
  api: Object.freeze({
    delivery: "once",
    priority: 3,
    inlineMax: 256 * KiB,
    deadlineMs: 10000,
    retentionSec: 7 * 86400,
    required: [],
    minClass: 0,
  }),
  // AI：逐次で返るので、断片ごとに順番（sq）を付ける
  ai: Object.freeze({
    delivery: "incremental",
    priority: 4,
    inlineMax: 256 * KiB,
    deadlineMs: 120000,
    retentionSec: 7 * 86400,
    required: [],
    minClass: 1,
  }),
  // レコード：表のデータを 1 件ずつ。更新には元の版（bv）を添える
  record: Object.freeze({
    delivery: "once",
    priority: 5,
    inlineMax: 64 * KiB,
    deadlineMs: 5000,
    retentionSec: null,
    required: [],
    minClass: 1,
  }),
  // イベント：起きたことの知らせ。同じ id は一度だけ処理する
  event: Object.freeze({
    delivery: "oneway",
    priority: 6,
    inlineMax: 16 * KiB,
    deadlineMs: 0,
    retentionSec: 7 * 86400,
    required: [],
    minClass: 0,
  }),
  // メディア：本文は直接持ち込まない。大きさとハッシュで照合する
  media: Object.freeze({
    delivery: "chunked",
    priority: 7,
    inlineMax: 0,
    deadlineMs: 0,
    retentionSec: null,
    required: ["ref", "len", "h"],
    minClass: 0,
  }),
});

export const LANE_NAMES = Object.freeze(Object.keys(LANES) as LaneName[]);

export function isLane(name: unknown): name is LaneName {
  return typeof name === "string" && Object.prototype.hasOwnProperty.call(LANES, name);
}

/** メディアを分割するときの 1 片の大きさ（バイト） */
export const MEDIA_CHUNK_BYTES = 1024 * KiB;

/** 封筒の見出しの上限（本文を除く）。これを超える見出しは読まずに拒否する */
export const HEADER_MAX_BYTES = 2 * KiB;
