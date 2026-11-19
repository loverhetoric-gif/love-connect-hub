// レーンごとの版を、変更履歴（CHANGELOG.md）の「対象のレーン」から作る。
//  - 各版の最初の行「- 対象のレーン：全レーン」または「…（key）・…（media）」を読む
//  - レーンの版の決め方：
//      本体の 1 つ目の数字（規格版）が上がった版で対象になったレーン → その数字.0.0
//      本体の 3 つ目の数字だけが上がった版で対象になったレーン      → 3 つ目を 1 つ上げる
//      それ以外で対象になったレーン                                → 2 つ目を 1 つ上げ、3 つ目を 0 にする
//  - 対象にならなかったレーンは、版も履歴もそのまま
// 使い方: npm run lanes（lanes.json を書き直す）／ npm run lanes -- --check（食い違えば失敗）
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { LANE_NAMES, SPEC_VERSION, type LaneName } from "../src/lanes.ts";

export const LANE_LABELS: Readonly<Record<LaneName, string>> = Object.freeze({
  key: "鍵",
  stream: "ストリーミング",
  sync: "同期",
  api: "API",
  ai: "AI",
  record: "レコード",
  event: "イベント",
  media: "メディア",
});

export interface LaneChange {
  /** その時のレーンの版 */
  readonly version: string;
  /** 本体（love-connect-hub）の版 */
  readonly package: string;
  readonly date: string;
  /** 全レーンにかかる変更か */
  readonly common: boolean;
  /** 変更の要約（その版の最初の項目） */
  readonly summary: string;
}

export interface LaneInfo {
  readonly name: LaneName;
  readonly label: string;
  readonly version: string;
  readonly updated: string;
  /** 新しい順 */
  readonly history: readonly LaneChange[];
}

export interface LanesFile {
  readonly package: string;
  readonly spec: number;
  readonly lanes: readonly LaneInfo[];
}

interface Release {
  version: string;
  date: string;
  lanes: LaneName[];
  common: boolean;
  summary: string;
}

const plain = (s: string) =>
  s.replace(/\*\*/g, "").replace(/`/g, "").replace(/\s+/g, " ").trim();

/** 変更履歴を版ごとに読む（古い順で返す） */
export function parseChangelog(text: string): Release[] {
  const out: Release[] = [];
  const sections = text.split(/^## /m).slice(1);
  for (const sec of sections) {
    const head = /^([0-9]+\.[0-9]+\.[0-9]+)（([0-9]{4}-[0-9]{2}-[0-9]{2})）/.exec(sec);
    if (!head) throw new Error("版の見出しを読めません: " + sec.slice(0, 40));
    const version = head[1]!, date = head[2]!;
    const items = sec.split("\n").filter((l) => l.startsWith("- "));
    const tag = items[0];
    if (!tag || !tag.startsWith("- 対象のレーン：")) {
      throw new Error(`${version} の最初の行に「- 対象のレーン：」がありません`);
    }
    const body = tag.slice("- 対象のレーン：".length);
    let lanes: LaneName[];
    const common = body.trim() === "全レーン";
    if (common) lanes = [...LANE_NAMES];
    else {
      lanes = [];
      for (const m of body.matchAll(/（`?([a-z]+)`?）/g)) {
        const name = m[1] as LaneName;
        if (!LANE_NAMES.includes(name)) throw new Error(`${version} の対象のレーンに知らない名前があります: ${m[1]}`);
        if (!lanes.includes(name)) lanes.push(name);
      }
      if (!lanes.length) throw new Error(`${version} の対象のレーンが読めません: ${body}`);
    }
    out.push({ version, date, lanes, common, summary: plain((items[1] ?? "").replace(/^- /, "")).slice(0, 200) });
  }
  return out.reverse();
}

const parts = (v: string) => v.split(".").map(Number) as [number, number, number];

/** 変更履歴からレーンごとの版を作る */
export function buildLanes(changelog: string, packageVersion: string): LanesFile {
  const releases = parseChangelog(changelog);
  const latest = releases[releases.length - 1];
  if (!latest || latest.version !== packageVersion) {
    throw new Error(`変更履歴のいちばん新しい版（${latest?.version}）と package.json の版（${packageVersion}）が違います`);
  }
  const state = new Map<LaneName, { v: [number, number, number]; history: LaneChange[] }>();
  let prev: [number, number, number] | null = null;
  for (const r of releases) {
    const p = parts(r.version);
    const majorUp = !prev || p[0] > prev[0];
    const patchOnly = !!prev && p[0] === prev[0] && p[1] === prev[1];
    for (const lane of r.lanes) {
      const cur = state.get(lane);
      let v: [number, number, number];
      if (!cur || majorUp) v = [p[0], 0, 0];
      else if (patchOnly) v = [cur.v[0], cur.v[1], cur.v[2] + 1];
      else v = [cur.v[0], cur.v[1] + 1, 0];
      const history = cur?.history ?? [];
      history.unshift({ version: v.join("."), package: r.version, date: r.date, common: r.common, summary: r.summary });
      state.set(lane, { v, history });
    }
    prev = p;
  }
  const lanes = LANE_NAMES.map((name) => {
    const s = state.get(name);
    if (!s) throw new Error(`レーン ${name} の履歴がありません`);
    return { name, label: LANE_LABELS[name], version: s.v.join("."), updated: s.history[0]!.date, history: s.history };
  });
  return { package: packageVersion, spec: SPEC_VERSION, lanes };
}

const root = new URL("..", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), "utf8");

export function currentLanes(): LanesFile {
  return buildLanes(read("CHANGELOG.md"), JSON.parse(read("package.json")).version);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = JSON.stringify(currentLanes(), null, 2) + "\n";
  if (process.argv.includes("--check")) {
    if (read("lanes.json") !== text) {
      console.error("lanes.json が変更履歴と食い違っています。npm run lanes で作り直してください");
      process.exit(1);
    }
    console.log("lanes.json は変更履歴と一致しています");
  } else {
    writeFileSync(new URL("lanes.json", root), text);
    console.log("lanes.json を書き直しました");
  }
}
