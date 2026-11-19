import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildLanes, currentLanes, parseChangelog } from "../tools/lanes.ts";
import { LANE_NAMES } from "../src/lanes.ts";

const LOG = (body: string) => "# 変更履歴\n\n" + body;

test("lanes.json は変更履歴から作った内容と一致する（npm run lanes の書き忘れを止める）", () => {
  const file = JSON.parse(readFileSync(new URL("../lanes.json", import.meta.url), "utf8"));
  assert.deepEqual(file, JSON.parse(JSON.stringify(currentLanes())));
});

test("全レーンの版と履歴がそろい、レーンの版はいちばん新しい履歴の版と同じ", () => {
  const f = currentLanes();
  assert.deepEqual(f.lanes.map((l) => l.name), [...LANE_NAMES]);
  for (const l of f.lanes) {
    assert.ok(l.history.length > 0, l.name);
    assert.equal(l.version, l.history[0]!.version, l.name);
    assert.equal(l.updated, l.history[0]!.date, l.name);
  }
});

test("規格版が上がった版は x.0.0、対象外のレーンは版が変わらない、3 つ目だけの版は 3 つ目を上げる", () => {
  const f = buildLanes(LOG([
    "## 2.0.1（2026-01-04）\n\n- 対象のレーン：鍵（`key`）\n- 直した",
    "## 2.0.0（2026-01-03）\n\n- 対象のレーン：全レーン\n- 第2版",
    "## 1.1.0（2026-01-02）\n\n- 対象のレーン：メディア（`media`）・AI（`ai`）\n- 分割",
    "## 1.0.0（2026-01-01）\n\n- 対象のレーン：全レーン\n- **第1版**",
  ].join("\n\n")), "2.0.1");
  const v = Object.fromEntries(f.lanes.map((l) => [l.name, l.version]));
  assert.equal(v.key, "2.0.1");
  assert.equal(v.media, "2.0.0");
  assert.equal(v.record, "2.0.0");
  const media = f.lanes.find((l) => l.name === "media")!;
  assert.deepEqual(media.history.map((h) => [h.version, h.package, h.common]), [["2.0.0", "2.0.0", true], ["1.1.0", "1.1.0", false], ["1.0.0", "1.0.0", true]]);
  assert.equal(media.history[2]!.summary, "第1版");
});

test("対象のレーンが無い・知らないレーン・本体の版と食い違いは止める", () => {
  assert.throws(() => parseChangelog(LOG("## 1.0.0（2026-01-01）\n\n- 作った")), /対象のレーン/);
  assert.throws(() => parseChangelog(LOG("## 1.0.0（2026-01-01）\n\n- 対象のレーン：謎（`nazo`）\n- 作った")), /知らない名前/);
  assert.throws(() => buildLanes(LOG("## 1.0.0（2026-01-01）\n\n- 対象のレーン：全レーン\n- 作った"), "1.1.0"), /package.json/);
});
