// 見本：UnderTalk の代理実行を、LOVE connect HUB の代理実行の窓口（KeyBroker）としてつなぐ。
// 土台は API キーの値を見ない。UnderTalk が、カテゴリで許した接続先・パス・方法の中だけで、送る直前に付ける。
// 土台が持つのは、UnderTalk の「呼び出し元トークン」だけ（秘密の値 UNDERTALK_CALLER_TOKEN）。値をこのファイルに書かない。

import { type KeyBroker, callWithKey } from "../src/index.ts";

export interface UnderTalkEnv {
  /** UnderTalk の公開アドレス（https） */
  UNDERTALK_URL: string;
  /** この土台用に作った呼び出し元トークン。使えるカテゴリは UnderTalk 側で絞る */
  UNDERTALK_CALLER_TOKEN: string;
}

export function createUnderTalkBroker(env: UnderTalkEnv, doFetch: typeof fetch = fetch): KeyBroker {
  const url = new URL("/v1/call", env.UNDERTALK_URL);
  if (url.protocol !== "https:") throw new Error("UnderTalk の送り先は https にしてください");
  return {
    async call(category, op, args) {
      const res = await doFetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${env.UNDERTALK_CALLER_TOKEN}` },
        body: JSON.stringify({ category, op, args }),
        redirect: "error",
      });
      const data = (await res.json().catch(() => ({}))) as { result?: unknown; error?: string };
      if (!res.ok) throw new Error(`UnderTalk が断りました（${res.status}）`);
      return data.result;
    },
  };
}

// 使い方（交通費の経路検索の例）：ハブの定義書に「api.transit.navitime は ut:nsc-navitime の鍵で送る」と書き、
// 土台はその参照で代理実行を頼む。返事から鍵の値は UnderTalk が消してある。
export async function searchRoute(env: UnderTalkEnv, query: Record<string, string>): Promise<unknown> {
  const broker = createUnderTalkBroker(env);
  return callWithKey("ut:nsc-navitime", broker, "request", {
    method: "GET",
    url: `https://navitime-route-totalnavi.p.rapidapi.com/route_transit?${new URLSearchParams(query)}`,
  });
}
