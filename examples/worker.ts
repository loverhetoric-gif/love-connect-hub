// 見本：Cloudflare Workers に LOVE connect HUB の受け口を置く。
// 署名用の鍵は Workers の秘密の値（wrangler secret put LCH_SIGNING_KEY）に base64url で入れる。
// 鍵の値をこのファイルやリポジトリに書かない。

import {
  type Envelope,
  createHttpHandler,
  createReceiver,
  formatTable,
  fromBase64Url,
  importSigningKey,
} from "../src/index.ts";

export interface Env {
  /** 署名用の鍵（base64url、32 バイト以上）。秘密の値として登録する */
  LCH_SIGNING_KEY: string;
  /** この受け口が受け付ける会社 ID */
  LCH_COMPANY: string;
}

/** このハブが受け付ける形式（許可の書いていないものは禁止） */
const FORMATS = formatTable({
  event: ["event.app.done"],
  record: ["record.app.item"],
});

let cached: { raw: string; key: CryptoKey } | undefined;
async function signingKey(env: Env): Promise<CryptoKey> {
  if (cached?.raw !== env.LCH_SIGNING_KEY) {
    cached = { raw: env.LCH_SIGNING_KEY, key: await importSigningKey(fromBase64Url(env.LCH_SIGNING_KEY)) };
  }
  return cached.key;
}

/** 受け取った封筒の処理（ここを各ハブの処理に置き換える） */
async function handle(env: Envelope): Promise<void> {
  void env;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const key = await signingKey(env);
    // 受け口は Workers の 1 つの実行の間だけ使う（重複防止の記憶も、その間だけ）。
    // 複数の実行をまたいで重複を防ぐには、Durable Objects などに記憶を置く（規格書 第16章）。
    const receiver = createReceiver({
      formats: FORMATS,
      now: () => Date.now(),
      signingKey: (co) => (co === env.LCH_COMPANY ? key : undefined),
    });
    return createHttpHandler({ receiver, onEnvelope: handle })(request);
  },
};
