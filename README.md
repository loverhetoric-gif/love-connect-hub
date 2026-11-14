# LOVE connect HUB

LOVE rhetoric 共通の HUB 規格。どんな種類のデータでも、8 本のレーンと共通の封筒で、同じ作法で出し入れする。

- 規格の正本：[`docs/規格.md`](docs/規格.md)
- 追求すること：機密性 → レスポンス → 速度 → 軽さ

## 8 本のレーン

| レーン | 流れるもの |
|---|---|
| 鍵 `key` | API キー・トークン・本人確認（値は流さず、置き場所だけ） |
| ストリーミング `stream` | 配信・録音・センサー・ログ |
| 同期 `sync` | 共同編集・チャット・端末間の同期 |
| API `api` | 外部サービスとのやり取り |
| AI `ai` | 指示文・応答・逐次生成 |
| レコード `record` | 表のデータ |
| イベント `event` | 通知・Webhook |
| メディア `media` | 画像・音声・動画・PDF |

## アプリからの送信（本人確認）

アプリ（iPhone・Android・Web）には署名用・暗号化用の鍵を持たせません。ログインのトークン付きで「下書き」を送り、土台が本人を確かめてから正式な封筒にします（規格書 第18章）。

## 使い方

```ts
import { checkEnvelope, signEnvelope, verifyEnvelope } from "love-connect-hub";

const r = checkEnvelope(受け取った封筒, { formats: { record: new Set(["record.nsc.attendance"]) } });
if (!r.ok) return 拒否(r.code, r.message);
```

## 開発

```sh
npm install
npm run check   # 型検査とテスト
```

実行時の外部部品はありません。Node.js 22.6 以上、Cloudflare Workers、ブラウザで動きます。
