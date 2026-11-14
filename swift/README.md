# LoveConnectHub（Swift）

LOVE connect HUB のアプリ側の部品（iPhone・iPad・Mac）。規格書 第18章「利用者の口」の送り口を、`src/user.ts` の `createUserClient` と同じ動きで作ったもの。

- アプリは署名用・暗号化用の鍵を持たない。ログインのトークンだけを付けて「下書き」を送る
- 送る前に下書きを検査し、通らないものは送らない（`Draft.check()`）
- 一時的な失敗だけを同じ番号でやり直す。期限切れのときだけトークンを取り直して一度だけ送り直す
- 外部部品なし（Foundation だけ）

## 使い方

```swift
import LoveConnectHub

let hub = try HubUserClient(url: URL(string: "https://nsc.ns-solution.jp/lch/v1/user")!) { refresh in
    try await session.accessToken(refresh: refresh)   // アプリのログインから取る
}
let r = await hub.send(Draft(lane: .record, format: "record.attendance.clockin", body: ["clockInType": "通常"]))
```

## テスト

```sh
cd swift && swift test
```

本物の受け口（TypeScript）との相互の確認：

```sh
node --experimental-strip-types swift/Interop/server.ts   # 表示された url と token を使う
cd swift && LCH_INTEROP_URL=… LCH_INTEROP_TOKEN=… swift test
```
