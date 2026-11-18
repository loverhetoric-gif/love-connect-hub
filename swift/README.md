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

## 端末の鍵（規格書 第21章）

トークンが盗まれても別の端末から送れないように、端末の中の取り出せない鍵（Secure Enclave）で、送るたびに証明を付ける。

```swift
// 鍵は本当に無いときだけ作る（参照は保存して持ち越す。作り直すと登録が外れる）
let key = try SecureEnclaveDeviceKey.create(requireBiometry: false)
save(key.dataRepresentation)
// 別の画面の QR で受け取った使い捨ての合言葉で、1 度だけ登録する
_ = await HubUserClient.enroll(url: deviceURL, token: token, device: key, co: companyId, by: userId, code: code)
// 以後は端末の鍵つきで送る
let hub = try HubUserClient(url: userURL, token: { refresh in try await session.accessToken(refresh: refresh) }, device: key)
```

承認の鍵（`use: "approve"`）は `requireBiometry: true` で作り、署名のたびに Face ID・Touch ID を求める。

## テスト

```sh
cd swift && swift test
```

本物の受け口（TypeScript）との相互の確認：

```sh
node --experimental-strip-types swift/Interop/server.ts   # 表示された url と token を使う
cd swift && LCH_INTEROP_URL=… LCH_INTEROP_TOKEN=… LCH_INTEROP_CODE=… swift test
```
