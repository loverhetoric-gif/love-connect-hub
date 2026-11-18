# LoveConnectHub（Kotlin・Android）

LOVE connect HUB のアプリ側の部品（Android 11 以上）。規格書 第18章「利用者の口」と第21章「端末の鍵」を、`src/user.ts`・`swift/` と同じ動きで作ったもの。外部部品なし（Android の標準の機能だけ）。

- アプリは署名用・暗号化用の鍵を持たない。ログインのトークンだけを付けて「下書き」を送る
- 端末の鍵は Android Keystore（StrongBox があればそこ）。秘密の部分は Keystore の外へ出ない
- 承認の鍵は、署名のたびにクラス 3（強い）の生体認証（指紋・顔・虹彩）を求める。PIN・パターンでは代われない

## 使い方

```kotlin
// 鍵は本当に無いときだけ作る（作り直すと登録が外れる）
val key = AndroidKeystoreDeviceKey.loadOrCreate("lch-device", use = "device")
// 別の画面の QR で受け取った使い捨ての合言葉で、1 度だけ登録する（作業用のスレッドから）
HubUserClient.enroll(deviceUrl, token, key, co = companyId, by = userId, code = code)
// 以後は端末の鍵つきで送る
val hub = HubUserClient(userUrl, { refresh -> session.accessToken(refresh) }, device = key)
hub.send(Draft(Lane.RECORD, "record.attendance.clockin", body = mapOf("clockInType" to "通常")))

// 承認：指紋・顔で本人を確かめてから署名する
val approver = AndroidKeystoreDeviceKey.loadOrCreate("lch-approve", use = "approve")
approver.signWithBiometric(activity, hubApprovalMessage(co, envId, envHash, now), "承認", "内容を確かめてください", "やめる", mainExecutor) { result -> /* 署名を土台へ */ }
```

## 鍵の証明（Android の鍵の証明書）

鍵を作るときに問いかけを入れると、`enroll` が鍵の証明書の鎖を添えて送る。土台は `verifyAndroidAttestation` で、鍵が端末の金庫の部品で作られ、承認の鍵が使うたびに生体認証を求めることを確かめる。

```kotlin
val challenge = AndroidKeystoreDeviceKey.attestationChallenge(companyId, userId)
val key = AndroidKeystoreDeviceKey.loadOrCreate("lch-device", use = "device", attestationChallenge = challenge)
```

## テスト

```sh
cd kotlin && ./gradlew :lch:testDebugUnitTest
```

本物の受け口（TypeScript）との相互の確認：

```sh
node --experimental-strip-types swift/Interop/server.ts   # 表示された url・token・code を使う
cd kotlin && LCH_INTEROP_URL=… LCH_INTEROP_TOKEN=… LCH_INTEROP_CODE=… ./gradlew :lch:testDebugUnitTest
```

端末の上の試験（鍵の作成・署名・鍵の証明書の鎖）は、端末か模擬端末をつないで `./gradlew :lch:connectedDebugAndroidTest`。

Java は Android Studio に入っているもの（`/Applications/Android Studio.app/Contents/jbr/Contents/Home`）を `JAVA_HOME` に指定する。
