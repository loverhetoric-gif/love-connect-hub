# 変更履歴

## 2.2.0（2026-11-18）

- 映像・音声のリアルタイム通信（第23章）の Swift 版（`Rtc.swift`）と Kotlin 版（`Rtc.kt`）を追加。連絡の署名と確かめ・SDP の確かめと並べ替え・送る量の上限・遠隔支援の信号と許可の確かめ・張り替えの決まりを、TypeScript 版と同じ決まりで持つ。
- 相互の確認：TypeScript が署名した見本（`test/vectors/rtc.json`。改行・引用符・日本語・制御文字を含む SDP と、遠隔操作の許可）を、Swift・Kotlin が同じ文に直して確かめた。
- テスト：TypeScript 144 件、Swift 26 件、Kotlin 15 件。

## 2.1.0（2026-11-18）

- **映像・音声のリアルタイム通信を規格にした**（規格書 第23章）。WEB 会議と遠隔支援（リモートアシスタント）に使う。WARPHOLE.（iPhone から Mac を操作するアプリ）で実際に動いている作りを、共通の決まりにした。封筒の形は変えない。
  - 映像・音声は端末どうしで直接送り（WebRTC）、直接つながらないときだけ中継（Cloudflare Realtime の TURN。期限 24 時間の許可を、部屋に入った人にだけ渡す）を通す。部屋と土台は映像を通さない
  - つなぐための連絡は、端末の鍵（第21章）で署名する。SDP（暗号の鍵の指紋）ごと署名するので、部屋や中継が割り込めない（`signRtc`・`createRtcVerifier`・`sdpProblem`）
  - 経路の張り替え（切れかけたらすぐ・5 秒ごと・20 秒で終える。回線が変わったら切れる前に。`createRestartPolicy`）
  - 映像は HEVC → H.264 High → VP9 → AV1 → VP8 の順（`preferVideoCodecs`）。音声は Opus に欠けの補いと無音の省略（`tuneOpus`）
  - 用途（画面・カメラ）と回線（Wi-Fi・モバイル回線）ごとの送る量の上限（`rtcBudget`）
  - 操作の 2 本の道（確実な `ctl`・欠けたら捨てる `mv`）と信号の確かめ（`checkAssistSignal`。遠隔支援ではパスワードを打たせない）
  - **遠隔操作は、支援される本人が承認の鍵（生体認証）で許したときだけ**。範囲（見る・指し示す・操作する）と期限（最長 30 分）つき（`verifyControlGrant`）
  - 計測の形（`summarizeRtcStats`）
  - 部屋の中核（`createRtcRoom`）と、Cloudflare の部屋（`LchRtcRoomObject`・`rtcRoomRequest`・`cloudflareTurn`）
- 次の段階：5 人以上の会議（SFU と SFrame）、Swift 版・Kotlin 版、PLEATS. の画面。
- テスト：TypeScript 143 件。

## 2.0.0（2026-11-18）

- **規格 第2版：作業 ID を全アプリ・全道具の基本の決まりにした**（規格書 第22章）。作業ひとつひとつに付ける番号（`w-` ＋ 英数字 8 文字）を、道具・アプリのあいだで相互に分け合う。先に出した方を、もう片方が引用する。今後のアプリは、この規格を基盤として作る。
  - 封筒・下書きに `tk`（作業 ID）を足した。署名は `tk` も守る（付け替え・取り外しは通らない）
  - 受け口・土台は第1版と第2版の両方を受け付ける。送り口は、作業 ID を付けるときだけ第2版の封筒を作り、付けないときは第1版のまま送る（第1版だけの受け口にも、これまでどおり届く）。第1版の封筒に `tk` があれば拒否する
  - 作業 ID の記録帳 `createTaskBook`（`task.ts`）：発行・引用・知らない ID の引き受け・終わった ID を断る・終了の宣言。放置で終わらせ・消すことはせず、消すのは終了を宣言して 7 日たった物だけ
  - Swift 版 `Draft(task:)`、Kotlin 版 `Draft(task = …)`。作業 ID を付けると第2版の下書きになる
  - 相互の確認の受け口（`swift/Interop/server.ts`）が作業 ID を返すようにし、Swift・Kotlin の送り口から本物の受け口まで作業 ID が届くことを確かめた
- テスト：TypeScript 131 件、Swift 20 件（相互の確認を含む）、Kotlin 9 件（相互の確認を含む）。

## 1.11.0（2026-11-18）

- iPhone・iPad・Mac の App Attest を確かめる部品を追加（規格書 第21章）。Apple の本物の端末の上の、許したアプリが端末の鍵を登録していることを、土台が確かめる（`verifyAppleAppAttest`）。改造したアプリ・偽のアプリ・シミュレーターからの登録は通らない。
  - 証明書の鎖を Apple App Attestation Root CA（公開鍵の SHA-256 で固定）までたどり、nonce・鍵の ID・アプリ（チーム ID.バンドル ID）・使った回数・本番か開発用かを確かめる。外部部品は入れず、Web Crypto と小さな CBOR の読み取り（`cbor.ts`）だけで書いた
  - clientDataHash に会社・本人・使い道・端末の公開鍵を入れ、証明を別の登録に使い回せないようにした（`appAttestClientDataHash`）
  - 鍵の証明の決まり `createAttestationCheck`：Android と Apple を `att.platform` で振り分け、承認の鍵は既定で証明を必須にする
  - 証明書の読み取りを `x509.ts` に分け、Android と Apple で共通にした
  - 登録の本文の上限を 4KB から 16KB に広げた（鍵の証明書の鎖・App Attest の証明が 4KB を超えるため）
  - Swift 版：`HubAppAttest.attestation`（App Attest の鍵を作り、証明を受け取る）、`HubUserClient.enroll` の `attestation`、`hubAppAttestClientDataHash`
- テスト：TypeScript 123 件、Swift 19 件（2 件は本物の受け口があるときだけ）。

## 1.10.0（2026-11-18）

- Android の鍵の証明書（Key Attestation）を確かめる部品を追加（規格書 第21章）。アプリの申告を信じずに、鍵が端末の金庫の部品（TEE・StrongBox）の中で作られ、承認の鍵が使うたびに強い生体認証を求めることを、土台が確かめる（`verifyAndroidAttestation`）。
  - 証明書の鎖を Google の根（RSA 4096・ECDSA P-384「Key Attestation CA1」。公開鍵の SHA-256 で固定）までたどり、有効期間・取り消し・公開鍵の一致・問いかけ・鍵の性質・起動の検査・作ったアプリを確かめる。外部部品は入れず、Web Crypto と小さな DER の読み取り（`asn1.ts`）だけで書いた
  - 登録の入口に `attest` を追加。通らなければ `PAIR_ATTEST` で断り、合言葉は使わない
  - Kotlin 版：鍵を作るときの問いかけ（`attestationChallenge`）と、鍵の証明書の鎖の取り出し（`attestationChain`）。`enroll` は Android Keystore の鍵なら鎖を添える
- Android の模擬端末（Android 17）で、Kotlin 版が作った本物の鍵の証明書の鎖を TypeScript の部品で読み、鎖の署名・公開鍵・問いかけ・鍵の記述（KeyMint 400）を正しく読めることを確かめた（模擬端末の鍵はソフトウェアの鍵なので、狙いどおり断る）。
- テスト：TypeScript 115 件、Kotlin 8 件 ＋ 端末の上の試験 1 件。

## 1.9.0（2026-11-18）

- 台数をまたぐ重複の記憶を追加（規格書 第16章・第2版の計画 A の 1）。受け口・利用者の口の `dedupe` と、端末の確認の `nonces` に、答えを待つ形の記憶（`SharedDedupe`）を渡せるようにした。
- Cloudflare Durable Objects に置く部品を `adapters/cloudflare/dedupe.ts` に追加（`LchDedupeObject`・`createDurableDedupe`）。会社ごとに 1 つの Durable Object が 1 件ずつ答えるので、別々の台に同時に送られても同じ番号は 1 回だけ通る。問い合わせられないときは通さない。
- 置き場所を使った重複の確かめ `storageFirst`（窓を過ぎた記憶を古い順に少しずつ消す）。
- テスト 109 件。

## 1.8.0（2026-11-18）

- 端末の鍵を追加（規格書 第21章）。WARPHOLE.（iPhone から Mac を操作するアプリ）の「端末の中の取り出せない鍵」「使い捨ての合言葉によるペアリング」「Face ID による承認」を、利用者の口に取り入れた。第2版の計画 B（DPoP と同じ考え方）の 1 つ目。
  - 端末の鍵は ECDSA P-256。iPhone・iPad・Mac は Secure Enclave、Web は取り出せない CryptoKey。秘密の部分は端末の外へ出さない。封筒の署名・暗号化には使わない（第18章のとおり）
  - 端末の登録：ログインのトークン ＋ 別の画面に出した使い捨ての合言葉（5 分・1 回だけ）＋ 鍵を持っている証明（`createDeviceEnrollment`・`issuePairingCode`）
  - 送るたびの証明（`lch-device` 見出し）：トークン・本文・入口に結び付けた署名。時刻は前後 2 分、使い捨ての番号は 5 分覚える（`createDeviceVerifier`）。利用者の口に `device` を渡すと、トークンを盗まれても別の端末からは送れない
  - 承認の証明：承認の鍵（署名のたびに生体認証）で封筒の中身に署名する（`signApproval`・`verifyApproval`）。AI や土台は作れない
  - アプリ側：`createUserClient` の `device`・`createWebDeviceKey`、Swift 版の `SecureEnclaveDeviceKey`・`HubUserClient(device:)`・`HubUserClient.enroll`
- 生体認証を端末ごとに決めた：iPhone・iPad は Face ID・Touch ID、Mac は Touch ID（Secure Enclave の `.biometryCurrentSet`）、Android はクラス 3（強い）の生体認証（指紋・顔・虹彩。Keystore の `AUTH_BIOMETRIC_STRONG`）。どれも PIN・パスコードでは代われず、登録し直すと承認の鍵は使えなくなる。
- Kotlin 版（`kotlin/`。Android 11 以上・外部部品なし）を追加：下書き・送り口（Swift 版と同じ動き）・Android Keystore の端末の鍵（StrongBox があればそこ）・`BiometricPrompt` での承認の署名。
- Swift 版に、Face ID・Touch ID の画面に理由を出す承認の署名（`signWithBiometry`）と、承認の文（`hubApprovalMessage`）を追加。
- 相互の確認：Swift（CryptoKit）と Kotlin（Java の標準）の端末の鍵の署名を、TypeScript（Web Crypto）の受け口が確かめた。
- テスト：TypeScript 105 件、Swift 18 件、Kotlin 8 件（相互の確認を含む）。

## 1.7.0（2026-11-14）

- Swift 版のアプリ側の送り口を追加（`swift/`。iPhone・iPad・Mac 用、外部部品なし）。下書きの検査・同じ番号でのやり直し・期限切れのときだけのトークンの取り直しを、TypeScript 版と同じ動きにした。
- 本物の受け口（TypeScript）と Swift 版が話せるかの相互の確認を追加（`swift/Interop/`）。
- Swift のテスト 14 件（相互の確認 1 件を含む）。

## 1.6.0（2026-11-14）

- 鍵の置き場所を追加（規格書 第20章）。参照は env:（土台の秘密の値）と ut:（UnderTalk の代理実行）の 2 種類だけ。署名用・暗号化用の鍵は env: だけに置く。
- 会社ごとの鍵の入れ替えに対応：先頭の鍵で署名・暗号化し、入れ替えの途中の鍵でも確かめる・開ける（受け口と readBody が鍵の並びを受け付ける）。
- 代理実行の窓口の形（KeyBroker）と、UnderTalk につなぐ見本を追加。
- テストを 99 件に拡充。

## 1.5.0（2026-11-14）

- ハブのつなぎ方を追加（規格書 第19章）。形式の名前は「レーン名.ハブID.名前」。許可表は各ハブの定義書の宣言（出す・受け取る・利用者に開く）から土台が組み立てる。
- ハブ同士の連動を 2 種類に整理：一緒に成り立つ連動は相手のハブの動作を呼ぶ、後から起きてよい連動はイベントで知らせる。
- 第18章に、自前のセッションのトークンを使うアプリ（N.S Connection）の扱いを追記。
- テストを 92 件に拡充。

## 1.4.0（2026-11-14）

- 利用者の口（本人確認）を追加（規格書 第18章）。アプリには署名用・暗号化用の鍵を持たせず、ログインのトークンで本人を確かめてから、土台が会社・送り手・時刻を付けて署名・暗号化する。
- トークンの検査を追加：ES256・RS256（公開鍵の一覧）と HS256。none・方式の取り違え・長すぎる有効期間を拒否する。
- アプリ側の送り口を追加：期限切れのときだけトークンを取り直して送り直す。
- テストを 90 件に拡充。

## 1.3.0（2026-11-10）

- 通信の口を追加：HTTP の受け口・送り口、WebSocket の口。標準の Request／Response／WebSocket だけで、Cloudflare Workers・Node.js・ブラウザで動く。
- 拒否の理由ごとの HTTP の状態番号を決めた（受け取り済みは届いたとみなす）。
- Cloudflare Workers の見本（examples/worker.ts）を追加。
- テストを 75 件に拡充。

## 1.2.0（2026-11-10）

- 残り4レーンの部品を追加：ストリーミングの並べ直し、同期の版の照合と項目ごとのまとめ、API の再試行、AI の逐次受け取り。
- 続き物の番号（まとまり番号_順番）を共通の部品にした。
- テストを 63 件に拡充。

## 1.1.0（2026-11-08）

- 送り口・受け口を追加（全レーン共通）。受け口は長さ → 形 → 時刻 → 署名 → 重複の順に検査し、重複の記録は署名の確認後だけに残す。
- レコードの一括（分割・件数とハッシュの照合）と、メディアの分割・組み立て（1 MiB ずつ、ハッシュの照合）を追加。
- 形式の名前は、封筒のレーン名で始めることを必須にした。
- テストを 46 件に拡充。

## 1.0.0（2026-11-06）

- 規格書 第1版を作成（8 本のレーン、共通の封筒、機密性・レスポンス・速度・軽さの決まり）。
- 中核部品を追加：封筒の検査、署名（HMAC-SHA256）、暗号化（AES-256-GCM）、ハッシュの照合、重複防止、処理の順番。
- テスト 25 件を追加。
