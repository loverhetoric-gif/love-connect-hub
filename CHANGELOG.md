# 変更履歴

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
