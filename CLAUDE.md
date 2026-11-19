# LOVE connect HUB 作業規約

- 規格の正本は `docs/規格.md`。規格を変えるときは、先に規格書を直し、`src/` と同じ内容に保つ。
- 追求する順：機密性 → レスポンス → 速度 → 軽さ。速度や軽さのために機密性を下げない。
- 実行時の外部部品は入れない。標準機能（Web Crypto など）だけで書く。開発用の部品は版を固定し、出てから 2 週間以上たった版だけを使う。
- 特定のアプリ・会社・公開先に依存する処理を `src/` に書かない（それは各アプリの側で、形式の許可表として渡す）。
- 鍵・トークンの値を、リポジトリ・記録・チャットに書かない。
- 変更後は `npm run check`（型検査とテスト）を通す。`swift/` を変えたときは `cd swift && swift test`、`kotlin/` を変えたときは `cd kotlin && ./gradlew :lch:testDebugUnitTest` も通し、受け口や下書きの決まりを変えたときは相互の確認（`swift/Interop/`）も行う。
- 版を上げるときは、変更履歴の新しい版の最初の行に「- 対象のレーン：」（全レーン、またはレーン名を括弧で書いた並び）を書き、`npm run lanes` で `lanes.json` を作り直す（`npm run check` が食い違いを止める）。レーンごとの版は Rhetoric Studio が読む。
- コメント・コミット・変更履歴は日本語。ブランチ → マージリクエスト → マージの順で進める。
- 正本は GitHub（loverhetoric-gif/love-connect-hub）。作業ブランチ → PR → マージは GitHub で行う。
- GitLab（loverhetoric1/love-connect-hub）はバックアップ。GitLab で作業を進めない。写すときは UnderTalk の窓口 `lch-gitlab` を使う（鍵の値は扱わない）。
