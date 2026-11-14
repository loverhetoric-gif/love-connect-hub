// 鍵の置き場所と参照。規格書 第20章。
// 封筒・定義書・記録に書くのは参照（置き場所の名前）だけ。値は使う瞬間に土台だけが取り出す。
//  - env:名前 … 土台の秘密の値（Cloudflare の Secrets など）。署名用・暗号化用の鍵はここだけに置く
//  - ut:カテゴリ … UnderTalk の代理実行。土台も値を見ない（UnderTalk が送る直前に付ける）

import { fromBase64Url, importSealKey, importSigningKey, sha256Hex } from "./crypto.ts";

export type KeyStore = "env" | "ut";

export interface KeyRef {
  store: KeyStore;
  name: string;
}

const ENV_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const UT_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** 鍵の参照を読む。形が違えば例外（動かす前に止める） */
export function parseKeyRef(ref: string): KeyRef {
  const i = ref.indexOf(":");
  const store = i > 0 ? ref.slice(0, i) : "";
  const name = i > 0 ? ref.slice(i + 1) : "";
  if (store === "env" && ENV_RE.test(name)) return { store, name };
  if (store === "ut" && UT_RE.test(name)) return { store, name };
  throw new Error(`鍵の参照の形が正しくありません（env:大文字の名前 か ut:カテゴリ）：${ref.slice(0, 80)}`);
}

/** 土台の秘密の値を名前で読む（Cloudflare Workers なら env[名前]）。値を記録に出さない */
export type SecretReader = (name: string) => string | undefined;

export interface CompanyKeysOptions {
  /** 秘密の値の読み方 */
  read: SecretReader;
  /**
   * 会社ごとの署名用の鍵の参照（env: だけ）。先頭が今の鍵で、署名に使う。
   * 2 つ目以降は入れ替えの途中の鍵で、確かめるときだけ使う。
   */
  signing: Readonly<Record<string, readonly string[]>>;
  /** 会社ごとの暗号化用の鍵の参照（env: だけ）。先頭で暗号化し、開くときは全部を試す */
  seal?: Readonly<Record<string, readonly string[]>>;
}

export interface CompanyKeys {
  /** 署名に使う今の鍵（無ければ undefined） */
  signingKey(co: string): Promise<CryptoKey | undefined>;
  /** 確かめるときに使う鍵（今の鍵＋入れ替えの途中の鍵） */
  verifyKeys(co: string): Promise<CryptoKey[]>;
  /** 暗号化に使う今の鍵 */
  sealKey(co: string): Promise<CryptoKey | undefined>;
  /** 開くときに使う鍵 */
  openKeys(co: string): Promise<CryptoKey[]>;
}

function envOnly(refs: readonly string[], what: string): string[] {
  return refs.map((r) => {
    const k = parseKeyRef(r);
    if (k.store !== "env") throw new Error(`${what}は土台の秘密の値（env:）にだけ置けます：${r}`);
    return k.name;
  });
}

/**
 * 会社ごとの署名用・暗号化用の鍵を、参照から読み込む。
 * 読み込んだ鍵は覚えておき、秘密の値が変わったときだけ読み直す（入れ替えに追従する）。
 * 値の形：base64url（署名用は 32 バイト以上、暗号化用はちょうど 32 バイト）。
 */
export function createCompanyKeys(opts: CompanyKeysOptions): CompanyKeys {
  // 参照の形は、作るときに全部確かめる
  const signing = new Map(Object.entries(opts.signing).map(([co, refs]) => [co, envOnly(refs, "署名用の鍵")]));
  const seal = new Map(Object.entries(opts.seal ?? {}).map(([co, refs]) => [co, envOnly(refs, "暗号化用の鍵")]));
  const cache = new Map<string, { fp: string; key: CryptoKey }>();

  async function load(name: string, kind: "sign" | "seal"): Promise<CryptoKey | undefined> {
    const raw = opts.read(name);
    if (raw === undefined || raw === "") return undefined;
    // 値そのものは覚えず、ハッシュで「変わったか」だけを見る
    const fp = await sha256Hex(`${kind}|${raw}`);
    const hit = cache.get(`${kind}|${name}`);
    if (hit && hit.fp === fp) return hit.key;
    let bytes: Uint8Array;
    try {
      bytes = fromBase64Url(raw.trim());
    } catch {
      throw new Error(`秘密の値の形が正しくありません（base64url）：${name}`);
    }
    const key = kind === "sign" ? await importSigningKey(bytes) : await importSealKey(bytes);
    bytes.fill(0);
    cache.set(`${kind}|${name}`, { fp, key });
    return key;
  }

  async function all(names: readonly string[] | undefined, kind: "sign" | "seal"): Promise<CryptoKey[]> {
    const out: CryptoKey[] = [];
    for (const n of names ?? []) {
      const k = await load(n, kind);
      if (k) out.push(k);
    }
    return out;
  }

  return {
    async signingKey(co) {
      const first = signing.get(co)?.[0];
      return first ? load(first, "sign") : undefined;
    },
    verifyKeys: (co) => all(signing.get(co), "sign"),
    async sealKey(co) {
      const first = seal.get(co)?.[0];
      return first ? load(first, "seal") : undefined;
    },
    openKeys: (co) => all(seal.get(co), "seal"),
  };
}

/**
 * 代理実行の窓口（UnderTalk など）。土台は値を見ずに、許可された操作だけを頼む。
 * 中核部品は形だけを決める。UnderTalk へのつなぎ方の見本は examples/undertalk.ts。
 */
export interface KeyBroker {
  call(category: string, op: string, args: Record<string, unknown>): Promise<unknown>;
}

/** 参照が ut: なら代理実行の窓口へ渡す。env: の鍵を外へ渡す道は作らない */
export async function callWithKey(
  ref: string,
  broker: KeyBroker,
  op: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const k = parseKeyRef(ref);
  if (k.store !== "ut") throw new Error("代理実行に使えるのは ut: の参照だけです");
  return broker.call(k.name, op, args);
}
