// 利用者の口（本人確認）。規格書 第18章。
// アプリ（iPhone・Android・Web）は署名用・暗号化用の鍵を持たない。持たせると取り出されるため。
// アプリは「下書き」をログインのトークン付きで送り、土台が本人を確かめてから、
// 会社・送り手・時刻を自分で付け、署名・暗号化して、正式な封筒にする。
// 送り手（by）と会社（co）は、アプリの申告ではなく、確かめたトークンからだけ決まる。

import { type CheckOptions, type Envelope, type ErrorCode, checkEnvelope } from "./envelope.ts";
import { type Classification, type LaneName, LANES, isLane } from "./lanes.ts";
import { SendError, createSender, randomId } from "./sender.ts";
import { type Dedupe, createDedupe } from "./dedupe.ts";
import { type TokenClaims, type TokenCode, type TokenVerifier, bearerToken } from "./token.ts";
import { HTTP_STATUS, SECURITY_HEADERS, readLimited } from "./http.ts";
import { RAW_MAX_BYTES } from "./receiver.ts";
import { type RetryOptions, withRetry } from "./api.ts";

/** 既定の入口のパス（封筒の入口とは分ける） */
export const USER_PATH = "/lch/v1/user";

/** 下書きに書いてよい項目。会社・送り手・時刻・署名・暗号方式は土台だけが付ける */
const DRAFT_FIELDS: ReadonlySet<string> = new Set(["v", "l", "f", "id", "c", "dl", "ap", "ret", "sq", "bv", "ref", "len", "h", "b"]);
const STAMPED_FIELDS: ReadonlySet<string> = new Set(["co", "by", "at", "sig", "e"]);

/** 利用者の口から受け付けないレーン。鍵は利用者から直接は扱わせない（固定） */
const USER_FORBIDDEN_LANES: ReadonlySet<LaneName> = new Set(["key"]);

/** 下書き。アプリが送るもの */
export interface Draft {
  v: number;
  l: LaneName;
  f: string;
  /** 一意の番号。やり直しでも同じ番号を使う（二重の実行を防ぐ） */
  id: string;
  c?: Classification;
  dl?: number;
  ap?: boolean;
  ret?: number;
  sq?: number;
  bv?: number;
  ref?: string;
  len?: number;
  h?: string;
  b?: unknown;
}

/** トークンから分かった本人。会社と送り手は、ここからだけ決まる */
export interface UserIdentity {
  co: string;
  by: string;
}

export type UserCode =
  | TokenCode
  | ErrorCode
  | "USER_FORBIDDEN"
  | "STAMPED_FIELD"
  | "LANE_NOT_ALLOWED"
  | "BAD_JSON"
  | "TOO_LARGE"
  | "DUPLICATE"
  | "SERVER_KEY"
  | "METHOD"
  | "NOT_FOUND"
  | "CONTENT_TYPE"
  | "HANDLER";

/** 拒否の名前と HTTP の状態番号 */
export const USER_HTTP_STATUS: Readonly<Record<UserCode, number>> = Object.freeze({
  ...(HTTP_STATUS as Record<string, number>),
  TOKEN_MISSING: 401,
  TOKEN_INVALID: 401,
  TOKEN_EXPIRED: 401,
  USER_FORBIDDEN: 403,
  STAMPED_FIELD: 400,
  LANE_NOT_ALLOWED: 403,
  SERVER_KEY: 500,
}) as Readonly<Record<UserCode, number>>;

export interface UserGatewayOptions {
  /** トークンの検査（createTokenVerifier で作る） */
  verifier: TokenVerifier;
  /**
   * トークンの中身から、会社と送り手を決める。決められない（使わせない）ときは undefined。
   * どの中身を使うかは各アプリが決める（例：会社の台帳を ID で引く）。
   */
  identify: (claims: TokenClaims) => UserIdentity | undefined | Promise<UserIdentity | undefined>;
  /** レーンごとに許す形式（必須）。利用者の口では、封筒の入口より狭くしてよい */
  formats: NonNullable<CheckOptions["formats"]>;
  /** 土台の時計（ミリ秒） */
  now: () => number;
  /** 会社ごとの署名用の鍵。機密以上の下書きを受け付けるには必須 */
  signingKey?: (co: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** 会社ごとの暗号化用の鍵。極秘の本文を受け付けるには必須 */
  sealKey?: (co: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** 重複防止（既定：24 時間・1 万件）。会社・送り手・番号の組で見る */
  dedupe?: Dedupe;
  /**
   * 正式な封筒にしたあとの処理。返した値は、利用者への返事の本文（b）として返す。
   * 返事は暗号化しない（利用者は暗号化用の鍵を持たないため。通信は https で守る）。
   */
  onEnvelope: (env: Envelope, who: UserIdentity) => Promise<unknown> | unknown;
  /** 入口のパス（既定 /lch/v1/user） */
  path?: string;
  /** 処理中の失敗を記録する（本文もトークンも渡さない） */
  onError?: (info: { id: string; lane: string; error: unknown }) => void;
}

function json(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...SECURITY_HEADERS, ...extra } });
}

function reject(code: UserCode, field: string, message: string): Response {
  const status = USER_HTTP_STATUS[code] ?? 400;
  // 401 には、Bearer で送り直すよう示す（理由は短い名前だけ。トークンの中身は返さない）
  const extra: Record<string, string> | undefined =
    status === 401 ? { "www-authenticate": `Bearer error="${code === "TOKEN_MISSING" ? "invalid_request" : "invalid_token"}"` } : undefined;
  return json(status, { ok: false, code, field, message }, extra);
}

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** 下書きの検査。会社・送り手などを自分で書いたものは、黙って書き換えずに拒否する */
export function checkDraft(input: unknown):
  | { ok: true; draft: Draft }
  | { ok: false; code: UserCode; field: string; message: string } {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, code: "NOT_OBJECT", field: "", message: "下書きの形ではありません" };
  }
  for (const k of Object.keys(input)) {
    if (STAMPED_FIELDS.has(k)) return { ok: false, code: "STAMPED_FIELD", field: k, message: `この項目は土台が付けます：${k}` };
    if (!DRAFT_FIELDS.has(k)) return { ok: false, code: "UNKNOWN_FIELD", field: k, message: `規格に無い項目です：${k}` };
  }
  const o = input as Record<string, unknown>;
  if (o.v !== 1) return { ok: false, code: "BAD_VERSION", field: "v", message: "対応していない規格版です" };
  if (o.c !== undefined && !(o.c === 0 || o.c === 1 || o.c === 2 || o.c === 3)) {
    return { ok: false, code: "BAD_FIELD", field: "c", message: "機密度は 0〜3 です" };
  }
  if (!isLane(o.l)) return { ok: false, code: "BAD_LANE", field: "l", message: "規格に無いレーンです" };
  if (USER_FORBIDDEN_LANES.has(o.l)) return { ok: false, code: "LANE_NOT_ALLOWED", field: "l", message: "このレーンは利用者の口から使えません" };
  // 番号は必須。土台が作ると、やり直しのたびに別の番号になり、二重に実行されるため
  if (o.id === undefined) return { ok: false, code: "MISSING_FIELD", field: "id", message: "一意の番号（id）は送り手が付けます" };
  return { ok: true, draft: o as unknown as Draft };
}

/** 利用者の口（HTTP）。Cloudflare Workers なら fetch(request) からそのまま呼ぶ */
export function createUserGateway(opts: UserGatewayOptions): (req: Request) => Promise<Response> {
  const path = opts.path ?? USER_PATH;
  const dedupe = opts.dedupe ?? createDedupe({ windowMs: 86_400_000, capacity: 10_000 });

  return async (req) => {
    // 1. 入口・方法・種類（本文を読む前に）
    const url = new URL(req.url);
    if (url.pathname !== path) return reject("NOT_FOUND", "", "入口が違います");
    if (req.method !== "POST") return new Response(null, { status: 405, headers: { ...SECURITY_HEADERS, allow: "POST" } });
    const type = (req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") return reject("CONTENT_TYPE", "", "application/json で送ってください");

    // 2. 本人確認（本文を読む前に。ログインしていない相手には何も読ませない）
    const t = await opts.verifier.verify(bearerToken(req.headers.get("authorization")));
    if (!t.ok) return reject(t.code, "authorization", t.message);
    let who: UserIdentity | undefined;
    try {
      who = await opts.identify(t.claims);
    } catch (error) {
      opts.onError?.({ id: "", lane: "", error });
      return reject("HANDLER", "", "処理中に問題が起きました");
    }
    if (!who || !ID_RE.test(who.co) || !ID_RE.test(who.by)) return reject("USER_FORBIDDEN", "", "この利用者は使えません");

    // 3. 長さ → 形
    const raw = await readLimited(req, RAW_MAX_BYTES);
    if (raw === undefined) return reject("TOO_LARGE", "", "受け取れる大きさを超えています");
    let input: unknown;
    try {
      input = JSON.parse(raw);
    } catch {
      return reject("BAD_JSON", "", "JSON として読めません");
    }
    const d = checkDraft(input);
    if (!d.ok) return reject(d.code, d.field, d.message);
    const draft = d.draft;

    // 4. 形式の許可（暗号化や署名の前に、安く弾く）
    const allowed = opts.formats[draft.l];
    if (typeof draft.f !== "string" || !allowed || !allowed.has(draft.f)) return reject("FORMAT_NOT_ALLOWED", "f", "許可されていない形式です");

    // 5. 正式な封筒にする（会社・送り手は確かめた本人から、時刻は土台の時計から）
    const c = draft.c ?? LANES[draft.l].minClass;
    const signingKey = await opts.signingKey?.(who.co);
    const sealKey = c === 3 && draft.b !== undefined ? await opts.sealKey?.(who.co) : undefined;
    if (c >= 2 && !signingKey) return reject("SERVER_KEY", "sig", "この会社は機密以上を受け付ける設定がありません");
    if (c === 3 && draft.b !== undefined && !sealKey) return reject("SERVER_KEY", "e", "この会社は極秘の本文を受け付ける設定がありません");
    const sender = createSender({
      co: who.co,
      by: who.by,
      now: opts.now,
      ...(signingKey ? { signingKey } : {}),
      ...(sealKey ? { sealKey } : {}),
    });
    let env: Envelope;
    try {
      const { v: _v, l, f, ...rest } = draft;
      env = await sender.make(l, f, { ...rest, c });
    } catch (e) {
      if (e instanceof SendError) {
        const code = (e.code in USER_HTTP_STATUS ? e.code : "BAD_FIELD") as UserCode;
        return reject(code, e.field, e.message);
      }
      throw e;
    }
    const r = checkEnvelope(env, { formats: opts.formats });
    if (!r.ok) return reject(r.code, r.field, r.message);

    // 6. 重複（会社・送り手・番号の組。他人の番号で邪魔をさせない）
    if (!dedupe.first(who.co, `${who.by}\u0000${env.id}`, opts.now())) {
      return reject("DUPLICATE", "id", "同じ番号の下書きを受け取り済みです");
    }

    // 7. 処理
    try {
      const reply = await opts.onEnvelope(env, who);
      const body: Record<string, unknown> = { ok: true, id: env.id, at: env.at };
      if (reply !== undefined) body.b = reply;
      return json(reply === undefined ? 202 : 200, body);
    } catch (error) {
      opts.onError?.({ id: env.id, lane: env.l, error });
      return reject("HANDLER", "", "処理中に問題が起きました");
    }
  };
}

// ---- アプリ側の送り口（Web・Node.js 用。Swift・Kotlin 版も同じ動きにする） ----

export interface UserClientOptions extends Omit<RetryOptions, "deadlineAt"> {
  /** 送り先の入口（https のみ。開発時の localhost は可） */
  url: string;
  /** 今のログインのトークンを返す。refresh が true なら、取り直したものを返す */
  token: (refresh: boolean) => Promise<string>;
  /** 通信の関数（既定は標準の fetch） */
  fetch?: (req: Request) => Promise<Response>;
}

export type UserSendResult =
  | { ok: true; status: number; id: string; at?: number; b?: unknown; duplicate: boolean; attempts: number }
  | { ok: false; status: number; code?: string; attempts: number };

export interface UserClient {
  /** 下書きを送る。id を省くと新しく作る。やり直しは同じ id で行う */
  send(draft: Omit<Draft, "v" | "id"> & { id?: string }): Promise<UserSendResult>;
}

/**
 * アプリ側の送り口。署名用・暗号化用の鍵は持たない。
 * 期限切れ（TOKEN_EXPIRED）のときだけ、トークンを取り直して一度だけ送り直す。
 */
export function createUserClient(opts: UserClientOptions): UserClient {
  const u = new URL(opts.url);
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new Error("送り先は https にしてください");
  const doFetch = opts.fetch ?? ((r: Request) => fetch(r));

  return {
    async send(input) {
      const draft: Draft = { v: 1, ...input, id: input.id ?? randomId() } as Draft;
      const body = JSON.stringify(draft);
      const dl = draft.dl ?? LANES[draft.l].deadlineMs;
      const start = opts.now();
      let refreshed = false;
      let lastCode: string | undefined;
      const res = await withRetry<{ status: number; id: string; at?: number; b?: unknown; duplicate: boolean }>(
        async () => {
          for (;;) {
            const token = await opts.token(refreshed);
            const resp = await doFetch(
              new Request(u, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body }),
            );
            let data: { ok?: boolean; code?: string; id?: string; at?: number; b?: unknown } = {};
            try {
              data = (await resp.json()) as typeof data;
            } catch {
              /* 本文が JSON でなくても状態番号で判断する */
            }
            lastCode = data.code;
            if (resp.status === 401 && data.code === "TOKEN_EXPIRED" && !refreshed) {
              refreshed = true;
              continue;
            }
            if (resp.status === 409 && data.code === "DUPLICATE") return { status: 200, value: { status: 409, id: draft.id, duplicate: true } };
            if (resp.status >= 200 && resp.status <= 299) {
              const value: { status: number; id: string; at?: number; b?: unknown; duplicate: boolean } = { status: resp.status, id: draft.id, duplicate: false };
              if (typeof data.at === "number") value.at = data.at;
              if (data.b !== undefined) value.b = data.b;
              return { status: resp.status, value };
            }
            const ra = Number(resp.headers.get("retry-after") ?? "NaN");
            return Number.isFinite(ra) ? { status: resp.status, retryAfterSec: ra } : { status: resp.status };
          }
        },
        { ...opts, ...(dl > 0 ? { deadlineAt: start + dl } : {}) },
      );
      if (res.ok) return { ok: true, ...res.value, attempts: res.attempts };
      return lastCode ? { ok: false, status: res.status, code: lastCode, attempts: res.attempts } : { ok: false, status: res.status, attempts: res.attempts };
    },
  };
}
