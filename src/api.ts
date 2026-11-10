// API の再試行。規格書 第15章。
// やり直してよいのは一時的な失敗（時間切れ・混雑・相手側の故障）だけ。
// 同じ封筒（同じ番号 id）を送り直すので、受け手の重複防止で二重実行にならない。
// 待ち時間は回ごとに倍にし、ばらつきを入れる（全員が同時にやり直して相手を潰さないため）。
// 締め切りを越える待ちはしない。

export interface RetryOptions {
  /** 試す回数の上限（最初の 1 回を含む、既定 4） */
  attempts?: number;
  /** 最初の待ち時間（ミリ秒、既定 200） */
  baseMs?: number;
  /** 待ち時間の上限（ミリ秒、既定 5000） */
  maxMs?: number;
  /** この時刻を過ぎる待ちはしない（ミリ秒。封筒の at + dl） */
  deadlineAt?: number;
  /** 土台の時計 */
  now: () => number;
  /** 待つ（既定は setTimeout） */
  sleep?: (ms: number) => Promise<void>;
  /** 0 以上 1 未満の乱数（既定は Web Crypto） */
  random?: () => number;
}

/** 一度の試行の結果 */
export interface Attempt<T> {
  /** 成功ならその値 */
  value?: T;
  /** HTTP の状態番号（通信できなかったときは 0） */
  status: number;
  /** 相手が示した待ち時間（秒）。Retry-After */
  retryAfterSec?: number;
}

export type RetryResult<T> =
  | { ok: true; value: T; attempts: number }
  | { ok: false; status: number; attempts: number; reason: "NOT_RETRYABLE" | "ATTEMPTS" | "DEADLINE" };

/** やり直してよい状態か。0 は通信できなかったとき */
export function isRetryable(status: number): boolean {
  return status === 0 || status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599 && status !== 501);
}

function cryptoRandom(): number {
  const a = globalThis.crypto.getRandomValues(new Uint32Array(1));
  return a[0]! / 2 ** 32;
}

/**
 * fn を、成功するか、やり直せない失敗になるまで試す。
 * fn は成功時に status 200〜299 と value を返す。
 */
export async function withRetry<T>(fn: (attempt: number) => Promise<Attempt<T>>, opts: RetryOptions): Promise<RetryResult<T>> {
  const attempts = opts.attempts ?? 4;
  const baseMs = opts.baseMs ?? 200;
  const maxMs = opts.maxMs ?? 5000;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? cryptoRandom;
  if (!(attempts >= 1)) throw new Error("attempts は 1 以上です");

  let last = 0;
  for (let i = 1; i <= attempts; i++) {
    let r: Attempt<T>;
    try {
      r = await fn(i);
    } catch {
      r = { status: 0 };
    }
    if (r.status >= 200 && r.status <= 299) return { ok: true, value: r.value as T, attempts: i };
    last = r.status;
    if (!isRetryable(r.status)) return { ok: false, status: r.status, attempts: i, reason: "NOT_RETRYABLE" };
    if (i === attempts) break;

    // 待ち時間：倍々の上限まで、ばらつきあり。相手の指示があればそれ以上待つ
    const cap = Math.min(maxMs, baseMs * 2 ** (i - 1));
    let wait = Math.floor(cap / 2 + random() * (cap / 2));
    if (r.retryAfterSec !== undefined && r.retryAfterSec >= 0) wait = Math.max(wait, Math.min(r.retryAfterSec * 1000, maxMs));
    if (opts.deadlineAt !== undefined && opts.now() + wait >= opts.deadlineAt) {
      return { ok: false, status: last, attempts: i, reason: "DEADLINE" };
    }
    await sleep(wait);
  }
  return { ok: false, status: last, attempts, reason: "ATTEMPTS" };
}
