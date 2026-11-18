// 作業 ID の記録帳（全アプリ共通）。規格書 第22章。
// 作業ひとつひとつに付ける番号を、道具・アプリのあいだで相互に分け合う。
// - 先に出した方を、もう片方が引用する。渡された ID は作り直さない
// - 知らない作業 ID の付いた操作は、ほかの道具が先に出した ID とみなして引き受ける（引用）
// - 終了は宣言だけで決まる（道具ごと）。終了を宣言した ID の操作は断り、始め直しにも使わない
// - 放置された作業を時間で終わらせ・消すことはしない。消すのは、終了を宣言してから決めた日数たった物だけ
// 置き場所は外から渡す（Durable Objects・KV・メモリなど、get と put があればよい）。

import { TASK_ID_RE } from "./lanes.ts";

export interface TaskStore {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

export type TaskState = "active" | "ended";

export interface TaskRecord {
  id: string;
  title: string;
  state: TaskState;
  /** 出したのがこの道具（self）か、ほかの道具の ID を引用したか（quoted） */
  issued_by: "self" | "quoted";
  started_at: number;
  last_at: number;
  ended_at?: number;
}

export type TaskCode = "BAD_TASK_ID" | "TASK_ENDED" | "TASK_FULL" | "TASK_UNKNOWN";

export type TaskFail = { ok: false; code: TaskCode; field: string; message: string };
export type TaskStart = { ok: true; task: TaskRecord; existing: boolean } | TaskFail;
export type TaskTouch = { ok: true; task: TaskRecord; adopted: boolean } | TaskFail;
export type TaskEnd = { ok: true; task: TaskRecord; already: boolean } | TaskFail;

export interface TaskBookOptions {
  store: TaskStore;
  /** 土台の時計（ミリ秒） */
  now: () => number;
  /** 置き場所の名前（既定 tasks） */
  key?: string;
  /** 終了を宣言してから消すまで（既定 7 日） */
  keepEndedMs?: number;
  /** 記録の数の上限（既定 300）。超えたら終わった物の古い順にだけ消す */
  max?: number;
  /** 引用で作った記録の題名（既定「ほかの道具から引用」） */
  quotedTitle?: string;
}

export interface TaskBook {
  /** 作業を始める。id を渡せばその ID のまま（同じ ID が進行中なら結び付ける）、無ければここで出す */
  start(id?: string, title?: string): Promise<TaskStart>;
  /** 作業 ID の付いた操作の前に呼ぶ。知らない ID は引用として引き受け、終わった ID は断る */
  touch(id: string): Promise<TaskTouch>;
  /** 終了を宣言する（二度目は already） */
  end(id: string): Promise<TaskEnd>;
  /** 進行中（新しく動いた順）と、終わった物（新しく終わった順、最大 50） */
  list(): Promise<{ active: TaskRecord[]; ended: TaskRecord[] }>;
}

export const TASK_DEFAULTS = { keepEndedMs: 7 * 86_400_000, max: 300, titleMax: 120, quotedTitle: "ほかの道具から引用" } as const;

const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** 新しい作業 ID（暗号の乱数。偏りが出ないよう、62 の倍数に収まらない値は捨てて引き直す） */
export function newTaskId(): string {
  let out = "w-";
  const b = new Uint8Array(16);
  while (out.length < 10) {
    globalThis.crypto.getRandomValues(b);
    for (const x of b) if (x < 248 && out.length < 10) out += ALPHABET[x % 62];
  }
  return out;
}

export function isTaskId(x: unknown): x is string {
  return typeof x === "string" && TASK_ID_RE.test(x);
}

const badId = (): TaskFail => ({ ok: false, code: "BAD_TASK_ID", field: "tk", message: "作業 ID は w- と英数字 8 文字です（例 w-a1B2c3D4）" });
const ended = (id: string): TaskFail => ({
  ok: false, code: "TASK_ENDED", field: "tk",
  message: `作業 ${id} は終了が宣言されています。終わった作業 ID の操作は受け付けず、始め直しにも使いません。新しい作業を始めてください`,
});
const full = (max: number): TaskFail => ({
  ok: false, code: "TASK_FULL", field: "tk",
  message: `進行中の作業が上限（${max}）に達しています。終わった作業の終了を宣言してから始めてください（自動では終わりません）`,
});

export function createTaskBook(opts: TaskBookOptions): TaskBook {
  const key = opts.key ?? "tasks";
  const keep = opts.keepEndedMs ?? TASK_DEFAULTS.keepEndedMs;
  const max = opts.max ?? TASK_DEFAULTS.max;
  const quotedTitle = opts.quotedTitle ?? TASK_DEFAULTS.quotedTitle;
  let chain: Promise<unknown> = Promise.resolve();

  // 読み書きを 1 本ずつ順に行う（同時の操作で二重に作らないように）
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = chain.then(fn);
    chain = run.catch(() => undefined);
    return run;
  };
  const load = async (): Promise<TaskRecord[]> => {
    const t = opts.now();
    // 消すのは、終了を宣言してから決めた日数たった物だけ。進行中の物は、どれだけ放置されても消さない
    return ((await opts.store.get<TaskRecord[]>(key)) ?? []).filter((r) => !(r.state === "ended" && t - (r.ended_at ?? 0) > keep));
  };
  const save = async (list: TaskRecord[]): Promise<void> => {
    if (list.length > max) {
      const drop = new Set(
        list.filter((r) => r.state === "ended").sort((a, b) => (a.ended_at ?? 0) - (b.ended_at ?? 0)).slice(0, list.length - max).map((r) => r.id),
      );
      list = list.filter((r) => !drop.has(r.id));
    }
    await opts.store.put(key, list);
  };
  const hasRoom = (list: TaskRecord[]) => list.length < max || list.some((r) => r.state === "ended");
  const fresh = (id: string, title: string, issued_by: TaskRecord["issued_by"]): TaskRecord => {
    const t = opts.now();
    return { id, title, state: "active", issued_by, started_at: t, last_at: t };
  };

  return {
    start(id, title) {
      return serial(async () => {
        if (id !== undefined && !isTaskId(id)) return badId();
        const list = await load();
        const name = (title ?? "").trim().slice(0, TASK_DEFAULTS.titleMax);
        if (id !== undefined) {
          const ex = list.find((r) => r.id === id);
          if (ex) {
            if (ex.state === "ended") return ended(id);
            ex.last_at = opts.now();
            if (name && ex.title === quotedTitle) ex.title = name;   // 引用で作った記録に、あとから題名が付いたら入れる
            await save(list);
            return { ok: true, task: ex, existing: true };
          }
        }
        if (!hasRoom(list)) return full(max);
        let newId = id;
        if (newId === undefined) {
          do newId = newTaskId();
          while (list.some((r) => r.id === newId));
        }
        const rec = fresh(newId, name || (id !== undefined ? quotedTitle : ""), id !== undefined ? "quoted" : "self");
        list.push(rec);
        await save(list);
        return { ok: true, task: rec, existing: false };
      });
    },
    touch(id) {
      return serial(async () => {
        if (!isTaskId(id)) return badId();
        const list = await load();
        const ex = list.find((r) => r.id === id);
        if (ex) {
          if (ex.state === "ended") return ended(id);
          ex.last_at = opts.now();
          await save(list);
          return { ok: true, task: ex, adopted: false };
        }
        if (!hasRoom(list)) return full(max);
        const rec = fresh(id, quotedTitle, "quoted");
        list.push(rec);
        await save(list);
        return { ok: true, task: rec, adopted: true };
      });
    },
    end(id) {
      return serial(async () => {
        if (!isTaskId(id)) return badId();
        const list = await load();
        const ex = list.find((r) => r.id === id);
        if (!ex) return { ok: false, code: "TASK_UNKNOWN", field: "tk", message: `作業 ${id} は、この道具では使われていません（または、終わってから日数がたって消えました）` };
        if (ex.state === "ended") return { ok: true, task: ex, already: true };
        ex.state = "ended";
        ex.ended_at = opts.now();
        ex.last_at = ex.ended_at;
        await save(list);
        return { ok: true, task: ex, already: false };
      });
    },
    list() {
      return serial(async () => {
        const list = await load();
        return {
          active: list.filter((r) => r.state === "active").sort((a, b) => b.last_at - a.last_at),
          ended: list.filter((r) => r.state === "ended").sort((a, b) => (b.ended_at ?? 0) - (a.ended_at ?? 0)).slice(0, 50),
        };
      });
    },
  };
}
