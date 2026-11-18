// 端末の登録のときの鍵の証明の決まり（規格書 第21章）。createDeviceEnrollment の attest にそのまま渡す。
// 登録の本文の att を platform で振り分け、Android は verifyAndroidAttestation、iPhone・iPad・Mac は verifyAppleAppAttest で確かめる。
// どの使い道に証明を必須にするか・どのアプリを許すかは、アプリの側が決めて渡す（src/ に特定のアプリを書かない）。

import { attestationChallenge, verifyAndroidAttestation, type AndroidAttestationOptions } from "./attestation.ts";
import { appAttestClientDataHash, verifyAppleAppAttest, type AppAttestOptions } from "./appattest.ts";
import type { DeviceUse } from "./device.ts";
import type { UserIdentity } from "./user.ts";

export interface AttestationPolicy {
  now: () => number;
  /** 証明を必須にする使い道（既定：approve だけ必須） */
  require?: readonly DeviceUse[];
  android?: Pick<AndroidAttestationOptions, "roots" | "revoked" | "apps" | "requireStrongBox" | "requireVerifiedBoot">;
  apple?: Pick<AppAttestOptions, "appIds" | "allowDevelopment" | "root" | "rootSpkiSha256">;
}

export type AttestDecision = { ok: true } | { ok: false; code: string; message: string };

const STR = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max;

/** createDeviceEnrollment の attest に渡す関数を作る */
export function createAttestationCheck(policy: AttestationPolicy): (p: { who: UserIdentity; pub: string; use: DeviceUse; att: unknown }) => Promise<AttestDecision> {
  const required = new Set<DeviceUse>(policy.require ?? ["approve"]);
  return async ({ who, pub, use, att }) => {
    if (att === undefined || att === null) {
      return required.has(use) ? { ok: false, code: "ATTEST_MISSING", message: "この使い道の鍵には、鍵の証明が必要です" } : { ok: true };
    }
    if (typeof att !== "object" || Array.isArray(att)) return { ok: false, code: "ATTEST_BAD", message: "鍵の証明の形が違います" };
    const a = att as Record<string, unknown>;
    if (a.platform === "android") {
      if (!policy.android) return { ok: false, code: "ATTEST_PLATFORM", message: "Android の鍵の証明は受け付けていません" };
      if (!Array.isArray(a.chain) || !a.chain.every((c) => STR(c, 8192))) return { ok: false, code: "ATTEST_BAD", message: "鍵の証明の形が違います" };
      const r = await verifyAndroidAttestation({ ...policy.android, chain: a.chain as string[], pub, use, challenge: await attestationChallenge(who.co, who.by), now: policy.now() });
      return r.ok ? { ok: true } : r;
    }
    if (a.platform === "apple") {
      if (!policy.apple) return { ok: false, code: "ATTEST_PLATFORM", message: "Apple の鍵の証明は受け付けていません" };
      if (!STR(a.keyId, 64) || !STR(a.attestation, 12288)) return { ok: false, code: "ATTEST_BAD", message: "鍵の証明の形が違います" };
      const r = await verifyAppleAppAttest({
        ...policy.apple,
        attestation: a.attestation,
        keyId: a.keyId,
        clientDataHash: await appAttestClientDataHash({ co: who.co, by: who.by, use, pub }),
        now: policy.now(),
      });
      return r.ok ? { ok: true } : r;
    }
    return { ok: false, code: "ATTEST_PLATFORM", message: "知らない種類の鍵の証明です" };
  };
}
