// 相互の確認用の受け口。TypeScript の利用者の口（src/user.ts）を手元で動かし、
// Swift の送り口が本物の受け口と話せるかを確かめる（swift/README.md の手順）。
// 鍵とトークンはその場で作る使い捨て。外へは出さない。
import { createServer } from "node:http";
import {
  type DeviceKey,
  createDeviceEnrollment,
  createDeviceVerifier,
  createTokenVerifier,
  createUserGateway,
  formatTable,
  importSigningKey,
  issuePairingCode,
  toBase64Url,
} from "../../src/index.ts";

const enc = new TextEncoder();
const b64 = (o: unknown) => toBase64Url(enc.encode(JSON.stringify(o)));
const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
const jwk = { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid: "k1" };
const now = () => Date.now();
const verifier = createTokenVerifier({ issuer: "interop", audience: "app", now, jwks: async () => ({ keys: [jwk as never] }) });
const signingKey = await importSigningKey(crypto.getRandomValues(new Uint8Array(32)));
const received: unknown[] = [];
const gateway = createUserGateway({
  verifier,
  identify: (c) => ({ co: "CO_TEST", by: c.sub }),
  formats: formatTable({ record: ["record.attendance.clockin"] }),
  now,
  signingKey: () => signingKey,
  onEnvelope: (env) => (received.push(env), { echo: env.b ?? null, by: env.by, co: env.co, ...(env.tk ? { tk: env.tk, v: env.v } : {}) }),
});

// 端末の鍵（規格書 第21章）：登録の入口と、端末の証明を求める利用者の口（/lch/v1/user-device）
const devices = new Map<string, DeviceKey[]>();
const codes = new Map<string, number>();
const store = {
  keys: (co: string, by: string) => devices.get(`${co}/${by}`) ?? [],
  take: (co: string, by: string, hash: string, at: number) => {
    const k = `${co}/${by}/${hash}`, until = codes.get(k);
    codes.delete(k);
    return until !== undefined && until > at;
  },
  add: (co: string, by: string, key: DeviceKey) => void devices.set(`${co}/${by}`, [...(devices.get(`${co}/${by}`) ?? []), key]),
};
const identify = (c: { sub: string }) => ({ co: "CO_TEST", by: c.sub });
const enroll = createDeviceEnrollment({ verifier, identify, store, now });
const deviceGateway = createUserGateway({
  verifier,
  identify,
  formats: formatTable({ record: ["record.attendance.clockin"] }),
  now,
  signingKey: () => signingKey,
  path: "/lch/v1/user-device",
  device: createDeviceVerifier({ directory: store, now }),
  onEnvelope: (env) => ({ echo: env.b ?? null, by: env.by, co: env.co, ...(env.tk ? { tk: env.tk, v: env.v } : {}) }),
});
const pairing = await issuePairingCode(Date.now(), 600_000);
codes.set(`CO_TEST/swift-user/${pairing.hash}`, pairing.expiresAt);

async function mint(sub: string) {
  const h = b64({ alg: "ES256", typ: "JWT", kid: "k1" });
  const s = Math.floor(Date.now() / 1000);
  const p = b64({ sub, iss: "interop", aud: "app", iat: s, exp: s + 600 });
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, enc.encode(`${h}.${p}`)));
  return `${h}.${p}.${toBase64Url(sig)}`;
}

const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const request = new Request(`http://localhost${req.url}`, { method: req.method, headers: req.headers as Record<string, string>, body: chunks.length ? Buffer.concat(chunks) : null });
  const handler = req.url === "/lch/v1/device" ? enroll : req.url === "/lch/v1/user-device" ? deviceGateway : gateway;
  const r = await handler(request);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
server.listen(0, "127.0.0.1", async () => {
  const port = (server.address() as { port: number }).port;
  console.log(JSON.stringify({ url: `http://localhost:${port}/lch/v1/user`, token: await mint("swift-user"), code: pairing.code }));
});
