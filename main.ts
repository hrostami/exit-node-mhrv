// mhrv-rs exit node — deploy as an HTTP endpoint on any serverless
// TypeScript host with a public IP that isn't a Google datacenter
// (Deno Deploy, fly.io, your own VPS, etc.). Uses only web-standard
// `Request` / `Response` / `fetch` so it's portable across runtimes.
//
// Purpose: chain client → Apps Script → this exit node → destination.
// Apps Script's UrlFetchApp can't reach Cloudflare-protected sites that
// flag Google datacenter IPs as bots (chatgpt.com, claude.ai, grok.com,
// many other CF-fronted SaaS). This exit node sits between Apps Script
// and the destination; the destination sees the exit node's outbound IP
// (generally not flagged as Google datacenter) and accepts the request.
//
// Setup:
//   1. Pick a host that runs web-standard fetch handlers (e.g. Deno
//      Deploy, fly.io with a thin server wrapper, or any cheap VPS
//      running Deno / Node + this script as a handler).
//   2. Paste the contents of this file as the request handler.
//   3. Set PSK below to a strong secret (`openssl rand -hex 32` from
//      a terminal — DO NOT leave the placeholder in production).
//   4. Deploy and copy the public URL of the deployed handler.
//   5. In mhrv-rs config.json, add:
//        "exit_node": {
//          "enabled": true,
//          "relay_url": "https://your-deployed-exit-node.example.com",
//          "psk": "<the same PSK you set above>",
//          "mode": "selective",
//          "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com"]
//        }
//
// Threat model: PSK is the only thing keeping this from being an open
// proxy on the public internet. Treat it like a password: do not commit
// to source control, do not share publicly, rotate if leaked. The exit
// node refuses all requests that don't carry the matching PSK.
//
// Failure mode: if the exit node is unreachable, mhrv-rs falls back to
// the regular Apps Script relay automatically — the only consequence
// of an offline exit node is that ChatGPT/Claude/Grok stop working;
// other sites are unaffected.
declare const Deno: any;
const PSK = Deno.env.get("EXIT_NODE_PSK") || "CHANGE_ME_TO_A_STRONG_SECRE";
console.log(`PSK Loaded: ${PSK.substring(0,4)}...`);

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  // Deno passes compressed response bytes through. Ask origins for plain bodies.
  "accept-encoding",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
]);

function decodeBase64ToBytes(input: string): Uint8Array {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function sanitizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

Deno.serve(async (req: Request): Promise<Response> => {
  try {
    if (req.method !== "POST") {
      return Response.json({ e: "method_not_allowed" }, { status: 405 });
    }

    const body = await req.json();
    if (!body || typeof body !== "object") {
      return Response.json({ e: "bad_json" }, { status: 400 });
    }

    if (!PSK) {
      return Response.json({ e: "server_psk_missing" }, { status: 500 });
    }

    const k = String((body as any).k ?? "");
    const u = String((body as any).u ?? "");
    const m = String((body as any).m ?? "GET").toUpperCase();
    const h = sanitizeHeaders((body as any).h);
    const b64 = (body as any).b;

    if (k !== PSK) return Response.json({ e: "unauthorized" }, { status: 401 });
    if (!/^https?:\/\//i.test(u)) return Response.json({ e: "bad_url" }, { status: 400 });

    let payload: Uint8Array | undefined;
    if (typeof b64 === "string" && b64.length > 0) payload = decodeBase64ToBytes(b64);
    const requestBody = payload ? Uint8Array.from(payload) : undefined;

    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: requestBody as unknown as BodyInit,
      redirect: "manual",
    });

    const data = new Uint8Array(await resp.arrayBuffer());
    const respHeaders: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

    return Response.json({
      s: resp.status,
      h: respHeaders,
      b: encodeBytesToBase64(data),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ e: message }, { status: 500 });
  }
});
