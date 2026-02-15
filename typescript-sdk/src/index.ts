// typescript-sdk/src/index.ts
// CommandLayer TypeScript SDK (Commons v1.0.0)
//
// - Calls runtime verbs
// - Returns typed receipts
// - Implements REAL receipt verification:
//   - canonicalization: cl-stable-json-v1 (stable JSON stringify w/ sorted keys)
//   - hash recomputation: SHA-256 over canonical unsigned receipt
//   - signature verification: Ed25519 over hash (Node crypto)
//   - ENS resolution (optional): fetch signer pubkey PEM from ENS TXT record via ethers v6
//
// Notes:
// - Node 18+ recommended (global fetch). You can inject fetchImpl.
// - Ed25519 verification uses Node's crypto. Browser builds may need a different impl.

import crypto from "crypto";
import { ethers } from "ethers";

export const version = "1.0.0";

/** Receipt proof as produced by your runtime */
export type Proof = {
  alg?: string; // "ed25519-sha256"
  canonical?: string; // "cl-stable-json-v1"
  signer_id?: string; // e.g. "runtime.commandlayer.eth"
  hash_sha256?: string; // hex
  signature_b64?: string; // base64
  [k: string]: any;
};

export type ReceiptMetadata = {
  receipt_id?: string;
  proof?: Proof;
  actor?: { id: string; role?: string } | any;
  [k: string]: any;
};

export type ReceiptTrace = {
  trace_id?: string;
  parent_trace_id?: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  provider?: string;
  [k: string]: any;
};

export type Receipt<T = any> = {
  status: "success" | "error" | string;
  x402?: any;
  trace?: ReceiptTrace;
  result?: T;
  error?: any;
  metadata?: ReceiptMetadata;
  delegation_result?: any;
  [k: string]: any;
};

export type VerifyChecks = {
  schema_valid?: boolean; // SDK does not AJV-compile schemas by default; keep placeholder
  hash_matches: boolean;
  signature_valid: boolean;
};

export type VerifyValues = {
  verb: string | null;
  signer_id: string | null;
  alg: string | null;
  canonical: string | null;
  claimed_hash: string | null;
  recomputed_hash: string | null;
  pubkey_source: "explicit" | "ens" | null;
};

export type VerifyResult = {
  ok: boolean;
  checks: VerifyChecks;
  values: VerifyValues;
  errors?: {
    signature_error?: string | null;
    schema_errors?: any[] | null;
  };
};

export class CommandLayerError extends Error {
  statusCode?: number;
  details?: any;

  constructor(message: string, statusCode?: number, details?: any) {
    super(message);
    this.name = "CommandLayerError";
    this.statusCode = statusCode;
    this.details = details;
  }
}

export type EnsVerifyOptions = {
  /** ENS name to resolve TXT record from (e.g. "runtime.commandlayer.eth") */
  name: string;
  /** Ethereum RPC URL for ENS resolution */
  rpcUrl: string;
  /** TXT key name containing PEM public key (default: "cl.receipt.pubkey_pem") */
  txtKey?: string;
};

export type VerifyOptions = {
  /** Provide explicit public key PEM for offline verification (fastest). */
  publicKeyPem?: string;
  /** Resolve public key PEM via ENS TXT record. Requires rpcUrl. */
  ens?: EnsVerifyOptions;
  /** If true, skip signature check (not recommended). */
  skipSignature?: boolean;
};

export type ClientOptions = {
  runtime?: string; // default: https://runtime.commandlayer.org
  actor?: string; // default: "sdk-user"
  verifyReceipts?: boolean; // default true: verify receipts after each call (hash+sig)
  /** Verify via explicit pubkey PEM (offline). If set, used for auto-verify. */
  publicKeyPem?: string;
  /** Verify via ENS (if set, used for auto-verify). */
  ens?: EnsVerifyOptions;
  timeout?: number; // ms, default 30000
  fetchImpl?: typeof fetch;
};

const VERBS = [
  "summarize",
  "analyze",
  "classify",
  "clean",
  "convert",
  "describe",
  "explain",
  "format",
  "parse",
  "fetch",
] as const;

type Verb = (typeof VERBS)[number];

function nowIso() {
  return new Date().toISOString();
}

// ---------- Canonicalization: cl-stable-json-v1 ----------
// Deterministic JSON stringify:
// - sorts object keys
// - preserves array order
// - replaces circular refs with "[Circular]" (should never occur in receipts)
function stableStringify(value: any): string {
  const seen = new WeakSet<object>();

  const helper = (v: any): any => {
    if (v === null || typeof v !== "object") return v;

    if (seen.has(v)) return "[Circular]";
    seen.add(v);

    if (Array.isArray(v)) return v.map(helper);

    const out: Record<string, any> = {};
    for (const k of Object.keys(v).sort()) out[k] = helper(v[k]);
    return out;
  };

  return JSON.stringify(helper(value));
}

function sha256Hex(utf8: string): string {
  return crypto.createHash("sha256").update(utf8, "utf8").digest("hex");
}

function normalizePem(text: string | undefined | null): string | null {
  if (!text) return null;
  const pem = String(text).replace(/\\n/g, "\n").trim();
  if (!pem.includes("BEGIN") || !pem.includes("PUBLIC KEY")) return null;
  return pem;
}

function verifyEd25519HashHexWithPem(hashHex: string, signatureB64: string, pubPem: string): boolean {
  // In your runtime: signature = sign(null, hashHexUtf8Bytes)
  // So we verify the signature over the UTF-8 bytes of the hex string.
  const key = crypto.createPublicKey(pubPem);
  return crypto.verify(null, Buffer.from(hashHex, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

// Build an "unsigned" receipt for canonical hashing:
// - blank out proof.hash_sha256 + proof.signature_b64
// - blank out metadata.receipt_id
function unsignedForHash(receipt: Receipt): any {
  const copy: any = structuredClone(receipt);

  if (copy?.metadata?.proof) {
    copy.metadata.proof.hash_sha256 = "";
    copy.metadata.proof.signature_b64 = "";
  }

  if (copy?.metadata) {
    copy.metadata.receipt_id = "";
  }

  return copy;
}

// ---------- ENS resolution (ethers v6) ----------
async function resolveEnsText({
  name,
  rpcUrl,
  txtKey,
  timeoutMs,
}: {
  name: string;
  rpcUrl: string;
  txtKey: string;
  timeoutMs: number;
}): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  // simple timeout wrapper
  const withTimeout = async <T>(p: Promise<T>, ms: number, label: string): Promise<T> => {
    if (!ms || ms <= 0) return await p;
    return await Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error(label)), ms))]);
  };

  const resolver = await withTimeout(provider.getResolver(name), Math.min(8000, timeoutMs), "ens_resolver_timeout");
  if (!resolver) throw new Error(`No resolver for ENS name: ${name}`);

  const txt = await withTimeout(resolver.getText(txtKey), Math.min(8000, timeoutMs), "ens_text_timeout");
  if (!txt) throw new Error(`ENS TXT missing: ${name} / ${txtKey}`);
  return txt;
}

// ---------- Public verify API ----------
export async function verifyReceipt(receipt: Receipt, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const proof = receipt?.metadata?.proof;

  const verb = (receipt as any)?.x402?.verb ? String((receipt as any).x402.verb) : null;
  const signer_id = proof?.signer_id ? String(proof.signer_id) : null;

  const baseValues: VerifyValues = {
    verb,
    signer_id,
    alg: proof?.alg ? String(proof.alg) : null,
    canonical: proof?.canonical ? String(proof.canonical) : null,
    claimed_hash: proof?.hash_sha256 ? String(proof.hash_sha256) : null,
    recomputed_hash: null,
    pubkey_source: null,
  };

  const fail = (message: string, patch?: Partial<VerifyResult>): VerifyResult => ({
    ok: false,
    checks: { hash_matches: false, signature_valid: false, schema_valid: undefined },
    values: baseValues,
    errors: { signature_error: message, schema_errors: null },
    ...(patch || {}),
  });

  if (!proof?.hash_sha256 || !proof?.signature_b64) {
    return fail("missing metadata.proof.hash_sha256 or metadata.proof.signature_b64");
  }

  // canonicalize + hash
  let recomputed: string;
  try {
    const unsigned = unsignedForHash(receipt);
    const canonical = stableStringify(unsigned);
    recomputed = sha256Hex(canonical);
  } catch (e: any) {
    return fail(e?.message || "failed to canonicalize/hash receipt");
  }

  const hashMatches = recomputed === String(proof.hash_sha256);

  // fetch pubkey
  let pubPem: string | null = null;
  let pubSrc: "explicit" | "ens" | null = null;

  if (opts.publicKeyPem) {
    pubPem = normalizePem(opts.publicKeyPem);
    if (!pubPem) return fail("invalid publicKeyPem (expected PEM public key)");
    pubSrc = "explicit";
  } else if (opts.ens) {
    try {
      const txtKey = opts.ens.txtKey || "cl.receipt.pubkey_pem";
      const txt = await resolveEnsText({
        name: opts.ens.name,
        rpcUrl: opts.ens.rpcUrl,
        txtKey,
        timeoutMs: 15000,
      });
      pubPem = normalizePem(txt);
      if (!pubPem) return fail(`ENS TXT ${txtKey} did not contain a valid PEM public key`);
      pubSrc = "ens";
    } catch (e: any) {
      return fail(e?.message || "ENS resolution failed");
    }
  }

  // signature verify
  let sigOk = false;
  let sigErr: string | null = null;

  if (opts.skipSignature) {
    sigOk = true;
  } else if (!pubPem) {
    sigOk = false;
    sigErr = "no public key available (provide publicKeyPem or ens:{name,rpcUrl})";
  } else {
    try {
      sigOk = verifyEd25519HashHexWithPem(String(proof.hash_sha256), String(proof.signature_b64), pubPem);
      if (!sigOk) sigErr = "signature verification failed";
    } catch (e: any) {
      sigOk = false;
      sigErr = e?.message || "signature verification error";
    }
  }

  const out: VerifyResult = {
    ok: hashMatches && sigOk,
    checks: { hash_matches: hashMatches, signature_valid: sigOk, schema_valid: undefined },
    values: {
      ...baseValues,
      recomputed_hash: recomputed,
      pubkey_source: pubSrc,
    },
    errors: { signature_error: sigErr, schema_errors: null },
  };

  return out;
}

// ---------- Client ----------
export class CommandLayerClient {
  runtime: string;
  actor: string;
  verifyReceipts: boolean;
  timeout: number;
  fetchImpl: typeof fetch;

  // verification defaults (optional)
  private publicKeyPem?: string;
  private ens?: EnsVerifyOptions;

  constructor(opts: ClientOptions = {}) {
    this.runtime = (opts.runtime || "https://runtime.commandlayer.org").replace(/\/+$/, "");
    this.actor = opts.actor || "sdk-user";
    this.verifyReceipts = opts.verifyReceipts !== false;
    this.timeout = opts.timeout ?? 30_000;

    const f = opts.fetchImpl || (globalThis as any).fetch;
    if (!f) {
      throw new CommandLayerError("No fetch implementation found. Use Node 18+ or pass fetchImpl.");
    }
    this.fetchImpl = f;

    this.publicKeyPem = opts.publicKeyPem;
    this.ens = opts.ens;
  }

  // ----- Verb methods (aligned to your runtime server.mjs) -----

  async summarize(opts: { content: string; style?: string; format?: string; maxTokens?: number }): Promise<Receipt> {
    return this.call("summarize", {
      input: {
        content: opts.content,
        summary_style: opts.style,
        format_hint: opts.format,
      },
      maxTokens: opts.maxTokens,
    });
  }

  async analyze(opts: { content: string; maxTokens?: number }): Promise<Receipt> {
    // Your runtime expects body.input to be a STRING, not an object.
    return this.call("analyze", {
      input: opts.content,
      maxTokens: opts.maxTokens,
    });
  }

  async classify(opts: { content: string; maxTokens?: number }): Promise<Receipt> {
    // Your runtime requires actor (we send it at top-level), and expects input.content.
    return this.call("classify", {
      input: { content: opts.content },
      maxTokens: opts.maxTokens,
    });
  }

  async clean(opts: { content: string; operations?: string[]; maxTokens?: number }): Promise<Receipt> {
    return this.call("clean", {
      input: { content: opts.content, operations: opts.operations },
      maxTokens: opts.maxTokens,
    });
  }

  async convert(opts: { content: string; from: string; to: string; maxTokens?: number }): Promise<Receipt> {
    return this.call("convert", {
      input: { content: opts.content, source_format: opts.from, target_format: opts.to },
      maxTokens: opts.maxTokens,
    });
  }

  async describe(opts: {
    subject: string;
    context?: string;
    detail_level?: "brief" | "short" | "medium" | "detailed" | string;
    audience?: string;
    maxTokens?: number;
  }): Promise<Receipt> {
    return this.call("describe", {
      input: {
        subject: opts.subject,
        context: opts.context,
        detail_level: opts.detail_level || "medium",
        audience: opts.audience || "general",
      },
      maxTokens: opts.maxTokens,
    });
  }

  async explain(opts: {
    subject: string;
    context?: string;
    style?: string;
    detail_level?: "brief" | "short" | "medium" | "detailed" | string;
    audience?: string;
    maxTokens?: number;
  }): Promise<Receipt> {
    return this.call("explain", {
      input: {
        subject: opts.subject,
        context: opts.context,
        style: opts.style || "step-by-step",
        audience: opts.audience || "general",
        detail_level: opts.detail_level || "medium",
      },
      maxTokens: opts.maxTokens,
    });
  }

  async format(opts: { content: string; target_style?: string; maxTokens?: number }): Promise<Receipt> {
    // Your runtime uses input.target_style (not target_format).
    return this.call("format", {
      input: { content: opts.content, target_style: opts.target_style || "text" },
      maxTokens: opts.maxTokens,
    });
  }

  async parse(opts: {
    content: string;
    content_type?: "json" | "yaml" | "text" | string;
    mode?: "best_effort" | "strict" | string;
    target_schema?: string | null;
    maxTokens?: number;
  }): Promise<Receipt> {
    return this.call("parse", {
      input: {
        content: opts.content,
        content_type: opts.content_type,
        mode: opts.mode,
        target_schema: opts.target_schema ?? undefined,
      },
      maxTokens: opts.maxTokens,
    });
  }

  async fetch(opts: { source: string; query?: string; include_metadata?: boolean; mode?: string; maxTokens?: number }): Promise<Receipt> {
    // Your runtime reads body.source OR body.input.source OR body.input.url
    // We'll send input.source for clarity.
    return this.call("fetch", {
      input: {
        source: opts.source,
        query: opts.query,
        include_metadata: opts.include_metadata,
        mode: opts.mode || "text",
      },
      maxTokens: opts.maxTokens,
    });
  }

  // ----- Core call -----

  async call(verb: Verb, opts: { input: any; maxTokens?: number }): Promise<Receipt> {
    const url = `${this.runtime}/${verb}/v1.0.0`;

    // Runtime uses:
    // - req.body.actor for classify (and also supports x402.tenant)
    // - req.body.limits.timeout_ms or limits.max_latency_ms (optional)
    // - req.body.limits.max_output_tokens (optional)
    const body: any = {
      x402: {
        verb,
        version: "1.0.0",
        entry: `x402://${verb}agent.eth/${verb}/v1.0.0`,
      },
      actor: this.actor,
      limits: {
        max_output_tokens: opts.maxTokens ?? 1000,
        timeout_ms: this.timeout,
      },
      input: opts.input,
      trace: {
        // optional upstream trace id - helps multi-step flows
        trace_id: `sdk_${crypto.randomBytes(6).toString("hex")}`,
        started_at: nowIso(),
      },
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `commandlayer-js/${version}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const data = (await response.json().catch(() => ({}))) as Receipt;

      if (!response.ok) {
        // your runtime returns a RECEIPT even on error (status: "error"), but still 500
        throw new CommandLayerError(
          (data as any)?.error?.message || (data as any)?.message || `HTTP ${response.status}`,
          response.status,
          data
        );
      }

      // Basic shape checks
      if (!data?.metadata?.proof?.hash_sha256 || !data?.metadata?.proof?.signature_b64) {
        throw new CommandLayerError("Invalid receipt: missing metadata.proof.hash_sha256 or signature_b64", 500, data);
      }
      if (!data?.metadata?.receipt_id) {
        // your runtime sets receipt_id = hash
        throw new CommandLayerError("Invalid receipt: missing metadata.receipt_id", 500, data);
      }

      // REAL verification (hash + signature), optionally ENS-based
      if (this.verifyReceipts) {
        const verifyOut = await verifyReceipt(data, {
          publicKeyPem: this.publicKeyPem,
          ens: this.ens,
        });

        if (!verifyOut.ok) {
          throw new CommandLayerError("Receipt verification failed", 400, {
            verify: verifyOut,
            receipt_id: data?.metadata?.receipt_id,
          });
        }
      }

      return data;
    } catch (err: any) {
      if (err?.name === "AbortError") {
        throw new CommandLayerError("Request timed out", 408);
      }
      if (err instanceof CommandLayerError) throw err;
      throw new CommandLayerError(err?.message || String(err));
    } finally {
      clearTimeout(timeoutId);
    }
  }

  close() {
    // No-op for fetch-based client
  }
}

export function createClient(opts: ClientOptions = {}) {
  return new CommandLayerClient(opts);
}
