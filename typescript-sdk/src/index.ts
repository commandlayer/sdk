// typescript-sdk/src/index.ts
import crypto from "crypto";
import { ethers } from "ethers";

/**
 * CommandLayer TypeScript SDK — Commons v1.0.0
 *
 * What this implements (for real):
 * - canonicalization: cl-stable-json-v1
 * - hash recomputation: sha256 over unsigned receipt canonical JSON
 * - signature verification: Ed25519 over the hash string (UTF-8)
 * - ENS pubkey resolution: TXT record lookup via ethers v6
 *
 * Notes:
 * - This SDK targets Node (uses node:crypto). If you want browser support,
 *   we can switch to @noble/ed25519 + @noble/hashes and conditional exports.
 */

export const version = "1.0.0";

export type Proof = {
  alg?: string; // "ed25519-sha256"
  canonical?: string; // "cl-stable-json-v1"
  signer_id?: string; // e.g. runtime.commandlayer.eth
  hash_sha256?: string; // hex
  signature_b64?: string; // base64
  // allow forward-compat fields
  [k: string]: any;
};

export type ReceiptMetadata = {
  receipt_id?: string; // usually equals hash_sha256
  proof?: Proof;
  actor?: { id: string; role?: string; [k: string]: any };
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

export type X402 = {
  verb?: string;
  version?: string;
  entry?: string;
  tenant?: string;
  extras?: Record<string, any>;
  [k: string]: any;
};

export type Receipt<T = any> = {
  status: "success" | "error" | string;
  x402?: X402;
  trace?: ReceiptTrace;
  result?: T;
  error?: any;
  metadata?: ReceiptMetadata;
  [k: string]: any;
};

export type VerifyChecks = {
  schema_valid?: boolean; // (not implemented here)
  hash_matches: boolean;
  signature_valid: boolean;
};

export type VerifyResult = {
  ok: boolean;
  checks: VerifyChecks;
  values: {
    verb: string | null;
    signer_id: string | null;
    alg: string | null;
    canonical: string | null;
    claimed_hash: string | null;
    recomputed_hash: string | null;
    pubkey_source: "explicit" | "ens" | null;
  };
  errors: {
    signature_error?: string | null;
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
  /** ENS name that holds TXT records (commonly runtime.commandlayer.eth) */
  name: string;
  /** Ethereum RPC URL (required for ENS resolution) */
  rpcUrl: string;
  /** TXT record key that contains a PEM public key (default: cl.receipt.pubkey_pem) */
  pubkeyTextKey?: string;
  /** If true, always refetch from RPC (no caching). Default false. */
  refresh?: boolean;
};

export type VerifyOptions = {
  /** Provide an explicit PEM public key (fastest; no RPC). */
  publicKeyPem?: string;
  /** Resolve PEM public key from ENS via TXT record. */
  ens?: EnsVerifyOptions;
};

export type ClientOptions = {
  runtime?: string; // default https://runtime.commandlayer.org
  actor?: string; // required-ish for classify; good everywhere
  timeoutMs?: number;
  fetchImpl?: typeof fetch;

  /**
   * If true, every client call verifies receipt integrity.
   * - Requires either `publicKeyPem` OR `ens` options.
   * - If neither is provided, we still recompute hash (integrity) but cannot verify signature.
   */
  verifyReceipts?: boolean;

  /** Optional default verification config */
  verify?: VerifyOptions;
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

function normalizeBase(url: string) {
  return String(url || "").replace(/\/+$/, "");
}

// Deterministic canonicalization: sort object keys recursively
function stableObject(value: any, seen = new WeakSet<object>()): any {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (Array.isArray(value)) return value.map((v) => stableObject(v, seen));

  const out: Record<string, any> = {};
  for (const k of Object.keys(value).sort()) out[k] = stableObject(value[k], seen);
  return out;
}

function stableStringify(value: any): string {
  return JSON.stringify(stableObject(value));
}

function sha256Hex(inputUtf8: string): string {
  return crypto.createHash("sha256").update(inputUtf8, "utf8").digest("hex");
}

function normalizePem(text: string | null | undefined): string | null {
  if (!text) return null;
  // ENS UI often stores escaped newlines \n in TXT
  const pem = String(text).replace(/\\n/g, "\n").trim();
  if (!pem.includes("BEGIN") || !pem.includes("PUBLIC KEY")) return null;
  return pem;
}

function verifyEd25519OverHashString(hashHex: string, signatureB64: string, publicKeyPem: string): boolean {
  // IMPORTANT: your runtime signs Buffer.from(hash, 'utf8') where hash is the hex string.
  const key = crypto.createPublicKey(publicKeyPem);
  return crypto.verify(
    null,
    Buffer.from(hashHex, "utf8"),
    key,
    Buffer.from(signatureB64, "base64")
  );
}

async function resolveEnsPubkeyPem(
  ens: EnsVerifyOptions
): Promise<{ pem: string | null; source: "ens" | null; error?: string }> {
  try {
    const provider = new ethers.JsonRpcProvider(ens.rpcUrl);
    const resolver = await provider.getResolver(ens.name);
    if (!resolver) return { pem: null, source: null, error: "No resolver for ENS name" };

    const key = ens.pubkeyTextKey || "cl.receipt.pubkey_pem";
    const txt = await resolver.getText(key);
    const pem = normalizePem(txt);
    if (!pem) return { pem: null, source: null, error: `ENS TXT ${key} missing/invalid PEM` };

    return { pem, source: "ens" };
  } catch (e: any) {
    return { pem: null, source: null, error: e?.message || "ENS resolution failed" };
  }
}

/**
 * Verify a receipt:
 * - recompute canonical hash over "unsigned receipt"
 * - compare to receipt.metadata.proof.hash_sha256
 * - verify ed25519 signature over the HASH STRING (utf8)
 * - pubkey from explicit PEM or ENS TXT
 */
export async function verifyReceipt(receipt: Receipt, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const proof = receipt?.metadata?.proof || {};
  const claimedHash = proof?.hash_sha256 ? String(proof.hash_sha256) : null;
  const sigB64 = proof?.signature_b64 ? String(proof.signature_b64) : null;

  const unsigned = structuredClone(receipt) as any;

  // blank out proof + receipt_id exactly like your runtime does
  if (unsigned?.metadata?.proof) {
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
  }
  if (unsigned?.metadata) {
    unsigned.metadata.receipt_id = "";
  }

  const canonical = stableStringify(unsigned);
  const recomputedHash = sha256Hex(canonical);

  const hashMatches = claimedHash ? recomputedHash === claimedHash : false;

  // pubkey: explicit > ENS
  let pubPem: string | null = normalizePem(opts.publicKeyPem || null);
  let pubSrc: "explicit" | "ens" | null = pubPem ? "explicit" : null;
  let sigErr: string | null = null;

  if (!pubPem && opts.ens) {
    const ensOut = await resolveEnsPubkeyPem(opts.ens);
    pubPem = ensOut.pem;
    pubSrc = ensOut.pem ? "ens" : null;
    if (!ensOut.pem && ensOut.error) sigErr = ensOut.error;
  }

  let sigOk = false;
  if (pubPem && claimedHash && sigB64) {
    try {
      sigOk = verifyEd25519OverHashString(claimedHash, sigB64, pubPem);
    } catch (e: any) {
      sigOk = false;
      sigErr = e?.message || "signature verify failed";
    }
  } else {
    sigOk = false;
    if (!sigErr) {
      if (!claimedHash || !sigB64) sigErr = "missing proof.hash_sha256 or proof.signature_b64";
      else sigErr = "no public key available (provide publicKeyPem or ens options)";
    }
  }

  const ok = hashMatches && sigOk;

  return {
    ok,
    checks: { hash_matches: hashMatches, signature_valid: sigOk },
    values: {
      verb: receipt?.x402?.verb ?? null,
      signer_id: proof?.signer_id ?? null,
      alg: proof?.alg ?? null,
      canonical: proof?.canonical ?? null,
      claimed_hash: claimedHash,
      recomputed_hash: recomputedHash,
      pubkey_source: pubSrc,
    },
    errors: { signature_error: sigErr },
  };
}

export class CommandLayerClient {
  runtime: string;
  actor: string;
  timeoutMs: number;
  fetchImpl: typeof fetch;
  verifyReceipts: boolean;
  verifyDefaults?: VerifyOptions;

  constructor(opts: ClientOptions = {}) {
    this.runtime = normalizeBase(opts.runtime || "https://runtime.commandlayer.org");
    this.actor = opts.actor || "sdk-user";
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetchImpl || fetch;
    this.verifyReceipts = opts.verifyReceipts !== false;
    this.verifyDefaults = opts.verify;
  }

  // ---- verb helpers (match your runtime handlers)
  async summarize(opts: { content: string; style?: string; format?: string; maxTokens?: number }) {
    return this.call("summarize", {
      input: {
        content: opts.content,
        summary_style: opts.style,
        format_hint: opts.format,
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async analyze(opts: { content: string; goal?: string; hints?: string[]; maxTokens?: number }) {
    // Your runtime's doAnalyze expects body.input to be a STRING, not { content }.
    return this.call("analyze", {
      input: opts.content,
      ...(opts.goal ? { goal: opts.goal } : {}),
      ...(opts.hints ? { hints: opts.hints } : {}),
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async classify(opts: { content: string; maxLabels?: number; maxTokens?: number }) {
    return this.call("classify", {
      actor: this.actor, // classify requires actor in your runtime
      input: { content: opts.content },
      limits: {
        max_labels: opts.maxLabels ?? 5,
        max_output_tokens: opts.maxTokens ?? 1000,
      },
    });
  }

  async clean(opts: { content: string; operations?: string[]; maxTokens?: number }) {
    return this.call("clean", {
      input: { content: opts.content, operations: opts.operations ?? ["trim", "normalize_newlines"] },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async convert(opts: { content: string; from: string; to: string; maxTokens?: number }) {
    return this.call("convert", {
      input: { content: opts.content, source_format: opts.from, target_format: opts.to },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async describe(opts: { subject: string; context?: string; detail?: "short" | "medium" | "detailed"; maxTokens?: number }) {
    const subject = (opts.subject || "").slice(0, 140);
    const context = (opts.context ?? opts.subject ?? "").toString();
    return this.call("describe", {
      input: {
        subject,
        context,
        detail_level: opts.detail ?? "medium",
        audience: "general",
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async explain(opts: { subject: string; context?: string; style?: string; detail?: string; maxTokens?: number }) {
    const subject = (opts.subject || "").slice(0, 140);
    const context = (opts.context ?? opts.subject ?? "").toString();
    return this.call("explain", {
      input: {
        subject,
        context,
        style: opts.style ?? "step-by-step",
        audience: "general",
        detail_level: opts.detail ?? "medium",
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async format(opts: { content: string; to: string; maxTokens?: number }) {
    // Your runtime uses input.target_style, not target_format.
    return this.call("format", {
      input: { content: opts.content, target_style: opts.to },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async parse(opts: { content: string; contentType?: "json" | "yaml" | "text"; mode?: "best_effort" | "strict"; targetSchema?: string; maxTokens?: number }) {
    return this.call("parse", {
      input: {
        content: opts.content,
        content_type: opts.contentType ?? "text",
        mode: opts.mode ?? "best_effort",
        ...(opts.targetSchema ? { target_schema: opts.targetSchema } : {}),
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  async fetch(opts: { source: string; maxTokens?: number }) {
    // Your runtime reads body.source OR input.source.
    return this.call("fetch", {
      input: { source: opts.source },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 },
    });
  }

  // ---- raw call (keeps you aligned with runtime contract)
  async call(
    verb: Verb,
    body: Record<string, any>
  ): Promise<Receipt> {
    const url = `${this.runtime}/${verb}/v1.0.0`;

    // Keep x402 minimal and consistent; runtime will echo/accept it.
    const payload = {
      x402: {
        verb,
        version: "1.0.0",
        entry: `x402://${verb}agent.eth/${verb}/v1.0.0`,
      },
      // actor is used by classify + helpful elsewhere
      ...(body.actor ? { actor: body.actor } : { actor: this.actor }),
      ...body,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `commandlayer-js/${version}`,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const data = await resp.json().catch(() => ({}));

      if (!resp.ok) {
        throw new CommandLayerError(
          data?.message || data?.error?.message || `HTTP ${resp.status}`,
          resp.status,
          data
        );
      }

      // Optional automatic verification
      if (this.verifyReceipts) {
        const v = await verifyReceipt(data as Receipt, this.verifyDefaults || {});
        if (!v.ok) {
          throw new CommandLayerError("Receipt verification failed", 422, v);
        }
      }

      return data as Receipt;
    } catch (err: any) {
      if (err?.name === "AbortError") throw new CommandLayerError("Request timed out", 408);
      if (err instanceof CommandLayerError) throw err;
      throw new CommandLayerError(err?.message || String(err));
    } finally {
      clearTimeout(timeoutId);
    }
  }

  close() {
    // no-op
  }
}

export function createClient(opts: ClientOptions = {}) {
  return new CommandLayerClient(opts);
}
