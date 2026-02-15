// typescript-sdk/src/index.ts
import { createHash } from "node:crypto";
import { ethers } from "ethers";
import nacl from "tweetnacl";

/**
 * CommandLayer TypeScript SDK — Commons v1.0.0
 *
 * Implements:
 * - Canonicalization: cl-stable-json-v1 (deterministic JSON w/ sorted keys, no whitespace)
 * - Hash recomputation: sha256 over canonicalized UNSIGNED receipt
 * - Signature verification: Ed25519 over the HASH STRING (utf8)
 * - ENS pubkey resolution: TXT lookup via ethers v6 resolver.getText()
 *
 * Node-only. (Uses node:crypto). For browser support, swap sha256 to noble + conditional exports.
 */

export const version = "1.0.0";

// -----------------------
// Types
// -----------------------
export type Proof = {
  alg?: string; // "ed25519-sha256"
  canonical?: string; // "cl-stable-json-v1"
  signer_id?: string; // e.g. runtime.commandlayer.eth
  hash_sha256?: string; // hex
  signature_b64?: string; // base64
  [k: string]: any;
};

export type ReceiptMetadata = {
  receipt_id?: string; // must equal proof.hash_sha256
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
  schema_valid?: boolean; // not implemented here
  hash_matches: boolean;
  signature_valid: boolean;
  receipt_id_matches: boolean;
  alg_matches: boolean;
  canonical_matches: boolean;
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
    receipt_id: string | null;
    pubkey_source: "explicit" | "ens" | null;
    ens_txt_key: string | null;
  };
  errors: {
    signature_error?: string | null;
    ens_error?: string | null;
    verify_error?: string | null;
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
  /**
   * TXT record key that contains an Ed25519 public key (32 bytes).
   * Accepts formats:
   * - "ed25519:<base64>"
   * - "<base64>" (32 bytes)
   * - "0x<hex>" / "<hex>" (64 hex chars)
   * Default: "cl.pubkey"
   */
  pubkeyTextKey?: string;
};

export type VerifyOptions = {
  /**
   * Explicit Ed25519 public key (preferred).
   * Accepts formats:
   * - "ed25519:<base64>"
   * - "<base64>" (32 bytes)
   * - "0x<hex>" / "<hex>" (64 hex chars)
   */
  publicKey?: string;
  /** Resolve Ed25519 public key from ENS via TXT record. */
  ens?: EnsVerifyOptions;
};

export type ClientOptions = {
  runtime?: string; // default https://runtime.commandlayer.org
  actor?: string; // used by classify + helpful elsewhere
  timeoutMs?: number;
  fetchImpl?: typeof fetch;

  /**
   * If true, every client call verifies the returned receipt.
   * Requires either:
   *  - opts.verify.publicKey, OR
   *  - opts.verify.ens (with rpcUrl)
   */
  verifyReceipts?: boolean;

  /** Default verification config used when verifyReceipts is enabled */
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
  "fetch"
] as const;

type Verb = (typeof VERBS)[number];

// -----------------------
// Helpers
// -----------------------
function normalizeBase(url: string) {
  return String(url || "").replace(/\/+$/, "");
}

// -----------------------
// Canonicalization: cl-stable-json-v1
// -----------------------
export function canonicalizeStableJsonV1(value: unknown): string {
  return encode(value);

  function encode(v: unknown): string {
    if (v === null) return "null";

    const t = typeof v;

    if (t === "string") return JSON.stringify(v);
    if (t === "boolean") return v ? "true" : "false";

    if (t === "number") {
      if (!Number.isFinite(v)) {
        throw new Error("canonicalize: non-finite number not allowed");
      }
      if (Object.is(v, -0)) return "0";
      return String(v);
    }

    if (t === "bigint") throw new Error("canonicalize: bigint not allowed");
    if (t === "undefined" || t === "function" || t === "symbol") {
      throw new Error(`canonicalize: unsupported type ${t}`);
    }

    if (Array.isArray(v)) {
      return "[" + v.map(encode).join(",") + "]";
    }

    if (t === "object") {
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).sort();

      let out = "{";
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i]!;
        const val = obj[k];

        if (typeof val === "undefined") {
          throw new Error(`canonicalize: undefined for key "${k}" not allowed`);
        }

        if (i) out += ",";
        out += JSON.stringify(k) + ":" + encode(val);
      }
      out += "}";
      return out;
    }

    throw new Error("canonicalize: unsupported value");
  }
}

export function sha256HexUtf8(input: string): string {
  return createHash("sha256").update(Buffer.from(input, "utf8")).digest("hex");
}

// -----------------------
// Ed25519 helpers (signs UTF-8 hash string)
// -----------------------
function b64ToBytes(b64: string): Uint8Array {
  const buf = Buffer.from(b64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error("invalid hex (expected 64 hex chars for ed25519 pubkey)");
  }
  const buf = Buffer.from(h, "hex");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Accepts:
 * - "ed25519:<base64>"
 * - "ed25519=<base64>"
 * - raw base64 (32 bytes)
 * - 0xhex / hex (64 hex chars => 32 bytes)
 */
export function parseEd25519Pubkey(text: string): Uint8Array {
  const s = String(text).trim();
  const m = s.match(/^ed25519\s*[:=]\s*(.+)$/i);
  const candidate = (m?.[1] ?? s).trim();

  // hex path
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(candidate)) {
    const pk = hexToBytes(candidate);
    if (pk.length !== 32) throw new Error("invalid ed25519 pubkey length");
    return pk;
  }

  // base64 path
  const pk = b64ToBytes(candidate);
  if (pk.length !== 32) throw new Error("invalid base64 ed25519 pubkey length (need 32 bytes)");
  return pk;
}

export function verifyEd25519SignatureOverUtf8HashString(
  hashHex: string,
  signatureB64: string,
  pubkey32: Uint8Array
): boolean {
  if (pubkey32.length !== 32) throw new Error("ed25519: pubkey must be 32 bytes");
  const msg = Buffer.from(hashHex, "utf8"); // IMPORTANT: hash is a hex string, signed as UTF-8
  const sig = b64ToBytes(signatureB64);
  if (sig.length !== 64) throw new Error("ed25519: signature must be 64 bytes");
  return nacl.sign.detached.verify(new Uint8Array(msg), sig, pubkey32);
}

// -----------------------
// ENS TXT pubkey resolution (ethers v6)
// -----------------------
export async function resolveEnsEd25519Pubkey(
  ens: EnsVerifyOptions
): Promise<{ pubkey: Uint8Array | null; source: "ens" | null; error?: string; txtKey: string; txtValue?: string }> {
  const txtKey = ens.pubkeyTextKey || "cl.pubkey";
  try {
    const provider = new ethers.JsonRpcProvider(ens.rpcUrl);
    const resolver = await provider.getResolver(ens.name);
    if (!resolver) return { pubkey: null, source: null, error: "No resolver for ENS name", txtKey };

    const txt = (await resolver.getText(txtKey))?.trim();
    if (!txt) return { pubkey: null, source: null, error: `ENS TXT ${txtKey} missing`, txtKey };

    const pubkey = parseEd25519Pubkey(txt);
    return { pubkey, source: "ens", txtKey, txtValue: txt };
  } catch (e: any) {
    return { pubkey: null, source: null, error: e?.message || "ENS resolution failed", txtKey };
  }
}

// -----------------------
// Receipt verification (protocol-aligned)
// -----------------------
/**
 * Unsigned receipt rule (production-safe):
 * - remove derived fields: metadata.receipt_id, proof.hash_sha256, proof.signature_b64
 * - keep proof.alg, proof.canonical, proof.signer_id (these are part of what is attested)
 */
export function toUnsignedReceipt(receipt: Receipt): any {
  if (!receipt || typeof receipt !== "object") throw new Error("receipt must be an object");

  const r: any = structuredClone(receipt);

  // Remove derived fields
  if (r.metadata && typeof r.metadata === "object") {
    if ("receipt_id" in r.metadata) delete r.metadata.receipt_id;

    if (r.metadata.proof && typeof r.metadata.proof === "object") {
      const p = r.metadata.proof;
      const unsignedProof: any = {};
      if (typeof p.alg === "string") unsignedProof.alg = p.alg;
      if (typeof p.canonical === "string") unsignedProof.canonical = p.canonical;
      if (typeof p.signer_id === "string") unsignedProof.signer_id = p.signer_id;
      r.metadata.proof = unsignedProof;
    }
  }

  // If top-level receipt_id ever exists, remove it too
  if ("receipt_id" in r) delete r.receipt_id;

  return r;
}

/**
 * Recompute receipt hash:
 * sha256Hex( canonicalizeStableJsonV1( unsignedReceipt ) )
 */
export function recomputeReceiptHashSha256(receipt: Receipt): { canonical: string; hash_sha256: string } {
  const unsigned = toUnsignedReceipt(receipt);
  const canonical = canonicalizeStableJsonV1(unsigned);
  const hash_sha256 = sha256HexUtf8(canonical);
  return { canonical, hash_sha256 };
}

/**
 * Verify a receipt:
 * - enforce proof.alg and proof.canonical
 * - recompute canonical hash over unsigned receipt
 * - compare to proof.hash_sha256
 * - enforce receipt_id == hash (metadata.receipt_id OR top-level receipt_id)
 * - verify Ed25519 signature over UTF-8 hash string using pubkey from explicit or ENS TXT
 */
export async function verifyReceipt(receipt: Receipt, opts: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    const proof: Proof = receipt?.metadata?.proof || {};
    const claimedHash = typeof proof.hash_sha256 === "string" ? proof.hash_sha256 : null;
    const sigB64 = typeof proof.signature_b64 === "string" ? proof.signature_b64 : null;

    const alg = typeof proof.alg === "string" ? proof.alg : null;
    const canonical = typeof proof.canonical === "string" ? proof.canonical : null;
    const signer_id = typeof proof.signer_id === "string" ? proof.signer_id : null;

    const algMatches = alg === "ed25519-sha256";
    const canonicalMatches = canonical === "cl-stable-json-v1";

    const { hash_sha256: recomputedHash } = recomputeReceiptHashSha256(receipt);
    const hashMatches = claimedHash ? recomputedHash === claimedHash : false;

    const receiptId = (receipt?.metadata?.receipt_id ?? (receipt as any)?.receipt_id ?? null) as string | null;
    const receiptIdMatches = claimedHash ? receiptId === claimedHash : false;

    // Resolve pubkey
    let pubkey: Uint8Array | null = null;
    let pubkey_source: "explicit" | "ens" | null = null;
    let ens_error: string | null = null;
    let ens_txt_key: string | null = null;

    if (opts.publicKey) {
      pubkey = parseEd25519Pubkey(opts.publicKey);
      pubkey_source = "explicit";
    } else if (opts.ens) {
      const res = await resolveEnsEd25519Pubkey(opts.ens);
      ens_txt_key = res.txtKey;
      if (!res.pubkey) {
        ens_error = res.error || "ENS pubkey not found";
      } else {
        pubkey = res.pubkey;
        pubkey_source = "ens";
      }
    }

    // Signature check
    let signature_valid = false;
    let signature_error: string | null = null;

    if (!algMatches) signature_error = `proof.alg must be "ed25519-sha256" (got ${String(alg)})`;
    else if (!canonicalMatches) signature_error = `proof.canonical must be "cl-stable-json-v1" (got ${String(canonical)})`;
    else if (!claimedHash || !sigB64) signature_error = "missing proof.hash_sha256 or proof.signature_b64";
    else if (!pubkey) signature_error = ens_error || "no public key available (provide verify.publicKey or verify.ens)";
    else {
      try {
        signature_valid = verifyEd25519SignatureOverUtf8HashString(claimedHash, sigB64, pubkey);
      } catch (e: any) {
        signature_valid = false;
        signature_error = e?.message || "signature verify failed";
      }
    }

    const ok = algMatches && canonicalMatches && hashMatches && receiptIdMatches && signature_valid;

    return {
      ok,
      checks: {
        hash_matches: hashMatches,
        signature_valid,
        receipt_id_matches: receiptIdMatches,
        alg_matches: algMatches,
        canonical_matches: canonicalMatches
      },
      values: {
        verb: receipt?.x402?.verb ?? null,
        signer_id,
        alg,
        canonical,
        claimed_hash: claimedHash,
        recomputed_hash: recomputedHash,
        receipt_id: receiptId,
        pubkey_source,
        ens_txt_key
      },
      errors: {
        signature_error,
        ens_error,
        verify_error: null
      }
    };
  } catch (e: any) {
    return {
      ok: false,
      checks: {
        hash_matches: false,
        signature_valid: false,
        receipt_id_matches: false,
        alg_matches: false,
        canonical_matches: false
      },
      values: {
        verb: receipt?.x402?.verb ?? null,
        signer_id: receipt?.metadata?.proof?.signer_id ?? null,
        alg: receipt?.metadata?.proof?.alg ?? null,
        canonical: receipt?.metadata?.proof?.canonical ?? null,
        claimed_hash: receipt?.metadata?.proof?.hash_sha256 ?? null,
        recomputed_hash: null,
        receipt_id: receipt?.metadata?.receipt_id ?? null,
        pubkey_source: null,
        ens_txt_key: null
      },
      errors: {
        signature_error: null,
        ens_error: null,
        verify_error: e?.message || String(e)
      }
    };
  }
}

// -----------------------
// Client
// -----------------------
export class CommandLayerClient {
  runtime: string;
  actor: string;
  timeoutMs: number;
  fetchImpl: typeof fetch;

  // default OFF unless explicitly enabled
  verifyReceipts: boolean;
  verifyDefaults?: VerifyOptions;

  constructor(opts: ClientOptions = {}) {
    this.runtime = normalizeBase(opts.runtime || "https://runtime.commandlayer.org");
    this.actor = opts.actor || "sdk-user";
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetchImpl || fetch;

    this.verifyReceipts = opts.verifyReceipts === true;
    this.verifyDefaults = opts.verify;
  }

  private ensureVerifyConfigIfEnabled() {
    if (!this.verifyReceipts) return;
    const v = this.verifyDefaults;
    const hasExplicit = !!(v?.publicKey && String(v.publicKey).trim().length);
    const hasEns = !!(v?.ens?.name && v?.ens?.rpcUrl);
    if (!hasExplicit && !hasEns) {
      throw new CommandLayerError(
        "verifyReceipts is enabled but no verification key config provided. Set: verify.publicKey OR verify.ens { name, rpcUrl }.",
        400
      );
    }
  }

  // ---- verb helpers
  async summarize(opts: { content: string; style?: string; format?: string; maxTokens?: number }) {
    return this.call("summarize", {
      input: {
        content: opts.content,
        summary_style: opts.style,
        format_hint: opts.format
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async analyze(opts: { content: string; goal?: string; hints?: string[]; maxTokens?: number }) {
    return this.call("analyze", {
      input: opts.content,
      ...(opts.goal ? { goal: opts.goal } : {}),
      ...(opts.hints ? { hints: opts.hints } : {}),
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async classify(opts: { content: string; maxLabels?: number; maxTokens?: number }) {
    return this.call("classify", {
      actor: this.actor,
      input: { content: opts.content },
      limits: {
        max_labels: opts.maxLabels ?? 5,
        max_output_tokens: opts.maxTokens ?? 1000
      }
    });
  }

  async clean(opts: { content: string; operations?: string[]; maxTokens?: number }) {
    return this.call("clean", {
      input: {
        content: opts.content,
        operations: opts.operations ?? ["normalize_newlines", "collapse_whitespace", "trim"]
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async convert(opts: { content: string; from: string; to: string; maxTokens?: number }) {
    return this.call("convert", {
      input: { content: opts.content, source_format: opts.from, target_format: opts.to },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async describe(opts: {
    subject: string;
    audience?: string;
    detail?: "short" | "medium" | "detailed";
    maxTokens?: number;
  }) {
    const subject = (opts.subject || "").slice(0, 140);
    return this.call("describe", {
      input: {
        subject,
        audience: opts.audience ?? "general",
        detail_level: opts.detail ?? "medium"
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async explain(opts: {
    subject: string;
    audience?: string;
    style?: string;
    detail?: "short" | "medium" | "detailed";
    maxTokens?: number;
  }) {
    const subject = (opts.subject || "").slice(0, 140);
    return this.call("explain", {
      input: {
        subject,
        audience: opts.audience ?? "general",
        style: opts.style ?? "step-by-step",
        detail_level: opts.detail ?? "medium"
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async format(opts: { content: string; to: string; maxTokens?: number }) {
    return this.call("format", {
      input: { content: opts.content, target_style: opts.to },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async parse(opts: {
    content: string;
    contentType?: "json" | "yaml" | "text";
    mode?: "best_effort" | "strict";
    targetSchema?: string;
    maxTokens?: number;
  }) {
    return this.call("parse", {
      input: {
        content: opts.content,
        content_type: opts.contentType ?? "text",
        mode: opts.mode ?? "best_effort",
        ...(opts.targetSchema ? { target_schema: opts.targetSchema } : {})
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  async fetch(opts: { source: string; query?: string; include_metadata?: boolean; maxTokens?: number }) {
    return this.call("fetch", {
      input: {
        source: opts.source,
        ...(opts.query !== undefined ? { query: opts.query } : {}),
        ...(opts.include_metadata !== undefined ? { include_metadata: opts.include_metadata } : {})
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }

  // ---- raw call
  async call(verb: Verb, body: Record<string, any>): Promise<Receipt> {
    const url = `${this.runtime}/${verb}/v1.0.0`;

    this.ensureVerifyConfigIfEnabled();

    const payload = {
      x402: {
        verb,
        version: "1.0.0",
        entry: `x402://${verb}agent.eth/${verb}/v1.0.0`
      },
      ...(body.actor ? { actor: body.actor } : { actor: this.actor }),
      ...body
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `commandlayer-js/${version}`
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      const data = await resp.json().catch(() => ({}));

      if (!resp.ok) {
        throw new CommandLayerError(
          data?.message || data?.error?.message || `HTTP ${resp.status}`,
          resp.status,
          data
        );
      }

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
