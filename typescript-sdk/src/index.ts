import { createHash } from "node:crypto";
import { ethers } from "ethers";
import nacl from "tweetnacl";

export const commonsVersion = "1.1.0";
export const agentCardsVersion = "1.1.0";
export const packageVersion = "1.1.0";
/** @deprecated Use commonsVersion. */
export const version = commonsVersion;

const CANONICAL_ALG = "ed25519-sha256" as const;
const CANONICAL_FORMAT = "cl-stable-json-v1" as const;
const DEFAULT_RUNTIME = "https://runtime.commandlayer.org";
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

export type Verb = (typeof VERBS)[number];
export type ReceiptStatus = "success" | "error" | string;

export type ReceiptProof = {
  alg: typeof CANONICAL_ALG;
  canonical: typeof CANONICAL_FORMAT;
  signer_id: string;
  hash_sha256?: string;
  signature_b64?: string;
  [k: string]: unknown;
};

export type ReceiptMetadata = {
  receipt_id?: string;
  proof: ReceiptProof;
  actor?: { id: string; role?: string; [k: string]: unknown };
  [k: string]: unknown;
};

export type CanonicalReceipt<T = unknown> = {
  status: "success" | "error" | string;
  /**
   * Legacy / commercial-only metadata.
   * Commons v1.1.0 receipts should not rely on or emit this block.
   */
  x402?: {
    /** @deprecated Legacy fallback only. Prefer the top-level receipt.verb field. */
    verb?: string;
    version?: string;
    entry?: string;
    tenant?: string;
    extras?: Record<string, unknown>;
    [k: string]: unknown;
  };
  result?: T;
  error?: unknown;
  metadata?: ReceiptMetadata;
  [k: string]: unknown;
};

export type RuntimeMetadata = {
  trace_id?: string;
  parent_trace_id?: string | null;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  provider?: string;
  runtime?: string;
  request_id?: string;
  [k: string]: unknown;
};

export type CommandResponse<TResult = unknown, TError = unknown> = {
  receipt: CanonicalReceipt<TResult>;
  runtime_metadata?: RuntimeMetadata;
};

export type LegacyBlendedReceipt<TResult = unknown, TError = unknown> = CanonicalReceipt<TResult> & {
  trace?: RuntimeMetadata;
};

export type VerifyChecks = {
  hash_matches: boolean;
  signature_valid: boolean;
  receipt_id_present: boolean;
  /** @deprecated Legacy compatibility signal only. New receipts do not require receipt_id === hash_sha256. */
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

export type EnsVerifyOptions = { name: string; rpcUrl: string };
export type SignerKeyResolution = { algorithm: "ed25519"; kid: string; rawPublicKeyBytes: Uint8Array };
export type VerifyOptions = { publicKey?: string; ens?: EnsVerifyOptions };
export type ClientOptions = {
  runtime?: string;
  actor?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  verifyReceipts?: boolean;
  verify?: VerifyOptions;
};

export type ReceiptProtocolMetadata = {
  verb: string;
  version: string;
  [k: string]: unknown;
};

export type CommonsRequestEnvelope<TBody extends Record<string, unknown> = Record<string, unknown>> = {
  x402: ReceiptProtocolMetadata;
  actor: string;
} & TBody;

export type CommercialRequestEnvelope<TBody extends Record<string, unknown> = Record<string, unknown>> = {
  mode: "commercial";
  receipt: ReceiptProtocolMetadata;
  actor: string;
  payment: Record<string, unknown>;
} & TBody;

export class CommandLayerError extends Error {
  statusCode?: number;
  details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = "CommandLayerError";
    this.statusCode = statusCode;
    this.details = details;
  }
}

function normalizeBase(url: string) {
  return String(url || "").replace(/\/+$/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isVerb(value: string): value is Verb {
  return (VERBS as readonly string[]).includes(value);
}

export function buildCommonsRequest<TBody extends Record<string, unknown>>(
  verb: Verb,
  body: TBody,
  options: { actor: string; version?: string } = { actor: "sdk-user" }
): CommonsRequestEnvelope<TBody> {
  const actor = String(options.actor || body.actor || "sdk-user");
  const merged = { ...body, actor } as TBody & { actor: string };
  return { x402: { verb, version: options.version ?? commonsVersion }, ...merged };
}

export function buildCommercialRequest<TBody extends Record<string, unknown>>(
  verb: string,
  body: TBody,
  options: { actor: string; version?: string; payment: Record<string, unknown> }
): CommercialRequestEnvelope<TBody> {
  return {
    mode: "commercial",
    receipt: { verb, version: options.version ?? commonsVersion },
    payment: options.payment,
    actor: String(options.actor || body.actor || "sdk-user"),
    ...body
  };
}

export function canonicalizeStableJsonV1(value: unknown): string {
  return encode(value);

  function encode(v: unknown): string {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "string") return JSON.stringify(v);
    if (t === "boolean") return v ? "true" : "false";
    if (t === "number") {
      if (!Number.isFinite(v)) throw new Error("canonicalize: non-finite number not allowed");
      if (Object.is(v, -0)) return "0";
      return String(v);
    }
    if (t === "bigint") throw new Error("canonicalize: bigint not allowed");
    if (t === "undefined" || t === "function" || t === "symbol") {
      throw new Error(`canonicalize: unsupported type ${t}`);
    }
    if (Array.isArray(v)) return `[${v.map(encode).join(",")}]`;
    if (t === "object") {
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      let out = "{";
      for (let i = 0; i < keys.length; i += 1) {
        const key = keys[i]!;
        const val = obj[key];
        if (typeof val === "undefined") throw new Error(`canonicalize: undefined for key "${key}" not allowed`);
        if (i) out += ",";
        out += JSON.stringify(key) + ":" + encode(val);
      }
      return out + "}";
    }
    throw new Error("canonicalize: unsupported value");
  }
}

export function sha256HexUtf8(input: string): string {
  return createHash("sha256").update(Buffer.from(input, "utf8")).digest("hex");
}

function b64ToBytes(b64: string): Uint8Array {
  const buf = Buffer.from(b64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) throw new Error("invalid hex (expected 64 hex chars for ed25519 pubkey)");
  const buf = Buffer.from(clean, "hex");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function parseEd25519Pubkey(text: string): Uint8Array {
  const match = String(text).trim().match(/^ed25519\s*[:=]\s*(.+)$/i);
  const candidate = (match?.[1] ?? text).trim();
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(candidate)) {
    const pk = hexToBytes(candidate);
    if (pk.length !== 32) throw new Error("invalid ed25519 pubkey length");
    return pk;
  }
  const pk = b64ToBytes(candidate);
  if (pk.length !== 32) throw new Error("invalid base64 ed25519 pubkey length (need 32 bytes)");
  return pk;
}

export function verifyEd25519SignatureOverUtf8HashString(hashHex: string, signatureB64: string, pubkey32: Uint8Array): boolean {
  if (pubkey32.length !== 32) throw new Error("ed25519: pubkey must be 32 bytes");
  const sig = b64ToBytes(signatureB64);
  if (sig.length !== 64) throw new Error("ed25519: signature must be 64 bytes");
  return nacl.sign.detached.verify(new Uint8Array(Buffer.from(hashHex, "utf8")), sig, pubkey32);
}

export async function resolveSignerKey(name: string, rpcUrl: string): Promise<SignerKeyResolution> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const agentResolver = await provider.getResolver(name);
  if (!agentResolver) throw new Error(`No resolver for agent ENS name: ${name}`);
  const signerName = (await agentResolver.getText("cl.receipt.signer"))?.trim();
  if (!signerName) throw new Error(`ENS TXT cl.receipt.signer missing for agent ENS name: ${name}`);
  const signerResolver = await provider.getResolver(signerName);
  if (!signerResolver) throw new Error(`No resolver for signer ENS name: ${signerName}`);
  const pubKeyText = (await signerResolver.getText("cl.sig.pub"))?.trim();
  if (!pubKeyText) throw new Error(`ENS TXT cl.sig.pub missing for signer ENS name: ${signerName}`);
  const kid = (await signerResolver.getText("cl.sig.kid"))?.trim();
  if (!kid) throw new Error(`ENS TXT cl.sig.kid missing for signer ENS name: ${signerName}`);
  try {
    return { algorithm: "ed25519", kid, rawPublicKeyBytes: parseEd25519Pubkey(pubKeyText) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`ENS TXT cl.sig.pub malformed for signer ENS name: ${signerName}. ${message}`);
  }
}


function getReceiptVerb(receipt: CanonicalReceipt): string | null {
  if (typeof receipt.verb === "string") return receipt.verb;
  if (typeof receipt.x402?.verb === "string") return receipt.x402.verb;
  return null;
}

function extractReceipt(subject: CanonicalReceipt | CommandResponse | LegacyBlendedReceipt): CanonicalReceipt {
  if (subject && typeof subject === "object" && "receipt" in subject && (subject as CommandResponse).receipt) {
    return (subject as CommandResponse).receipt;
  }
  return subject as CanonicalReceipt;
}

export function extractReceiptVerb(subject: CanonicalReceipt | CommandResponse | LegacyBlendedReceipt): string | null {
  const receipt = extractReceipt(subject);
  return getReceiptVerb(receipt);
}

export function normalizeCommandResponse<T = unknown>(payload: unknown): CommandResponse<T> {
  if (!isRecord(payload)) throw new CommandLayerError("Runtime response must be a JSON object", 502, payload);
  if (isRecord(payload.receipt)) {
    const response: CommandResponse<T> = { receipt: payload.receipt as CanonicalReceipt<T> };
    if (isRecord(payload.runtime_metadata)) response.runtime_metadata = payload.runtime_metadata as RuntimeMetadata;
    return response;
  }
  const legacy = structuredClone(payload) as LegacyBlendedReceipt<T>;
  const runtime_metadata = isRecord(legacy.trace) ? legacy.trace : undefined;
  delete legacy.trace;
  return runtime_metadata ? { receipt: legacy, runtime_metadata } : { receipt: legacy };
}

export function toUnsignedReceipt(receiptLike: CanonicalReceipt | CommandResponse): CanonicalReceipt {
  const receipt = extractReceipt(receiptLike);
  if (!isRecord(receipt)) throw new Error("receipt must be an object");
  const unsigned = structuredClone(receipt) as CanonicalReceipt;
  delete (unsigned as Record<string, unknown>).receipt_id;
  if (isRecord(unsigned.metadata)) {
    delete unsigned.metadata.receipt_id;
    if (isRecord(unsigned.metadata.proof)) {
      const proof = unsigned.metadata.proof;
      unsigned.metadata.proof = {
        alg: proof.alg as typeof CANONICAL_ALG,
        canonical: proof.canonical as typeof CANONICAL_FORMAT,
        signer_id: String(proof.signer_id || "")
      };
    }
  }
  return unsigned;
}

export function recomputeReceiptHashSha256(receiptLike: CanonicalReceipt | CommandResponse) {
  const canonical = canonicalizeStableJsonV1(toUnsignedReceipt(receiptLike));
  return { canonical, hash_sha256: sha256HexUtf8(canonical) };
}

export async function verifyReceipt(receiptLike: CanonicalReceipt | CommandResponse, opts: VerifyOptions = {}): Promise<VerifyResult> {
  try {
    const receipt = extractReceipt(receiptLike);
    const proof = isRecord(receipt.metadata?.proof) ? (receipt.metadata.proof as Record<string, unknown>) : {};
    const claimedHash = typeof proof.hash_sha256 === "string" ? proof.hash_sha256 : null;
    const signatureB64 = typeof proof.signature_b64 === "string" ? proof.signature_b64 : null;
    const alg = typeof proof.alg === "string" ? proof.alg : null;
    const canonical = typeof proof.canonical === "string" ? proof.canonical : null;
    const signerId = typeof proof.signer_id === "string" ? proof.signer_id : null;
    const algMatches = alg === CANONICAL_ALG;
    const canonicalMatches = canonical === CANONICAL_FORMAT;
    const { hash_sha256: recomputedHash } = recomputeReceiptHashSha256(receipt);
    const hashMatches = claimedHash === recomputedHash;
    const receiptId = typeof receipt.metadata?.receipt_id === "string" ? receipt.metadata.receipt_id : null;
    const receiptIdMatches = !receiptId || !claimedHash ? true : receiptId === claimedHash;
    const receiptIdPresent = typeof receiptId === "string";

    let pubkey: Uint8Array | null = null;
    let pubkey_source: "explicit" | "ens" | null = null;
    let ens_error: string | null = null;
    let ens_txt_key: string | null = null;

    if (opts.publicKey) {
      pubkey = parseEd25519Pubkey(opts.publicKey);
      pubkey_source = "explicit";
    } else if (opts.ens) {
      ens_txt_key = "cl.receipt.signer -> cl.sig.pub, cl.sig.kid";
      try {
        const signerKey = await resolveSignerKey(opts.ens.name, opts.ens.rpcUrl);
        pubkey = signerKey.rawPublicKeyBytes;
        pubkey_source = "ens";
      } catch (error) {
        ens_error = error instanceof Error ? error.message : String(error);
      }
    }

    let signature_valid = false;
    let signature_error: string | null = null;
    if (!algMatches) signature_error = `proof.alg must be "${CANONICAL_ALG}" (got ${String(alg)})`;
    else if (!canonicalMatches) signature_error = `proof.canonical must be "${CANONICAL_FORMAT}" (got ${String(canonical)})`;
    else if (!claimedHash || !signatureB64) signature_error = "missing proof.hash_sha256 or proof.signature_b64";
    else if (!pubkey) signature_error = ens_error || "no public key available (provide publicKey or ens)";
    else {
      try {
        signature_valid = verifyEd25519SignatureOverUtf8HashString(claimedHash, signatureB64, pubkey);
      } catch (error) {
        signature_error = error instanceof Error ? error.message : String(error);
      }
    }

    return {
      ok: algMatches && canonicalMatches && hashMatches && signature_valid,
      checks: {
        hash_matches: hashMatches,
        signature_valid,
        receipt_id_present: receiptIdPresent,
        receipt_id_matches: receiptIdMatches,
        alg_matches: algMatches,
        canonical_matches: canonicalMatches
      },
      values: {
        verb: getReceiptVerb(receipt),
        signer_id: signerId,
        alg,
        canonical,
        claimed_hash: claimedHash,
        recomputed_hash: recomputedHash,
        receipt_id: receiptId,
        pubkey_source,
        ens_txt_key
      },
      errors: { signature_error, ens_error, verify_error: null }
    };
  } catch (error) {
    const receipt = extractReceipt(receiptLike as CanonicalReceipt | CommandResponse);
    return {
      ok: false,
      checks: {
        hash_matches: false,
        signature_valid: false,
        receipt_id_present: typeof receipt?.metadata?.receipt_id === "string",
        receipt_id_matches: false,
        alg_matches: false,
        canonical_matches: false
      },
      values: {
        verb: receipt ? getReceiptVerb(receipt) : null,
        signer_id: typeof receipt?.metadata?.proof?.signer_id === "string" ? receipt.metadata.proof.signer_id : null,
        alg: typeof receipt?.metadata?.proof?.alg === "string" ? receipt.metadata.proof.alg : null,
        canonical: typeof receipt?.metadata?.proof?.canonical === "string" ? receipt.metadata.proof.canonical : null,
        claimed_hash: typeof receipt?.metadata?.proof?.hash_sha256 === "string" ? receipt.metadata.proof.hash_sha256 : null,
        recomputed_hash: null,
        receipt_id: typeof receipt.metadata?.receipt_id === "string" ? receipt.metadata.receipt_id : null,
        pubkey_source: null,
        ens_txt_key: null
      },
      errors: { signature_error: null, ens_error: null, verify_error: error instanceof Error ? error.message : String(error) }
    };
  }
}

export class CommandLayerClient {
  runtime: string;
  actor: string;
  timeoutMs: number;
  fetchImpl: typeof fetch;
  verifyReceipts: boolean;
  verifyDefaults?: VerifyOptions;

  constructor(opts: ClientOptions = {}) {
    this.runtime = normalizeBase(opts.runtime || DEFAULT_RUNTIME);
    this.actor = opts.actor || "sdk-user";
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetchImpl || fetch;
    this.verifyReceipts = opts.verifyReceipts === true;
    this.verifyDefaults = opts.verify;
  }

  private ensureVerifyConfigIfEnabled() {
    if (!this.verifyReceipts) return;
    const hasExplicit = !!this.verifyDefaults?.publicKey?.trim();
    const hasEns = !!(this.verifyDefaults?.ens?.name && this.verifyDefaults?.ens?.rpcUrl);
    if (!hasExplicit && !hasEns) {
      throw new CommandLayerError("verifyReceipts is enabled but no verification key config provided. Set verify.publicKey or verify.ens { name, rpcUrl }.", 400);
    }
  }

  async summarize(opts: { content: string; style?: string; format?: string; maxTokens?: number }) {
    return this.call("summarize", { input: { content: opts.content, summary_style: opts.style, format_hint: opts.format }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async analyze(opts: { content: string; goal?: string; hints?: string[]; maxTokens?: number }) {
    return this.call("analyze", { input: opts.content, ...(opts.goal ? { goal: opts.goal } : {}), ...(opts.hints ? { hints: opts.hints } : {}), limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async classify(opts: { content: string; maxLabels?: number; maxTokens?: number }) {
    return this.call("classify", { input: { content: opts.content }, limits: { max_labels: opts.maxLabels ?? 5, max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async clean(opts: { content: string; operations?: string[]; maxTokens?: number }) {
    return this.call("clean", { input: { content: opts.content, operations: opts.operations ?? ["normalize_newlines", "collapse_whitespace", "trim"] }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async convert(opts: { content: string; from: string; to: string; maxTokens?: number }) {
    return this.call("convert", { input: { content: opts.content, source_format: opts.from, target_format: opts.to }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async describe(opts: { subject: string; audience?: string; detail?: "short" | "medium" | "detailed"; maxTokens?: number }) {
    return this.call("describe", { input: { subject: (opts.subject || "").slice(0, 140), audience: opts.audience ?? "general", detail_level: opts.detail ?? "medium" }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async explain(opts: { subject: string; audience?: string; style?: string; detail?: "short" | "medium" | "detailed"; maxTokens?: number }) {
    return this.call("explain", { input: { subject: (opts.subject || "").slice(0, 140), audience: opts.audience ?? "general", style: opts.style ?? "step-by-step", detail_level: opts.detail ?? "medium" }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }
  async format(opts: { content: string; to: string; maxTokens?: number }) {
    return this.call("format", { input: { content: opts.content, target_style: opts.to }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }

  async parse(opts: {
    content: string;
    contentType?: "json" | "yaml" | "text";
    mode?: "best_effort" | "strict";
    schema?: string;
    /** @deprecated Use schema. */
    targetSchema?: string;
    maxTokens?: number;
  }) {
    return this.call("parse", {
      input: {
        content: opts.content,
        content_type: opts.contentType ?? "text",
        mode: opts.mode ?? "best_effort",
        ...(opts.schema || opts.targetSchema ? { schema: opts.schema ?? opts.targetSchema } : {})
      },
      limits: { max_output_tokens: opts.maxTokens ?? 1000 }
    });
  }
  async fetch(opts: { source: string; query?: string; include_metadata?: boolean; maxTokens?: number }) {
    return this.call("fetch", { input: { source: opts.source, ...(opts.query !== undefined ? { query: opts.query } : {}), ...(opts.include_metadata !== undefined ? { include_metadata: opts.include_metadata } : {}) }, limits: { max_output_tokens: opts.maxTokens ?? 1000 } });
  }

  async call(verb: Verb, body: Record<string, unknown>): Promise<CommandResponse> {
    if (!isVerb(verb)) throw new CommandLayerError(`Unsupported verb: ${verb}`, 400);
    this.ensureVerifyConfigIfEnabled();

    const payload = {
      ...(body.actor ? { actor: body.actor } : { actor: this.actor }),
      ...body
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.runtime}/${verb}/v${commonsVersion}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": `commandlayer-js/${packageVersion}` },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      let data: unknown;
      try {
        data = await response.json();
      } catch {
        if (!response.ok) throw new CommandLayerError(`HTTP ${response.status} (non-JSON response)`, response.status);
        throw new CommandLayerError("Runtime returned non-JSON response", response.status);
      }
      if (!response.ok) {
        const detail = data as Record<string, any>;
        throw new CommandLayerError(detail?.message || detail?.error?.message || `HTTP ${response.status}`, response.status, data);
      }
      const normalized = normalizeCommandResponse(data);
      if (this.verifyReceipts) {
        const verified = await verifyReceipt(normalized.receipt, this.verifyDefaults || {});
        if (!verified.ok) throw new CommandLayerError("Receipt verification failed", 422, verified);
      }
      return normalized;
    } catch (error) {
      if ((error as { name?: string })?.name === "AbortError") throw new CommandLayerError("Request timed out", 408);
      if (error instanceof CommandLayerError) throw error;
      throw new CommandLayerError(error instanceof Error ? error.message : String(error));
    } finally {
      clearTimeout(timeoutId);
    }
  }

  close() {}
}

export function createClient(opts: ClientOptions = {}) {
  return new CommandLayerClient(opts);
}
