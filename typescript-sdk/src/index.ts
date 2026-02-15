import Ajv from "ajv";
import addFormats from "ajv-formats";

export const version = "1.0.0";

export type Proof = {
  hash_sha256?: string;
  signature_ed25519?: string;
  signer_id?: string;
};

export type ReceiptMetadata = {
  receipt_id?: string;
  timestamp?: string;
  proof?: Proof;
  [k: string]: any;
};

export type ReceiptTrace = {
  trace_id?: string;
  [k: string]: any;
};

export type Receipt<T = any> = {
  status: "success" | "error" | string;
  result?: T;
  error?: any;
  metadata?: ReceiptMetadata;
  trace?: ReceiptTrace;
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

export type ClientOptions = {
  runtime?: string;
  actor?: string;
  verifyReceipts?: boolean; // NOTE: integrity check only unless you implement real signature verification
  timeout?: number;
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
  "fetch"
] as const;

type Verb = (typeof VERBS)[number];

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
void ajv; // prevent unused warning

export class CommandLayerClient {
  runtime: string;
  actor: string;
  verifyReceipts: boolean;
  timeout: number;
  fetchImpl: typeof fetch;

  constructor(opts: ClientOptions = {}) {
    this.runtime = (opts.runtime || "https://runtime.commandlayer.org").replace(/\/+$/, "");
    this.actor = opts.actor || "sdk-user";
    this.verifyReceipts = opts.verifyReceipts !== false;
    this.timeout = opts.timeout ?? 30_000;
    this.fetchImpl = opts.fetchImpl || fetch;
  }

  async summarize(opts: { content: string; style?: string; format?: string; maxTokens?: number }) {
    return this.call("summarize", {
      input: {
        content: opts.content,
        summary_style: opts.style,
        format_hint: opts.format
      },
      maxTokens: opts.maxTokens
    });
  }

  async analyze(opts: { content: string; dimensions?: string[]; maxTokens?: number }) {
    return this.call("analyze", {
      input: { content: opts.content, dimensions: opts.dimensions },
      maxTokens: opts.maxTokens
    });
  }

  async classify(opts: { content: string; categories?: string[]; maxTokens?: number }) {
    return this.call("classify", {
      input: { content: opts.content, categories: opts.categories },
      maxTokens: opts.maxTokens
    });
  }

  async clean(content: string, maxTokens?: number) {
    return this.call("clean", { input: { content }, maxTokens });
  }

  async convert(content: string, from: string, to: string, maxTokens?: number) {
    return this.call("convert", {
      input: { content, source_format: from, target_format: to },
      maxTokens
    });
  }

  async describe(content: string, detail: string = "medium", maxTokens?: number) {
    return this.call("describe", {
      input: {
        subject: content.slice(0, 140),
        context: content,
        detail_level: detail,
        audience: "general"
      },
      maxTokens
    });
  }

  async explain(content: string, style: string = "step-by-step", maxTokens?: number) {
    return this.call("explain", {
      input: {
        subject: content.slice(0, 140),
        context: content,
        style,
        audience: "general",
        detail_level: "medium"
      },
      maxTokens
    });
  }

  async format(content: string, target: string, maxTokens?: number) {
    return this.call("format", {
      input: { content, target_format: target },
      maxTokens
    });
  }

  async parse(content: string, schema: any = null, maxTokens?: number) {
    return this.call("parse", {
      input: { content, target_schema: schema },
      maxTokens
    });
  }

  async fetch(query: string, mode: string = "text", maxTokens?: number) {
    return this.call("fetch", {
      input: { query, mode },
      maxTokens
    });
  }

  async call(
    verb: Verb,
    opts: { input: Record<string, any>; maxTokens?: number }
  ): Promise<Receipt> {
    const url = `${this.runtime}/${verb}/v1.0.0`;

    const body = {
      x402: {
        verb,
        version: "1.0.0",
        protocol: "https"
      },
      actor: this.actor,
      limits: {
        max_output_tokens: opts.maxTokens ?? 1000
      },
      input: Object.fromEntries(
        Object.entries(opts.input).filter(([, v]) => v !== undefined && v !== null)
      ),
      channel: {
        protocol: "https",
        input_modalities: ["json"],
        output_modalities: ["json"]
      }
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `commandlayer-js/${version}`
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new CommandLayerError(
          data?.message || `HTTP ${response.status}`,
          response.status,
          data
        );
      }

      // Integrity check only (NOT cryptographic verification)
      if (
        this.verifyReceipts &&
        data?.metadata?.proof &&
        !data?.metadata?.receipt_id
      ) {
        throw new CommandLayerError("Invalid receipt: missing receipt_id");
      }

      return data as Receipt;
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
