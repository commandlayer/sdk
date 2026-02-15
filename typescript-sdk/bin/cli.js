// typescript-sdk/bin/cli.js
#!/usr/bin/env node

/**
 * CommandLayer CLI
 *
 * Monorepo layout:
 *   typescript-sdk/
 *     dist/index.js
 *     bin/cli.js   (this file)
 *
 * This CLI matches the UPDATED SDK:
 * - Real receipt verification (canonicalize + hash + Ed25519)
 * - Optional ENS pubkey resolution (ethers v6) OR explicit PEM
 *
 * Node 18+ recommended.
 */

const fs = require("fs");
const path = require("path");
const { createClient, CommandLayerError } = require("../dist/index.js");

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
];

function printUsage() {
  console.log(`
CommandLayer CLI v1.0.0

Usage:
  commandlayer <verb> [options]

Available verbs:
  ${VERBS.join(", ")}

Examples:
  commandlayer summarize --content "Long text..." --style bullet_points --json
  commandlayer analyze --content "Data..." --json
  commandlayer clean --content " a\\n\\n b " --operations trim,normalize_newlines,remove_empty_lines --json
  commandlayer convert --content '{"a":1,"b":2}' --from json --to csv --json
  commandlayer describe --subject "CommandLayer receipt" --context "..." --detail medium --json
  commandlayer explain --subject "x402 receipt verification" --context "..." --style step-by-step --json
  commandlayer format --content "a: 1\\nb: 2" --target table --json
  commandlayer parse --content '{"a":1}' --content-type json --mode strict --json
  commandlayer fetch --source "https://example.com" --mode text --json

Global options:
  --actor <id>           Actor identifier (default: sdk-user)
  --runtime <url>        Custom runtime URL (default: https://runtime.commandlayer.org)
  --timeout <ms>         Request timeout (default: 30000)
  --no-verify            Disable receipt verification (NOT recommended)
  --json                 Output raw receipt JSON
  --stdin                Read content/context from stdin (ignores --content/--context if provided)
  --help, -h             Show help

Verification options (pick one):
  --pubkey-pem <pem>     Explicit public key PEM (string). Fastest.
  --pubkey-file <path>   Read public key PEM from file.
  --ens-name <name>      Resolve PEM from ENS TXT (e.g. runtime.commandlayer.eth)
  --rpc-url <url>        Ethereum RPC URL for ENS resolution
  --ens-txt-key <key>    ENS TXT key for PEM (default: cl.receipt.pubkey_pem)

Verb options (by verb):
  summarize:
    --content <text>      Required (or --stdin)
    --style <style>       e.g. bullet_points
    --format <format>     e.g. markdown|text
    --max-tokens <n>      default 1000

  analyze:
    --content <text>      Required (or --stdin)
    --max-tokens <n>

  classify:
    --content <text>      Required (or --stdin)
    --max-tokens <n>

  clean:
    --content <text>      Required (or --stdin)
    --operations <list>   Comma-separated ops (trim, normalize_newlines, etc.)
    --max-tokens <n>

  convert:
    --content <text>      Required (or --stdin)
    --from <format>       Required
    --to <format>         Required
    --max-tokens <n>

  describe:
    --subject <text>      Required
    --context <text>      Optional (or --stdin for context)
    --detail <level>      default medium
    --audience <aud>      default general
    --max-tokens <n>

  explain:
    --subject <text>      Required
    --context <text>      Optional (or --stdin for context)
    --style <style>       default step-by-step
    --detail <level>      default medium
    --audience <aud>      default general
    --max-tokens <n>

  format:
    --content <text>      Required (or --stdin)
    --target <style>      e.g. table|text (maps to target_style)
    --max-tokens <n>

  parse:
    --content <text>      Required (or --stdin)
    --content-type <t>    json|yaml|text
    --mode <m>            best_effort|strict
    --target-schema <s>   optional string
    --max-tokens <n>

  fetch:
    --source <url>        Required
    --mode <mode>         text|html|json (runtime-specific)
    --query <q>           optional
    --include-metadata    optional flag
    --max-tokens <n>

Notes:
  - Pipe input with --stdin:
      cat file.txt | commandlayer summarize --stdin --style bullet_points --json
`);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const out = { _: [] };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];

    if (!a.startsWith("-")) {
      out._.push(a);
      continue;
    }

    if (a === "--help" || a === "-h") {
      out.help = true;
      continue;
    }

    if (a === "--json") {
      out.json = true;
      continue;
    }

    if (a === "--stdin") {
      out.stdin = true;
      continue;
    }

    if (a === "--no-verify") {
      out["no-verify"] = true;
      continue;
    }

    if (a === "--include-metadata") {
      out["include-metadata"] = true;
      continue;
    }

    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];

      if (next === undefined || next.startsWith("-")) {
        out[key] = true;
      } else {
        out[key] = next;
        i++;
      }
      continue;
    }
  }

  return out;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function commaList(v) {
  if (!v) return undefined;
  return String(v)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function readFileIfExists(p) {
  const abs = path.resolve(process.cwd(), p);
  if (!fs.existsSync(abs)) return null;
  return fs.readFileSync(abs, "utf8");
}

function buildVerifyConfig(opts) {
  // Explicit PEM via flag or file (preferred)
  let pem = null;

  if (opts["pubkey-pem"]) pem = String(opts["pubkey-pem"]);
  if (!pem && opts["pubkey-file"]) pem = readFileIfExists(String(opts["pubkey-file"]));

  if (pem) {
    return { publicKeyPem: pem };
  }

  // ENS-based
  if (opts["ens-name"] || opts["rpc-url"]) {
    if (!opts["ens-name"]) throw new Error("--ens-name required when using ENS verification");
    if (!opts["rpc-url"]) throw new Error("--rpc-url required when using ENS verification");
    return {
      ens: {
        name: String(opts["ens-name"]),
        rpcUrl: String(opts["rpc-url"]),
        txtKey: opts["ens-txt-key"] ? String(opts["ens-txt-key"]) : "cl.receipt.pubkey_pem",
      },
    };
  }

  // none
  return {};
}

async function main() {
  const opts = parseArgs(process.argv);

  if (opts.help || opts._.length === 0) {
    printUsage();
    process.exit(0);
  }

  const verb = opts._[0];
  if (!VERBS.includes(verb)) {
    console.error(`Error: Unknown verb "${verb}"`);
    console.error(`Available verbs: ${VERBS.join(", ")}`);
    process.exit(1);
  }

  const timeout = opts.timeout ? parseInt(opts.timeout, 10) : 30000;
  const maxTokens = opts["max-tokens"] ? parseInt(opts["max-tokens"], 10) : 1000;

  let verifyCfg = {};
  try {
    verifyCfg = buildVerifyConfig(opts);
  } catch (e) {
    console.error("\n❌ Error:", e?.message || String(e));
    process.exit(1);
  }

  const client = createClient({
    runtime: opts.runtime,
    actor: opts.actor,
    timeout,
    verifyReceipts: !opts["no-verify"],
    ...verifyCfg,
  });

  try {
    // stdin can feed either content OR context depending on verb; we decide below
    const stdinText = opts.stdin ? (await readStdin()).trimEnd() : null;

    let receipt;

    switch (verb) {
      case "summarize": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.summarize({
          content,
          style: opts.style,
          format: opts.format,
          maxTokens,
        });
        break;
      }

      case "analyze": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.analyze({ content, maxTokens });
        break;
      }

      case "classify": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.classify({ content, maxTokens });
        break;
      }

      case "clean": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.clean({
          content,
          operations: commaList(opts.operations),
          maxTokens,
        });
        break;
      }

      case "convert": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.from) throw new Error("--from required");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.convert({
          content,
          from: String(opts.from),
          to: String(opts.to),
          maxTokens,
        });
        break;
      }

      case "describe": {
        const subject = opts.subject ? String(opts.subject) : null;
        if (!subject) throw new Error("--subject required");
        const context = stdinText != null ? stdinText : (opts.context ? String(opts.context) : undefined);

        receipt = await client.describe({
          subject,
          context,
          detail_level: opts.detail ? String(opts.detail) : "medium",
          audience: opts.audience ? String(opts.audience) : "general",
          maxTokens,
        });
        break;
      }

      case "explain": {
        const subject = opts.subject ? String(opts.subject) : null;
        if (!subject) throw new Error("--subject required");
        const context = stdinText != null ? stdinText : (opts.context ? String(opts.context) : undefined);

        receipt = await client.explain({
          subject,
          context,
          style: opts.style ? String(opts.style) : "step-by-step",
          detail_level: opts.detail ? String(opts.detail) : "medium",
          audience: opts.audience ? String(opts.audience) : "general",
          maxTokens,
        });
        break;
      }

      case "format": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        const target = opts.target ? String(opts.target) : null;
        if (!target) throw new Error("--target required (e.g. table|text)");
        receipt = await client.format({ content, target_style: target, maxTokens });
        break;
      }

      case "parse": {
        const content = stdinText != null ? stdinText : opts.content;
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.parse({
          content,
          content_type: opts["content-type"] ? String(opts["content-type"]) : undefined,
          mode: opts.mode ? String(opts.mode) : undefined,
          target_schema: opts["target-schema"] ? String(opts["target-schema"]) : undefined,
          maxTokens,
        });
        break;
      }

      case "fetch": {
        const source = opts.source ? String(opts.source) : null;
        if (!source) throw new Error("--source required (absolute URL)");
        receipt = await client.fetch({
          source,
          mode: opts.mode ? String(opts.mode) : "text",
          query: opts.query ? String(opts.query) : undefined,
          include_metadata: !!opts["include-metadata"],
          maxTokens,
        });
        break;
      }

      default:
        throw new Error(`Verb "${verb}" not implemented`);
    }

    if (opts.json) {
      console.log(JSON.stringify(receipt, null, 2));
      return;
    }

    // Human output
    console.log("\n📝 Result:");
    console.log(JSON.stringify(receipt.result ?? receipt.error ?? null, null, 2));

    console.log("\n📋 Receipt:");
    const rid = receipt?.metadata?.receipt_id || "(none)";
    const status = receipt?.status || "n/a";
    const traceId = receipt?.trace?.trace_id || "(none)";
    const duration = receipt?.trace?.duration_ms != null ? `${receipt.trace.duration_ms}ms` : "(n/a)";
    console.log(`  ID: ${rid}`);
    console.log(`  Status: ${status}`);
    console.log(`  Trace: ${traceId} (${duration})`);

    const proof = receipt?.metadata?.proof;
    if (proof) {
      console.log("\n🔐 Proof:");
      if (proof.alg) console.log(`  Alg: ${proof.alg}`);
      if (proof.canonical) console.log(`  Canonical: ${proof.canonical}`);
      if (proof.signer_id) console.log(`  Signer: ${proof.signer_id}`);
      if (proof.hash_sha256) console.log(`  Hash: ${String(proof.hash_sha256).slice(0, 16)}...`);
      console.log(`  Verify: ${opts["no-verify"] ? "skipped" : "ok (SDK verified)"}`);
    }
  } catch (err) {
    const error = err;

    console.error("\n❌ Error:", error?.message || String(error));

    if (error instanceof CommandLayerError || error?.statusCode || error?.details) {
      if (error.statusCode) console.error(`   Status: ${error.statusCode}`);
      if (error.details) console.error("   Details:", error.details);
    }

    process.exit(1);
  } finally {
    try {
      if (typeof client?.close === "function") client.close();
    } catch {}
  }
}

main();
