#!/usr/bin/env node
// typescript-sdk/bin/cli.js  (ESM)

import { createClient, CommandLayerError, verifyReceipt } from "../dist/index.js";

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
  commandlayer analyze --content "Text..." --json
  commandlayer convert --content "{\\"a\\":1}" --from json --to csv --json
  commandlayer fetch --source "https://example.com" --json

Options:
  --content <text>       Content to process (required for most verbs)
  --source <url>         Source URL (fetch verb)
  --style <style>        Style hint (summarize, explain)
  --format <format>      Format hint (summarize)
  --categories <list>    Comma-separated categories (classify)
  --mode <mode>          parse mode: best_effort|strict
  --content-type <type>  parse content_type: json|yaml|text
  --from <format>        Source format (convert)
  --to <format>          Target format (convert, format)
  --detail <level>       describe detail: short|medium|detailed (default: medium)
  --max-tokens <n>       Maximum output tokens (default: 1000)
  --actor <id>           Actor identifier
  --runtime <url>        Custom runtime URL
  --no-verify            Disable auto verification
  --verify-ens <name>    Verify via ENS name (e.g. runtime.commandlayer.eth)
  --rpc <url>            ETH RPC URL for ENS verification
  --pubkey <pem>         Explicit PEM for verification (offline)
  --json                 Output raw receipt JSON
  --stdin                Read content from stdin (ignores --content)
  --help, -h             Show this help
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

    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = args[i + 1];

      if (next === undefined || next.startsWith("-")) {
        out[key] = true;
      } else {
        out[key] = next;
        i++;
      }
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

  const verifyDefaults = {};
  if (opts.pubkey) verifyDefaults.publicKeyPem = String(opts.pubkey);
  if (opts["verify-ens"] && opts.rpc) {
    verifyDefaults.ens = {
      name: String(opts["verify-ens"]),
      rpcUrl: String(opts.rpc),
      pubkeyTextKey: "cl.receipt.pubkey_pem",
    };
  }

  const client = createClient({
    runtime: opts.runtime,
    actor: opts.actor,
    verifyReceipts: !opts["no-verify"],
    verify: verifyDefaults,
  });

  const maxTokens = opts["max-tokens"] ? parseInt(opts["max-tokens"], 10) : 1000;

  try {
    const content = opts.stdin ? (await readStdin()).trimEnd() : opts.content;

    let receipt;

    switch (verb) {
      case "summarize":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.summarize({
          content,
          style: opts.style,
          format: opts.format,
          maxTokens,
        });
        break;

      case "analyze":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.analyze({ content, maxTokens });
        break;

      case "classify":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.classify({
          content,
          maxLabels: opts["max-labels"] ? parseInt(opts["max-labels"], 10) : 5,
          maxTokens,
        });
        break;

      case "clean":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.clean({
          content,
          operations: commaList(opts.operations),
          maxTokens,
        });
        break;

      case "convert":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.from) throw new Error("--from required");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.convert({ content, from: opts.from, to: opts.to, maxTokens });
        break;

      case "describe":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.describe({ subject: content, detail: opts.detail || "medium", maxTokens });
        break;

      case "explain":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.explain({ subject: content, style: opts.style || "step-by-step", maxTokens });
        break;

      case "format":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.format({ content, to: opts.to, maxTokens });
        break;

      case "parse":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.parse({
          content,
          contentType: opts["content-type"] || "text",
          mode: opts.mode || "best_effort",
          maxTokens,
        });
        break;

      case "fetch":
        if (!opts.source) throw new Error("--source required");
        receipt = await client.fetch({ source: opts.source, maxTokens });
        break;

      default:
        throw new Error(`Verb "${verb}" not implemented`);
    }

    if (opts.json) {
      console.log(JSON.stringify(receipt, null, 2));
      return;
    }

    console.log("\n📝 Result:");
    console.log(JSON.stringify(receipt.result, null, 2));

    console.log("\n📋 Receipt:");
    const rid = receipt?.metadata?.receipt_id;
    console.log(`  ID: ${rid || "n/a"}`);
    console.log(`  Status: ${receipt.status || "n/a"}`);
    if (receipt?.trace?.trace_id) console.log(`  Trace ID: ${receipt.trace.trace_id}`);

    if (receipt?.metadata?.proof) {
      const out = await verifyReceipt(receipt, verifyDefaults);
      console.log("\n🔐 Proof:");
      console.log(`  Hash matches: ${out.checks.hash_matches ? "yes" : "no"}`);
      console.log(`  Signature ok: ${out.checks.signature_valid ? "yes" : "no"}`);
      if (!out.ok && out.errors.signature_error) console.log(`  Error: ${out.errors.signature_error}`);
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
