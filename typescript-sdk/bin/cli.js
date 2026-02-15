#!/usr/bin/env node

/**
 * CommandLayer CLI
 *
 * Quick command-line interface for testing CommandLayer verbs.
 *
 * Works with the monorepo layout:
 *   typescript-sdk/
 *     dist/index.js
 *     bin/cli.js   (this file)
 */

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
  commandlayer summarize --content "Long text..." --style bullet_points
  commandlayer analyze --content "Data..." --dimensions sentiment,tone,themes
  commandlayer convert --content "# Title" --from markdown --to html
  commandlayer fetch --query "https://example.com" --mode text

Options:
  --content <text>       Content to process (required for most verbs)
  --query <url|text>     Query/URL (fetch verb)
  --style <style>        Style hint (summarize, explain)
  --format <format>      Format hint (summarize)
  --dimensions <list>    Comma-separated dimensions (analyze)
  --categories <list>    Comma-separated categories (classify)
  --mode <mode>          fetch mode: text|html|json (default: text)
  --from <format>        Source format (convert)
  --to <format>          Target format (convert, format)
  --detail <level>       describe detail: brief|medium|detailed (default: medium)
  --max-tokens <n>       Maximum output tokens (default: 1000)
  --actor <id>           Actor identifier
  --runtime <url>        Custom runtime URL
  --no-verify            Disable receipt verification
  --json                 Output raw receipt JSON
  --stdin                Read content from stdin (ignores --content if provided)
  --help, -h             Show this help

Notes:
  - Use --stdin to pipe content in:
      cat file.txt | commandlayer summarize --stdin --style bullet_points
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

      // flags that require a value
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

  const client = createClient({
    runtime: opts.runtime,
    actor: opts.actor,
    verifyReceipts: !opts["no-verify"],
  });

  const maxTokens = opts["max-tokens"] ? parseInt(opts["max-tokens"], 10) : 1000;

  try {
    // Allow piping large content without shell quoting limits
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
        receipt = await client.analyze({
          content,
          dimensions: commaList(opts.dimensions),
          maxTokens,
        });
        break;

      case "classify":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.classify({
          content,
          categories: commaList(opts.categories),
          maxTokens,
        });
        break;

      case "clean":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.clean(content, maxTokens);
        break;

      case "convert":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.from) throw new Error("--from required");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.convert(content, opts.from, opts.to, maxTokens);
        break;

      case "describe":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.describe(content, opts.detail || "medium", maxTokens);
        break;

      case "explain":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.explain(content, opts.style || "step-by-step", maxTokens);
        break;

      case "format":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.format(content, opts.to, maxTokens);
        break;

      case "parse":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.parse(content, null, maxTokens);
        break;

      case "fetch":
        if (!opts.query) throw new Error("--query required");
        receipt = await client.fetch(opts.query, opts.mode || "text", maxTokens);
        break;

      default:
        throw new Error(`Verb "${verb}" not implemented`);
    }

    if (opts.json) {
      console.log(JSON.stringify(receipt, null, 2));
      return;
    }

    // Human output
    console.log("\n📝 Result:");
    console.log(JSON.stringify(receipt.result, null, 2));

    console.log("\n📋 Receipt:");
    const rid = receipt?.metadata?.receipt_id || receipt?.receipt_id;
    const ts = receipt?.metadata?.timestamp || receipt?.timestamp;
    console.log(`  ID: ${rid || "n/a"}`);
    console.log(`  Status: ${receipt.status || "n/a"}`);
    console.log(`  Timestamp: ${ts || "n/a"}`);

    if (receipt?.trace?.trace_id) {
      console.log(`  Trace ID: ${receipt.trace.trace_id}`);
    }

    if (receipt?.metadata?.proof) {
      const proof = receipt.metadata.proof;
      console.log("\n🔐 Proof:");
      if (proof.hash_sha256) console.log(`  Hash: ${String(proof.hash_sha256).slice(0, 16)}...`);
      if (proof.signer_id) console.log(`  Signer: ${proof.signer_id}`);
      console.log("  ✅ Signature verified");
    }
  } catch (err) {
    const error = err;

    console.error("\n❌ Error:", error?.message || String(error));

    // SDK error shape
    if (error instanceof CommandLayerError || error?.statusCode || error?.details) {
      if (error.statusCode) console.error(`   Status: ${error.statusCode}`);
      if (error.details) console.error("   Details:", error.details);
    }

    process.exit(1);
  } finally {
    // best effort close
    try {
      if (typeof client?.close === "function") client.close();
    } catch {}
  }
}

main();
