// typescript-sdk/bin/cli.js
#!/usr/bin/env node
// Keep this file as CommonJS so it can require dist/index.cjs reliably,
// even though the package is type=module.

const { createClient, CommandLayerError } = require("../dist/index.cjs");

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
  commandlayer analyze --content "Data..." --goal "find anomalies" --hints sentiment,tone
  commandlayer convert --content "# Title" --from json --to csv
  commandlayer fetch --query "https://example.com" --mode text

Options:
  --content <text>       Content to process (required for most verbs)
  --query <url>          URL to fetch (fetch verb)
  --style <style>        summarize/explain style hint
  --format <format>      summarize format hint
  --goal <text>          analyze goal
  --hints <list>         analyze hints (comma-separated)
  --dimensions <list>    alias for --hints
  --categories <list>    classify categories (comma-separated)
  --mode <mode>          fetch mode: text|html|json (default: text)
  --from <format>        convert source format
  --to <format>          convert target format
  --detail <level>       describe detail: short|medium|detailed (default: medium)
  --max-tokens <n>       Maximum output tokens (default: 1000)
  --actor <id>           Actor identifier
  --runtime <url>        Custom runtime URL
  --no-verify            Disable receipt verification
  --ens-rpc <url>        ETH RPC URL for ENS pubkey resolution (or env ETH_RPC_URL)
  --ens-text-key <key>   ENS TXT key for pubkey (default: cl.receipt.pubkey_pem)
  --json                 Output raw receipt JSON
  --stdin                Read content from stdin
  --help, -h             Show help
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
      if (next === undefined || next.startsWith("-")) out[key] = true;
      else {
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
    process.exit(1);
  }

  const ensRpcUrl = opts["ens-rpc"] || process.env.ETH_RPC_URL || "";
  const ensTextKey = opts["ens-text-key"] || "cl.receipt.pubkey_pem";

  const client = createClient({
    runtime: opts.runtime,
    actor: opts.actor,
    verifyReceipts: !opts["no-verify"],
    verifyWithEns: true,
    ensRpcUrl: ensRpcUrl || undefined,
    ensPubkeyTextKey: ensTextKey,
    validateSchema: false
  });

  const maxTokens = opts["max-tokens"] ? parseInt(opts["max-tokens"], 10) : 1000;

  try {
    const content = opts.stdin ? (await readStdin()).trimEnd() : opts.content;

    let receipt;

    switch (verb) {
      case "summarize":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.summarize({ content, style: opts.style, format: opts.format, maxTokens });
        break;

      case "analyze":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.analyze({
          content,
          goal: opts.goal,
          hints: commaList(opts.hints || opts.dimensions),
          maxTokens
        });
        break;

      case "classify":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.classify({ content, categories: commaList(opts.categories), maxTokens });
        break;

      case "clean":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.clean({ content, operations: commaList(opts.operations), maxTokens });
        break;

      case "convert":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.from) throw new Error("--from required");
        if (!opts.to) throw new Error("--to required");
        receipt = await client.convert({ content, from: opts.from, to: opts.to, maxTokens });
        break;

      case "describe":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.describe({
          subject: content.slice(0, 140),
          context: content,
          detail_level: opts.detail || "medium",
          maxTokens
        });
        break;

      case "explain":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.explain({
          subject: content.slice(0, 140),
          context: content,
          style: opts.style || "step-by-step",
          maxTokens
        });
        break;

      case "format":
        if (!content) throw new Error("--content required (or use --stdin)");
        if (!opts.to) throw new Error("--to required (maps to target_style)");
        receipt = await client.format({ content, target_style: opts.to, maxTokens });
        break;

      case "parse":
        if (!content) throw new Error("--content required (or use --stdin)");
        receipt = await client.parse({ content, content_type: opts["content-type"], mode: opts.mode, maxTokens });
        break;

      case "fetch":
        if (!opts.query) throw new Error("--query required");
        receipt = await client.fetch({ source: opts.query, mode: opts.mode || "text", maxTokens });
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
    const rid = receipt?.metadata?.receipt_id || receipt?.metadata?.proof?.hash_sha256 || "n/a";
    console.log(`  ID: ${rid}`);
    console.log(`  Status: ${receipt.status || "n/a"}`);
    if (receipt?.trace?.trace_id) console.log(`  Trace ID: ${receipt.trace.trace_id}`);

    if (opts["no-verify"]) console.log("\n🔐 Verification: skipped (--no-verify)");
    else console.log("\n🔐 Verification: ok (hash + signature)");
  } catch (err) {
    console.error("\n❌ Error:", err?.message || String(err));
    if (err instanceof CommandLayerError || err?.statusCode || err?.details) {
      if (err.statusCode) console.error(`   Status: ${err.statusCode}`);
      if (err.details) console.error("   Details:", err.details);
    }
    process.exit(1);
  }
}

main();
