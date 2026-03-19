#!/usr/bin/env node
import { Command } from "commander";
import { createClient, verifyReceipt, type CommandResponse } from "./index";

function parseIntSafe(value: string, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

const program = new Command();
program
  .name("commandlayer")
  .description("CommandLayer CLI: verb-specific commands for fast common usage, plus call for generic JSON requests, and verify for receipts/envelopes")
  .option("--runtime <url>", "CommandLayer runtime base URL", "https://runtime.commandlayer.org")
  .option("--actor <id>", "Actor id used in requests", "sdk-cli")
  .option("--timeout-ms <ms>", "Request timeout in milliseconds", "30000")
  .option("--json", "Print full JSON output", false);

function printCommandResponse(response: CommandResponse, jsonOutput: boolean) {
  if (jsonOutput) {
    console.log(JSON.stringify(response, null, 2));
    return;
  }
  console.log(`status: ${response.receipt.status}`);
  if (response.receipt.metadata?.receipt_id) console.log(`receipt_id: ${response.receipt.metadata.receipt_id}`);
  if (response.runtime_metadata?.duration_ms !== undefined) {
    console.log(`duration_ms: ${response.runtime_metadata.duration_ms}`);
  }
  if (response.receipt.result !== undefined) {
    console.log("result:");
    console.log(JSON.stringify(response.receipt.result, null, 2));
  }
}

function createConfiguredClient() {
  const root = program.opts();
  return createClient({ runtime: root.runtime, actor: root.actor, timeoutMs: parseIntSafe(root.timeoutMs, 30_000) });
}

function withCommonOptions(cmd: Command) {
  return cmd.requiredOption("--content <text>", "Input content").option("--max-tokens <n>", "Max output tokens", "1000");
}

withCommonOptions(program.command("summarize").description("Summarize content").option("--style <style>", "Summary style").option("--format <format>", "Format hint")).action(async (opts) => {
  const response = await createConfiguredClient().summarize({
    content: opts.content,
    style: opts.style,
    format: opts.format,
    maxTokens: parseIntSafe(opts.maxTokens, 1000)
  });
  printCommandResponse(response, !!program.opts().json);
});

withCommonOptions(program.command("analyze").description("Analyze content").option("--goal <goal>", "Optional analysis goal")).action(async (opts) => {
  const response = await createConfiguredClient().analyze({
    content: opts.content,
    goal: opts.goal,
    maxTokens: parseIntSafe(opts.maxTokens, 1000)
  });
  printCommandResponse(response, !!program.opts().json);
});

program.command("call").description("Generic command for any verb when the verb-specific commands are too narrow").requiredOption("--verb <verb>", "Verb name").requiredOption("--body <json>", "Request body JSON").action(async (opts) => {
  const response = await createConfiguredClient().call(opts.verb, JSON.parse(opts.body) as Record<string, unknown>);
  printCommandResponse(response, !!program.opts().json);
});

program.command("verify").description("Verify a canonical receipt JSON object or a full response envelope with a top-level receipt field").requiredOption("--file <path>", "Path to receipt or response envelope JSON file").option("--public-key <key>", "Explicit Ed25519 public key").option("--ens-name <name>", "ENS name that publishes cl.receipt.signer").option("--rpc-url <url>", "RPC URL for ENS lookups").action(async (opts) => {
  const fs = await import("node:fs/promises");
  const raw = JSON.parse(await fs.readFile(opts.file, "utf8")) as Record<string, unknown>;
  const result = await verifyReceipt(raw as any, {
    ...(opts.publicKey ? { publicKey: opts.publicKey } : {}),
    ...(opts.ensName ? { ens: { name: opts.ensName, rpcUrl: opts.rpcUrl } } : {})
  });
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.ok ? 0 : 1;
});

program.parseAsync().catch((err: unknown) => {
  console.error(`commandlayer: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
