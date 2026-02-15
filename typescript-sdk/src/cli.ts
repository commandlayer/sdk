#!/usr/bin/env node
import { Command } from "commander";
import { createClient, type Receipt } from "./index";

const program = new Command();

program
  .name("commandlayer")
  .description("CommandLayer TypeScript SDK CLI")
  .option("--runtime <url>", "CommandLayer runtime base URL", "https://runtime.commandlayer.org")
  .option("--actor <id>", "Actor id used in requests", "sdk-cli")
  .option("--timeout-ms <ms>", "Request timeout in milliseconds", "30000")
  .option("--json", "Print full JSON receipt", false);

function printResult(receipt: Receipt, jsonOutput: boolean) {
  if (jsonOutput) {
    console.log(JSON.stringify(receipt, null, 2));
    return;
  }

  if (receipt.status) console.log(`status: ${receipt.status}`);
  if (receipt.metadata?.receipt_id) console.log(`receipt_id: ${receipt.metadata.receipt_id}`);
  if (receipt.result !== undefined) {
    console.log("result:");
    console.log(JSON.stringify(receipt.result, null, 2));
  }
}

function withCommonOptions(cmd: Command) {
  return cmd.requiredOption("--content <text>", "Input content").option("--max-tokens <n>", "Max output tokens", "1000");
}

withCommonOptions(
  program
    .command("summarize")
    .description("Summarize content")
    .option("--style <style>", "Summary style")
    .option("--format <format>", "Format hint")
).action(async (opts) => {
  const root = program.opts();
  const client = createClient({
    runtime: root.runtime,
    actor: root.actor,
    timeoutMs: Number(root.timeoutMs)
  });

  const receipt = await client.summarize({
    content: opts.content,
    style: opts.style,
    format: opts.format,
    maxTokens: Number(opts.maxTokens)
  });

  printResult(receipt, !!root.json);
});

withCommonOptions(program.command("analyze").description("Analyze content").option("--goal <goal>", "Optional analysis goal")).action(
  async (opts) => {
    const root = program.opts();
    const client = createClient({
      runtime: root.runtime,
      actor: root.actor,
      timeoutMs: Number(root.timeoutMs)
    });

    const receipt = await client.analyze({
      content: opts.content,
      goal: opts.goal,
      maxTokens: Number(opts.maxTokens)
    });

    printResult(receipt, !!root.json);
  }
);

program.command("call").description("Call a verb with a raw JSON payload").requiredOption("--verb <verb>", "Verb name")
  .requiredOption("--body <json>", "Request body JSON")
  .action(async (opts) => {
    const root = program.opts();
    const client = createClient({
      runtime: root.runtime,
      actor: root.actor,
      timeoutMs: Number(root.timeoutMs)
    });

    const body = JSON.parse(opts.body) as Record<string, unknown>;
    const receipt = await client.call(opts.verb, body as any);
    printResult(receipt, !!root.json);
  });

program.parseAsync().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`commandlayer: ${message}`);
  process.exitCode = 1;
});
