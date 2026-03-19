import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkDir = path.resolve(__dirname, "..");
const cliPath = path.join(sdkDir, "dist", "cli.cjs");
const fixturePath = path.resolve(sdkDir, "..", "test_vectors", "receipt_valid.json");
const publicKey = `ed25519:${fs.readFileSync(path.resolve(sdkDir, "..", "test_vectors", "public_key_base64.txt"), "utf8").trim()}`;

function runCase(name, args, expected) {
  const result = spawnSync("node", [cliPath, ...args], { cwd: sdkDir, encoding: "utf8" });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (result.status !== expected.exitCode) {
    throw new Error(`${name}: expected exit code ${expected.exitCode}, got ${result.status}.\nOutput:\n${output}`);
  }
  for (const snippet of expected.includes) {
    if (!output.includes(snippet)) {
      throw new Error(`${name}: missing expected output snippet: "${snippet}"\nOutput:\n${output}`);
    }
  }
  console.log(`PASS: ${name}`);
}

runCase("help output", ["--help"], {
  exitCode: 0,
  includes: ["Usage: commandlayer", "CommandLayer CLI for calling Commons verbs and verifying signed receipts"]
});

runCase("argument validation", ["summarize"], {
  exitCode: 1,
  includes: ["required option '--content <text>' not specified"]
});

runCase("bad JSON path", ["call", "--verb", "summarize", "--body", "{not-json}"], {
  exitCode: 1,
  includes: ["commandlayer:", "Expected property name or '}' in JSON"]
});

runCase("verify fixture", ["verify", "--file", fixturePath, "--public-key", publicKey], {
  exitCode: 0,
  includes: ['"ok": true']
});

console.log("CLI smoke tests passed.");
