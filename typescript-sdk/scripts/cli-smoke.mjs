import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkDir = path.resolve(__dirname, "..");
const cliPath = path.join(sdkDir, "dist", "cli.cjs");

function runCase(name, args, expected) {
  const result = spawnSync("node", [cliPath, ...args], {
    cwd: sdkDir,
    encoding: "utf8"
  });

  const output = `${result.stdout || ""}\n${result.stderr || ""}`;

  if (result.status !== expected.exitCode) {
    throw new Error(
      `${name}: expected exit code ${expected.exitCode}, got ${result.status}.\nOutput:\n${output}`
    );
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
  includes: ["Usage: commandlayer", "CommandLayer TypeScript SDK CLI"]
});

runCase("argument validation", ["summarize"], {
  exitCode: 1,
  includes: ["required option '--content <text>' not specified"]
});

runCase("bad JSON path", ["call", "--verb", "summarize", "--body", "{not-json}"], {
  exitCode: 1,
  includes: ["commandlayer:", "Expected property name or '}' in JSON"]
});

console.log("CLI smoke tests passed.");
