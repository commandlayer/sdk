import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";

const suites = [
  { pattern: "runtime/tests/*.test.mjs", optional: false },
  { pattern: "typescript-sdk/tests/*.test.mjs", optional: true }
];

for (const { pattern, optional } of suites) {
  const matches = globSync(pattern, { cwd: new URL("../..", import.meta.url) });
  if (optional && matches.length === 0) continue;

  const run = spawnSync("node", ["--test", pattern], {
    stdio: "inherit",
    cwd: new URL("../..", import.meta.url)
  });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
