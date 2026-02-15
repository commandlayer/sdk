import { spawnSync } from "node:child_process";

const suites = [
  "runtime/tests/*.test.mjs",
  "typescript-sdk/tests/*.test.mjs"
];

for (const pattern of suites) {
  const run = spawnSync("node", ["--test", pattern], {
    stdio: "inherit",
    cwd: new URL("../..", import.meta.url)
  });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
