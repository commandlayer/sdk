import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";

const suites = [
  {
    pattern: "runtime/tests/*.test.mjs",
    optional: true
  },
  {
    pattern: "typescript-sdk/tests/*.test.mjs",
    optional: false
  }
];

const cwd = new URL("../..", import.meta.url);

for (const suite of suites) {
  const matches = globSync(suite.pattern, { cwd });

  if (matches.length === 0) {
    if (suite.optional) {
      console.log(`Skipping optional template test suite: ${suite.pattern}`);
      continue;
    }

    console.error(`No template tests found for required suite: ${suite.pattern}`);
    process.exit(1);
  }

  const run = spawnSync("node", ["--test", ...matches], {
    stdio: "inherit",
    cwd
  });

  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
