import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("../..", import.meta.url);

const suites = ["runtime/tests", "typescript-sdk/tests"];

const findTestFiles = (dir) => {
  if (!existsSync(new URL(dir, root))) {
    return [];
  }

  return readdirSync(new URL(dir, root))
    .filter((name) => name.endsWith(".test.mjs"))
    .map((name) => join(dir, name));
};

for (const suiteDir of suites) {
  const files = findTestFiles(suiteDir);
  if (files.length === 0) {
    continue;
  }

  const run = spawnSync("node", ["--test", ...files], {
    stdio: "inherit",
    cwd: root
  });
  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
