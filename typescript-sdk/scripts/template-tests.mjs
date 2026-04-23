import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";

const repoRoot = new URL("../..", import.meta.url);

const suites = [
  "runtime/tests/*.test.mjs",
  "typescript-sdk/tests/*.test.mjs"
];

function hasGlobMatches(pattern) {
  const dir = pattern.slice(0, pattern.lastIndexOf("/"));
  const namePattern = pattern.slice(pattern.lastIndexOf("/") + 1);
  const dirPath = path.resolve(repoRoot.pathname, dir);

  if (!existsSync(dirPath)) {
    return false;
  }

  const matcher = new RegExp(
    `^${namePattern.replace(/[.+?^${}()|[\\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`
  );

  return readdirSync(dirPath).some((file) => matcher.test(file));
}

for (const pattern of suites) {
  if (!hasGlobMatches(pattern)) {
    continue;
  }

  const run = spawnSync("node", ["--test", pattern], {
    stdio: "inherit",
    cwd: repoRoot
  });

  if (run.status !== 0) {
    process.exit(run.status ?? 1);
  }
}
