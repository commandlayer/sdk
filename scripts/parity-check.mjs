import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "test_vectors", "parity_manifest.json"), "utf8"));

function runJson(command, args, options = {}) {
  const stdout = execFileSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    ...options
  });
  return JSON.parse(stdout);
}

function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalize(value[key])]));
  }
  return value;
}

function comparableVector(vector) {
  return normalize({
    name: vector.name,
    expected_ok: vector.expected_ok,
    ok: vector.ok,
    checks: vector.checks,
    errors: vector.errors,
    values: vector.values,
    recomputed_hash: vector.recomputed_hash
  });
}

function comparableEns(result) {
  return normalize({
    name: result.name,
    ok: result.ok,
    algorithm: result.algorithm,
    kid: result.kid,
    signer_name: result.signer_name,
    public_key_b64: result.public_key_b64
  });
}

const tsReport = runJson("node", [path.join("scripts", "parity-ts-report.mjs")]);
const pyReport = runJson("python", [path.join("python-sdk", "tests", "parity_report.py")], {
  env: { ...process.env, PYTHONPATH: path.join(repoRoot, "python-sdk") }
});

let failed = false;
console.log("Parity check against shared test_vectors:\n");
for (const vector of manifest.verification_vectors) {
  const tsVector = tsReport.vector_results.find((entry) => entry.name === vector.name);
  const pyVector = pyReport.vector_results.find((entry) => entry.name === vector.name);
  const tsComparable = comparableVector(tsVector);
  const pyComparable = comparableVector(pyVector);
  const matchesExpectation = tsVector.ok === vector.expected_ok && pyVector.ok === vector.expected_ok;
  const matchesEachOther = JSON.stringify(tsComparable) === JSON.stringify(pyComparable);
  const status = matchesExpectation && matchesEachOther ? "PASS" : "FAIL";
  console.log(`- ${status} ${vector.name}`);
  console.log(`  expected_ok=${vector.expected_ok} ts_ok=${tsVector.ok} py_ok=${pyVector.ok}`);
  console.log(`  hash=${tsVector.recomputed_hash}`);
  console.log(`  signer_id=${tsVector.values.signer_id} pubkey_source=${tsVector.values.pubkey_source}`);
  if (!matchesExpectation || !matchesEachOther) {
    failed = true;
    console.log("  ts=", JSON.stringify(tsComparable, null, 2));
    console.log("  py=", JSON.stringify(pyComparable, null, 2));
  }
}

console.log("\nENS signer resolution parity:\n");
for (const caseDef of manifest.ens_resolution_cases) {
  const tsEns = tsReport.ens_results.find((entry) => entry.name === caseDef.name);
  const pyEns = pyReport.ens_results.find((entry) => entry.name === caseDef.name);
  const tsComparable = comparableEns(tsEns);
  const pyComparable = comparableEns(pyEns);
  const matchesEachOther = JSON.stringify(tsComparable) === JSON.stringify(pyComparable);
  const matchesExpectation = caseDef.expected
    ? tsEns.ok && pyEns.ok && tsEns.algorithm === caseDef.expected.algorithm && tsEns.kid === caseDef.expected.kid && tsEns.signer_name === caseDef.expected.signer_name
    : !tsEns.ok && !pyEns.ok && tsEns.error?.includes(caseDef.error_contains) && pyEns.error?.includes(caseDef.error_contains);
  const status = matchesEachOther && matchesExpectation ? "PASS" : "FAIL";
  console.log(`- ${status} ${caseDef.name}`);
  console.log(`  ts_ok=${tsEns.ok} py_ok=${pyEns.ok} signer=${tsEns.signer_name}`);
  console.log(`  kid=${tsEns.kid} algorithm=${tsEns.algorithm}`);
  if (!matchesEachOther || !matchesExpectation) {
    failed = true;
    console.log("  ts=", JSON.stringify(tsComparable, null, 2));
    console.log("  py=", JSON.stringify(pyComparable, null, 2));
  }
}

if (tsReport.public_key_length !== 32 || pyReport.public_key_length !== 32) {
  failed = true;
  console.error(`\nFAIL public key parsing mismatch: ts=${tsReport.public_key_length}, py=${pyReport.public_key_length}`);
}

if (failed) {
  console.error("\nParity check failed.");
  process.exit(1);
}

console.log("\nParity check passed: TypeScript and Python agree on shared verification semantics.");
