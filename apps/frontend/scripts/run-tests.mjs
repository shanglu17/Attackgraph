import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const testsRoot = fileURLToPath(new URL("../tests/", import.meta.url));

async function discoverTests(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const discovered = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) discovered.push(...await discoverTests(absolute));
    else if (entry.isFile() && entry.name.endsWith(".test.ts")) discovered.push(absolute);
  }
  return discovered.sort((left, right) => left.localeCompare(right));
}

const tests = await discoverTests(testsRoot);
if (tests.length === 0) {
  console.error(`No .test.ts files found under ${testsRoot}`);
  process.exitCode = 1;
} else {
  const child = spawn(process.execPath, ["--import", "tsx", "--test", ...tests], { stdio: "inherit" });
  child.on("error", (error) => {
    console.error(error);
    process.exitCode = 1;
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      console.error(`Frontend tests terminated by ${signal}`);
      process.exitCode = 1;
    } else {
      process.exitCode = code ?? 1;
    }
  });
}
