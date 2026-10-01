#!/usr/bin/env node
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const exe = fileURLToPath(new URL("../native/pi-windows-sandbox.exe", import.meta.url));
const child = spawn(exe, process.argv.slice(2), { stdio: "inherit" });
child.on("error", (error) => {
  console.error(`Cannot start sandbox launcher: ${error.message}`);
  process.exitCode = 1;
});
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
});
