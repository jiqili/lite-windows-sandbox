import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const packageDir = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const root = resolve(packageDir, "..");
const build = spawnSync("cargo", ["build", "--release", "--locked"], { cwd: root, stdio: "inherit" });
if (build.error) throw build.error;
if (build.status !== 0) process.exit(build.status ?? 1);

const native = join(packageDir, "native");
mkdirSync(native, { recursive: true });
copyFileSync(join(root, "target", "release", "pi-windows-sandbox.exe"), join(native, "pi-windows-sandbox.exe"));
