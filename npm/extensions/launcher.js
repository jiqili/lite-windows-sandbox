import { fileURLToPath } from "node:url";

const exe = fileURLToPath(new URL("../native/pi-windows-sandbox.exe", import.meta.url));

export default function (pi) {
  pi.registerCommand("sandbox", {
    description: "Show how to launch Pi in the Windows sandbox",
    handler: async (_args, ctx) => {
      if (!ctx.hasUI) return;
      const command = `& '${exe.replaceAll("'", "''")}'`;
      ctx.ui.notify(`In a host PowerShell, run:\n${command} setup\n${command} login <provider>\n${command} pi <workspace>`, "info");
    },
  });
}
