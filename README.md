# lite-windows-sandbox (Pi prototype)

Runs native Windows programs as a dedicated non-admin local account. `setup` requests UAC to create the account and protect its machine-scope DPAPI credentials, then installs Node and Pi as that account without elevation. The host user can add a workspace with `add`, or let `pi <workspace>` add it automatically, without UAC.

## Install

On Windows x64, install from npm and run from a host PowerShell:

```powershell
npm install -g lite-windows-sandbox
pi-windows-sandbox setup
pi-windows-sandbox login openrouter
pi-windows-sandbox pi C:\Users\YourName\project
```

If Pi is already installed on the host, `pi install npm:lite-windows-sandbox` also installs the package. Run `/sandbox` in the host Pi to see the path to the packaged executable, then run that executable from a host PowerShell. `pi install` does not replace the already-running host Pi; only the packaged executable starts a Pi session as the sandbox account. The Pi package's `/sandbox` command only prints instructions. The `/login` guard is embedded in the executable and loads only in sandbox Pi.

## Build and try from source

Requires Rust and an NTFS project directory **inside** the host user's profile. Clone the repository and run from an ordinary user terminal:

```powershell
git clone https://github.com/jiqili/lite-windows-sandbox.git
Set-Location lite-windows-sandbox
```

Then build and set up:

```powershell
cargo build --release
.\target\release\pi-windows-sandbox.exe setup
$workspace = Join-Path $env:USERPROFILE 'sandbox-demo'
New-Item -ItemType Directory -Path $workspace
New-Item -ItemType File -Path (Join-Path $workspace 'before-add.txt')
$private = Join-Path $env:USERPROFILE 'sandbox-private-probe'
New-Item -ItemType Directory -Path $private
New-Item -ItemType File -Path (Join-Path $private 'secret.txt')
Copy-Item .\scripts\probe.ps1 (Join-Path $workspace 'probe.ps1')
.\target\release\pi-windows-sandbox.exe add $workspace
.\target\release\pi-windows-sandbox.exe list
.\target\release\pi-windows-sandbox.exe run $workspace C:\Windows\System32\whoami.exe /user
```

Only `setup` opens a UAC prompt. It creates `agent-sandbox-<id>` and an empty workspace registry. After UAC returns, it downloads Node v24.19.0, verifies its SHA-256 against Node's release manifest, extracts it under the sandbox account's `%LOCALAPPDATA%\agent-sandbox-runtime`, and installs `@earendil-works/pi-coding-agent` under that directory with npm. Bootstrap uses the sandbox identity and needs no workspace. It forwards the host's `HTTP_PROXY` and `HTTPS_PROXY` to npm if set, but refuses proxy URLs containing credentials. If a download or install fails, retry with `pi-windows-sandbox bootstrap` without rerunning `setup` or rotating the password; an already extracted Node runtime is reused.

`add` edits only the project ACL, recursively granting Modify rights to the sandbox account. Windows accounts normally have bypass-traverse-checking privilege, so no ancestor ACL rewrite is needed; the probe checks actual access. Each added root stays accessible to the same sandbox account. `run` accepts an added root or a descendant as its working directory.

To add another existing project, run `pi-windows-sandbox add <project-path>` as the host user, or start `pi <project-path>` to add it automatically before launching Pi. Both use the same path checks and recursive ACL grant; the path must exist inside the host profile. `list` shows all registered roots. No default workspaces directory is created.

## Start Pi from the host terminal

```powershell
.\target\release\pi-windows-sandbox.exe pty-probe $workspace
.\target\release\pi-windows-sandbox.exe pi-pty-probe $workspace
.\target\release\pi-windows-sandbox.exe pi $workspace
```

`pi` launches the original Pi TUI under the sandbox account. The host launcher places a read/execute-only, versioned helper under `%LOCALAPPDATA%\pi-windows-sandbox\bin\`; that helper creates ConPTY in the sandbox account and forwards terminal bytes over an authenticated, short-lived localhost connection. The first two commands verify the account and Pi binary without starting an interactive session. For host-managed API keys, use the host-side `login` command below before starting Pi.

ConPTY receives the terminal size at startup; live window resizing is not forwarded yet.
The launcher flushes each TUI output chunk, reads Windows console keystrokes as Unicode, and writes UTF-8 terminal output without line buffering. If it prints `Host stdin is not a Windows console`, the caller is using a pipe instead of a console and keyboard input may arrive a line at a time.

The original host-side attempt to attach ConPTY through `CreateProcessWithLogonW` returned Windows error 87. Running the helper with `CreateProcessWithLogonW` and then creating ConPTY/starting Pi with `CreateProcessW` inside that account works.

The npm package bundles the compiled Windows `pi-windows-sandbox.exe` as a host-side launcher. Users run `setup` once, then `pi <project>` from their terminal; `add` remains available for registering projects separately. Node and Pi are installed into their own sandbox account during setup. The `npm install` route needs Node/npm on the host; the `pi install` route needs a host Pi for installation. The Pi extension itself does not establish the whole-process sandbox boundary.

## Host-side provider login

```powershell
.\target\release\pi-windows-sandbox.exe login openrouter
.\target\release\pi-windows-sandbox.exe login openai
.\target\release\pi-windows-sandbox.exe login anthropic
.\target\release\pi-windows-sandbox.exe login google
.\target\release\pi-windows-sandbox.exe login list
.\target\release\pi-windows-sandbox.exe logout openrouter
```

`login <provider>` asks for an API key in the host terminal with echo disabled. Supported providers are `openrouter`, `openai`, `anthropic`, `deepseek`, and `google` (Gemini). It stores user-scope DPAPI ciphertext in `%LOCALAPPDATA%\pi-windows-sandbox\keys.json`, outside the sandbox account's access; `login list` prints provider names, not keys. When `pi <workspace>` starts, the host serves those providers through a temporary localhost proxy; the sandbox Pi receives only proxy URLs and session-specific placeholder keys in its own `models.json`. The host injects the real key into requests to the corresponding fixed provider endpoint and forwards streamed responses. The launcher also loads `extensions/login-guard.js` from the sandbox account's runtime: it hides `/login` from the TUI completion list and intercepts `/login` editor submissions with a reminder to use the host CLI. It does not modify Pi itself or prevent direct writes to the sandbox account's `auth.json`; do not enter real keys into sandbox processes. OAuth and subscription login are not covered by this API-key flow.

Inspect `icacls $workspace` after `add` to confirm Modify access for the sandbox SID. For a file-access check executed as the sandbox account, run:

```powershell
$stateFile = Join-Path $env:LOCALAPPDATA 'pi-windows-sandbox\credentials.json'
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
.\target\release\pi-windows-sandbox.exe run $workspace $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $workspace 'probe.ps1') $workspace $env:USERPROFILE (Join-Path $private 'secret.txt') $stateFile
$report = Get-Content -LiteralPath (Join-Path $workspace 'sandbox-probe-result.json') -Raw | ConvertFrom-Json
$record = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
$report
$report.sid -eq $record.sid
```

The report must show the sandbox SID and workspace read/write as `true`. Profile listing, credential reading, and `canReadHostSibling` must all be `false` before making a host-data-isolation claim; `add` does not enforce those restrictions. If no report is created, troubleshoot process startup and desktop access before interpreting filesystem results. The script does not print the secret file or decrypted password.

## Current scope

This is a host launcher for Pi's native TUI, with a Pi package that helps locate the launcher. Native TUI, terminal input, and live host-managed provider requests have been exercised. The `/login` guard has not yet been verified in an interactive session, and bootstrap does not currently pin a Pi version. **The current prototype does not guarantee that non-workspace host files are unreadable**: ACLs already granted to Windows groups may still permit access. It does not set up a network firewall or reset the sandbox account's profile between sessions. `icacls` applies the workspace grant recursively; do not use an unreviewed workspace with junctions or links to private files. A failed `add` can leave partial ACL grants, and there is not yet a `remove` command. Previous builds may already have added an explicit deny ACE for the sandbox SID on the host profile; this build does not remove it. Repeating `setup` rotates the password; use `bootstrap` alone to retry installing Node or Pi. If initial setup fails after account creation but before credentials are saved, manual account recovery is needed. Existing single-workspace credentials from the earlier prototype require manual migration and ACL cleanup.
