# lite-windows-sandbox

Runs Pi as a separate Windows account, with API keys kept in the host account. Windows x64 only. [Source, setup details, and current limitations](https://github.com/jiqili/lite-windows-sandbox#readme).

## Host command

```powershell
npm install -g lite-windows-sandbox
pi-windows-sandbox setup
pi-windows-sandbox login openrouter
pi-windows-sandbox pi C:\Users\YourName\project
```

`setup` requests UAC once and installs Node and Pi in the sandbox account. The launcher includes the `/login` guard; enter provider API keys only through the host-side `pi-windows-sandbox login <provider>` command.

## Install using Pi

```powershell
pi install npm:lite-windows-sandbox
```

Open host Pi and run `/sandbox` to display the packaged executable path and the host PowerShell commands. Run the packaged executable to start sandbox Pi; installing this Pi package does not isolate the already-running host Pi. The package's host-side Pi extension only displays instructions and does not intercept `/login` outside the sandbox.
