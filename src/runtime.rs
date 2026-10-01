use anyhow::{Context, Result, bail};
use std::{env, path::PathBuf};

use crate::win;

pub const NODE_VERSION: &str = "v24.19.0";

pub fn node_folder() -> Result<String> {
    let arch = match env::consts::ARCH {
        "x86_64" => "win-x64",
        "aarch64" => "win-arm64",
        other => bail!("unsupported Node architecture: {other}"),
    };
    Ok(format!("node-{NODE_VERSION}-{arch}"))
}

pub fn proxy_value(key: &str) -> Result<Option<String>> {
    match env::var(key) {
        Ok(value) => {
            let authority = value
                .split_once("://")
                .map(|(_, tail)| tail.split('/').next().unwrap_or(""));
            if authority.is_none()
                || authority.is_some_and(|host| host.contains('@'))
                || value.chars().any(char::is_control)
            {
                bail!("{key} cannot be passed to the sandbox process");
            }
            Ok(Some(value))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn proxy_setup() -> Result<String> {
    let mut script = String::new();
    for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
        if let Some(value) = proxy_value(key)? {
            script.push_str(&format!("$env:{key}='{}'; ", value.replace('\'', "''")));
        }
    }
    Ok(script)
}

fn stages() -> Result<Vec<(&'static str, String)>> {
    let folder = node_folder()?;
    let zip = format!("{folder}.zip");
    let download = format!(
        r#"$ErrorActionPreference='Stop'; $d=Join-Path $env:LOCALAPPDATA 'agent-sandbox-runtime'; $n=Join-Path $d '{folder}'; if ((Test-Path (Join-Path $n 'node.exe')) -and (Test-Path (Join-Path $n 'node_modules\npm\bin\npm-cli.js'))) {{ exit 0 }}; New-Item -ItemType Directory -Force -Path $d | Out-Null; Invoke-WebRequest -UseBasicParsing 'https://nodejs.org/dist/{NODE_VERSION}/{zip}' -OutFile (Join-Path $d 'node.zip'); Invoke-WebRequest -UseBasicParsing 'https://nodejs.org/dist/{NODE_VERSION}/SHASUMS256.txt' -OutFile (Join-Path $d 'SHASUMS256.txt')"#
    );
    let extract = format!(
        r#"$ErrorActionPreference='Stop'; $d=Join-Path $env:LOCALAPPDATA 'agent-sandbox-runtime'; $n=Join-Path $d '{folder}'; if ((Test-Path (Join-Path $n 'node.exe')) -and (Test-Path (Join-Path $n 'node_modules\npm\bin\npm-cli.js'))) {{ exit 0 }}; $line=Get-Content (Join-Path $d 'SHASUMS256.txt') | Where-Object {{ $_.EndsWith('  {zip}') }} | Select-Object -First 1; if (!$line -or (Get-FileHash (Join-Path $d 'node.zip') -Algorithm SHA256).Hash -ne $line.Substring(0,64)) {{ throw 'Node checksum mismatch' }}; Expand-Archive -LiteralPath (Join-Path $d 'node.zip') -DestinationPath $d -Force"#
    );
    let proxy = proxy_setup()?;
    let install = format!(
        r#"$ErrorActionPreference='Stop'; {proxy}$d=Join-Path $env:LOCALAPPDATA 'agent-sandbox-runtime'; $n=Join-Path $d '{folder}'; & (Join-Path $n 'node.exe') (Join-Path $n 'node_modules\npm\bin\npm-cli.js') install --prefix (Join-Path $d 'pi') --ignore-scripts @earendil-works/pi-coding-agent; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}"#
    );
    Ok(vec![
        ("download Node", download),
        ("verify and extract Node", extract),
        ("install Pi", install),
    ])
}

pub fn bootstrap(user: &str, password: &[u8]) -> Result<()> {
    let windows = PathBuf::from(env::var_os("WINDIR").context("WINDIR is missing")?);
    let cwd = windows.join("System32");
    let powershell = cwd
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    for (step, script) in stages()? {
        println!("Runtime bootstrap: {step}");
        let args = [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ]
        .map(str::to_string);
        let exit = win::run_as(user, password, &powershell, &args, &cwd)?;
        if exit != 0 {
            bail!("{step} failed (exit {exit}); run `pi-windows-sandbox bootstrap` to retry");
        }
    }
    println!("Node and Pi are installed in the sandbox account profile");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn bootstrap_commands_fit_windows_logon_limit() {
        for (_, script) in super::stages().unwrap() {
            assert!(script.encode_utf16().count() + 180 < 1024);
        }
    }
}
