#![cfg(windows)]

mod login;
mod pi_guard;
mod providers;
mod proxy;
mod pty;
mod runtime;
mod win;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    fs::OpenOptions,
    path::{Component, Path, PathBuf, Prefix},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    sid: String,
    password: String,
}

fn state_dir() -> Result<PathBuf> {
    Ok(
        PathBuf::from(env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is missing")?)
            .join("pi-windows-sandbox"),
    )
}

fn account_name(owner_sid: &str) -> String {
    format!(
        "agent-sandbox-{}",
        &blake3::hash(owner_sid.as_bytes()).to_hex()[..6]
    )
}

fn is_local_disk(path: &Path) -> bool {
    matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}

fn is_executable_path(path: &Path) -> bool {
    path.is_absolute()
        && is_local_disk(path)
        && path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
}

fn check_workspace(workspace: &Path, profile: &Path, state: &Path) -> Result<()> {
    if !workspace.is_dir() || !is_local_disk(workspace) || workspace.components().count() < 3 {
        bail!("workspace must be a local disk directory");
    }
    if !workspace.starts_with(profile) || workspace == profile {
        bail!("workspace must be inside the host profile");
    }
    if workspace.starts_with(state) || state.starts_with(workspace) {
        bail!("workspace must not overlap sandbox state");
    }
    for key in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Some(root) = env::var_os(key).and_then(|p| PathBuf::from(p).canonicalize().ok())
            && (workspace.starts_with(&root) || root.starts_with(workspace))
        {
            bail!("workspace overlaps protected directory {key}");
        }
    }
    Ok(())
}

fn setup(state: &Path, owner_sid: &str) -> Result<()> {
    fs::create_dir_all(state)?;
    win::protect_state_dir(state, owner_sid)?;
    let username = account_name(owner_sid);
    let previous = match fs::read(state.join("credentials.json")) {
        Ok(data) => {
            let value: serde_json::Value = serde_json::from_slice(&data)?;
            if value.get("workspace").is_some() {
                bail!("old single-workspace credentials need manual migration and ACL cleanup");
            }
            Some(serde_json::from_value::<Credentials>(value)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(old) = &previous {
        if old.username != username {
            bail!("existing credentials use a different sandbox account; migrate them manually");
        }
        if win::account_sid(&username)? != old.sid {
            bail!("sandbox account SID changed; manual recovery is required");
        }
    }
    let password = Zeroizing::new(win::random_password()?);
    win::ensure_account(&username, &password, previous.is_some())?;
    let sid = win::account_sid(&username)?;
    if previous.as_ref().is_some_and(|old| old.sid != sid) {
        bail!("sandbox account SID changed; manual recovery is required");
    }
    let credentials = Credentials {
        username,
        sid,
        password: STANDARD.encode(win::protect(password.as_bytes())?),
    };
    let temporary = state.join("credentials.tmp");
    fs::write(&temporary, serde_json::to_vec(&credentials)?)?;
    fs::rename(&temporary, state.join("credentials.json"))?;
    let paths_file = state.join("workspaces.json");
    if !paths_file.exists() {
        fs::write(paths_file, b"[]")?;
    }
    println!("Sandbox account is ready");
    Ok(())
}

fn credentials(state: &Path) -> Result<Credentials> {
    let record: Credentials = serde_json::from_slice(&fs::read(state.join("credentials.json"))?)?;
    if account_name(&win::current_sid()?) != record.username
        || win::account_sid(&record.username)? != record.sid
    {
        bail!("sandbox credentials do not match this host user or account");
    }
    Ok(record)
}

fn workspaces(state: &Path) -> Result<Vec<PathBuf>> {
    Ok(serde_json::from_slice(&fs::read(
        state.join("workspaces.json"),
    )?)?)
}

fn is_registered(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

fn add(workspace: &Path) -> Result<()> {
    let state = state_dir()?;
    let record = credentials(&state)?;
    let workspace = workspace.canonicalize().context("workspace must exist")?;
    let profile = PathBuf::from(env::var_os("USERPROFILE").context("USERPROFILE is missing")?)
        .canonicalize()?;
    check_workspace(&workspace, &profile, &state.canonicalize()?)?;
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(state.join("workspaces.lock"))?;
    lock.lock()?;
    let mut paths = workspaces(&state)?;
    if paths.contains(&workspace) {
        return Ok(());
    }
    win::grant_workspace(&workspace, &record.sid)?;
    paths.push(workspace);
    let temporary = state.join("workspaces.tmp");
    fs::write(&temporary, serde_json::to_vec(&paths)?)?;
    fs::rename(temporary, state.join("workspaces.json"))?;
    println!("Workspace added");
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("usage: pi-windows-sandbox run <workspace> <absolute-exe> [args...]");
    }
    let state = state_dir()?;
    let record = credentials(&state)?;
    let workspace = Path::new(&args[0]).canonicalize()?;
    if !is_registered(&workspace, &workspaces(&state)?) {
        bail!("workspace was not added; run `pi-windows-sandbox add <workspace>` first");
    }
    let secret = STANDARD.decode(record.password)?;
    let password = Zeroizing::new(win::unprotect(&secret)?);
    let program = Path::new(&args[1]);
    if !is_executable_path(program) {
        bail!("run requires an absolute local .exe path");
    }
    let exit = win::run_as(&record.username, &password, program, &args[2..], &workspace)?;
    drop(password);
    std::process::exit(exit);
}

fn run_tui(workspace: &Path, mode: &str) -> Result<()> {
    let state = state_dir()?;
    let record = credentials(&state)?;
    let workspace = workspace.canonicalize()?;
    if !is_registered(&workspace, &workspaces(&state)?) {
        if mode == "pi" {
            add(&workspace)?;
        } else {
            bail!("workspace was not added");
        }
    }
    let helper = win::prepare_helper(&state, &win::current_sid()?, &record.sid)?;
    let secret = STANDARD.decode(record.password)?;
    let password = Zeroizing::new(win::unprotect(&secret)?);
    let inference = if mode == "pi" {
        proxy::Proxy::start(&state)?
    } else {
        None
    };
    let routes = inference
        .as_ref()
        .map(proxy::Proxy::config)
        .unwrap_or_default();
    pty::connect(
        &record.username,
        &password,
        &helper,
        &workspace,
        mode,
        routes,
    )
}

fn bootstrap() -> Result<()> {
    let record = credentials(&state_dir()?)?;
    let secret = STANDARD.decode(record.password)?;
    let password = Zeroizing::new(win::unprotect(&secret)?);
    runtime::bootstrap(&record.username, &password)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "setup" => {
            let state = state_dir()?;
            let owner = win::current_sid()?;
            win::elevate_setup(&state, &owner)?;
            bootstrap()
        }
        [command] if command == "bootstrap" => bootstrap(),
        [command, operation] if command == "login" && operation == "list" => {
            login::list(&state_dir()?)
        }
        [command, provider] if command == "login" => login::login(&state_dir()?, provider),
        [command, provider] if command == "logout" => login::logout(&state_dir()?, provider),
        [command, state, owner] if command == "__setup-elevated" => {
            let result = setup(Path::new(state), owner);
            if let Err(error) = &result {
                let _ = fs::write(
                    Path::new(state).join("setup-error.txt"),
                    format!("{error:#}"),
                );
            }
            result
        }
        [command, workspace] if command == "add" => add(Path::new(workspace)),
        [command] if command == "list" => {
            for workspace in workspaces(&state_dir()?)? {
                println!("{}", workspace.display());
            }
            Ok(())
        }
        [command, rest @ ..] if command == "run" => run(rest),
        [command, workspace] if command == "pi" => run_tui(Path::new(workspace), "pi"),
        [command, workspace] if command == "pi-tui" => run_tui(Path::new(workspace), "pi"),
        [command, workspace] if command == "pty-probe" => run_tui(Path::new(workspace), "probe"),
        [command, workspace] if command == "pi-pty-probe" => {
            run_tui(Path::new(workspace), "version")
        }
        [command, port, key, mode] if command == "__helper" => {
            pty::helper(port.parse()?, key, mode)
        }
        _ => bail!(
            "usage: pi-windows-sandbox setup | bootstrap | login <provider> | login list | logout <provider> | add <workspace> | list | run <workspace> <absolute-exe> [args...] | pi <workspace> | pty-probe <workspace> | pi-pty-probe <workspace>"
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_name_fits_windows_limit() {
        assert!(super::account_name("S-1-5-21-1234567890").len() <= 20);
    }

    #[test]
    fn verbatim_disk_is_local_but_unc_is_not() {
        use std::path::Path;
        assert!(super::is_local_disk(Path::new(
            r"\\?\C:\Users\Alice\project"
        )));
        assert!(super::is_local_disk(Path::new(r"C:\Users\Alice\project")));
        assert!(!super::is_local_disk(Path::new(r"\\server\share\project")));
    }

    #[test]
    fn sandbox_owned_executable_does_not_need_host_file_access() {
        use std::path::Path;
        assert!(super::is_executable_path(Path::new(
            r"C:\Users\agent-sandbox-demo\AppData\Local\agent-sandbox-runtime\node.exe"
        )));
        assert!(!super::is_executable_path(Path::new(
            r"C:\relative\node.cmd"
        )));
    }

    #[test]
    fn registered_root_does_not_match_sibling() {
        use std::path::{Path, PathBuf};
        let roots = vec![PathBuf::from(r"C:\Users\Alice\project")];
        assert!(super::is_registered(
            Path::new(r"C:\Users\Alice\project\src"),
            &roots
        ));
        assert!(!super::is_registered(
            Path::new(r"C:\Users\Alice\project-secret"),
            &roots
        ));
    }
}
