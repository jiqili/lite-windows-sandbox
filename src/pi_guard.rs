use anyhow::{Context, Result, bail};
use std::{env, fs, path::PathBuf};

const EXTENSION: &str = include_str!("../extensions/login-guard.js");

pub fn path() -> Result<PathBuf> {
    let base = PathBuf::from(env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is missing")?)
        .join("agent-sandbox-runtime")
        .join("extensions");
    let hash = blake3::hash(EXTENSION.as_bytes()).to_hex();
    Ok(base.join(format!("login-guard-{}.js", &hash[..12])))
}

pub fn install() -> Result<PathBuf> {
    let path = path()?;
    fs::create_dir_all(path.parent().context("missing extension directory")?)?;
    match fs::read(&path) {
        Ok(data) if data == EXTENSION.as_bytes() => {}
        Ok(_) => bail!("sandbox login guard was modified: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::write(&path, EXTENSION)?,
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}
