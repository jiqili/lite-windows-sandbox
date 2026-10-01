use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{collections::BTreeMap, fs, fs::OpenOptions, path::Path};
use zeroize::Zeroizing;

use crate::{providers, win};

type Keys = BTreeMap<String, String>;

fn valid_provider(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

fn read(state: &Path) -> Result<Keys> {
    match fs::read(state.join("keys.json")) {
        Ok(data) => Ok(serde_json::from_slice(&data)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Keys::new()),
        Err(error) => Err(error.into()),
    }
}

fn update(state: &Path, change: impl FnOnce(&mut Keys) -> Result<()>) -> Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(state.join("keys.lock"))?;
    lock.lock()?;
    let mut keys = read(state)?;
    change(&mut keys)?;
    let temporary = state.join("keys.tmp");
    fs::write(&temporary, serde_json::to_vec(&keys)?)?;
    fs::rename(temporary, state.join("keys.json"))?;
    Ok(())
}

pub fn login(state: &Path, provider: &str) -> Result<()> {
    if !state.is_dir() {
        bail!("run setup before configuring provider keys");
    }
    if !valid_provider(provider) {
        bail!("provider name must use lowercase letters, digits, - or _");
    }
    if providers::get(provider).is_none() {
        bail!("unsupported API-key provider: {provider}");
    }
    let key = win::prompt_secret(provider)?;
    let encrypted = STANDARD.encode(win::protect_user(key.as_bytes())?);
    update(state, |keys| {
        keys.insert(provider.to_owned(), encrypted);
        Ok(())
    })?;
    println!("Stored {provider} API key for the host user");
    Ok(())
}

pub fn logout(state: &Path, provider: &str) -> Result<()> {
    if !valid_provider(provider) {
        bail!("invalid provider name");
    }
    update(state, |keys| {
        keys.remove(provider);
        Ok(())
    })?;
    println!("Removed host key for {provider}");
    Ok(())
}

pub fn list(state: &Path) -> Result<()> {
    for provider in names(state)? {
        if key(state, &provider)?.is_some() {
            println!("{provider}: stored on host");
        }
    }
    Ok(())
}

pub fn names(state: &Path) -> Result<Vec<String>> {
    Ok(read(state)?.into_keys().collect())
}

pub fn key(state: &Path, provider: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let keys = read(state)?;
    match keys.get(provider) {
        Some(value) => Ok(Some(Zeroizing::new(win::unprotect_user(
            &STANDARD.decode(value)?,
        )?))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_ids_do_not_escape_host_vault() {
        assert!(super::valid_provider("openrouter"));
        assert!(super::valid_provider("some_provider-2"));
        assert!(!super::valid_provider("../credentials.json"));
    }
}
