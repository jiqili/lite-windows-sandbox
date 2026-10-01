use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    ffi::{OsStr, c_void},
    io::{self, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    process::Command,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree, WAIT_OBJECT_0},
    NetworkManagement::NetManagement::{
        NERR_Success, NetUserAdd, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
        USER_INFO_1003, USER_PRIV_USER,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetTokenInformation, LookupAccountNameW,
        PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    },
    System::Threading::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW, GetCurrentProcess,
        GetExitCodeProcess, INFINITE, LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION,
        STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    },
    UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
};
use zeroize::Zeroizing;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

fn spawn_cwd(path: &Path) -> Vec<u16> {
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16])
        && units.get(5) == Some(&(b':' as u16))
    {
        units.drain(..4);
    }
    units.push(0);
    units
}

fn error() -> anyhow::Error {
    anyhow::anyhow!("Windows error {}", unsafe { GetLastError() })
}

pub fn current_sid() -> Result<String> {
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(error());
        }
        let result = (|| {
            let mut len = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
            let mut data = vec![0u8; len as usize];
            if GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), len, &mut len) == 0 {
                return Err(error());
            }
            sid_string(
                (data.as_ptr() as *const TOKEN_USER)
                    .read_unaligned()
                    .User
                    .Sid,
            )
        })();
        CloseHandle(token);
        result
    }
}

unsafe fn sid_string(sid: *mut c_void) -> Result<String> {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(error());
    }
    let len = (0..).take_while(|&n| unsafe { *text.add(n) } != 0).count();
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })?;
    unsafe { LocalFree(text as _) };
    Ok(result)
}

pub fn account_sid(name: &str) -> Result<String> {
    let name = wide(name);
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        );
        let mut sid = vec![0u8; sid_size as usize];
        let mut domain = vec![0u16; domain_size as usize];
        if LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        ) == 0
        {
            return Err(error());
        }
        sid_string(sid.as_mut_ptr().cast())
    }
}

pub fn random_password() -> Result<String> {
    let mut bytes = [0u8; 48];
    getrandom::fill(&mut bytes).map_err(|err| anyhow::anyhow!("random password: {err}"))?;
    Ok(format!("A1!{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub fn ensure_account(name: &str, password: &str, exists: bool) -> Result<()> {
    let name = wide(name);
    let password = wide(password);
    unsafe {
        if exists {
            let info = USER_INFO_1003 {
                usri1003_password: password.as_ptr() as _,
            };
            let status = NetUserSetInfo(
                ptr::null(),
                name.as_ptr(),
                1003,
                (&info as *const USER_INFO_1003).cast_mut().cast(),
                ptr::null_mut(),
            );
            if status != NERR_Success {
                bail!("NetUserSetInfo failed: {status}");
            }
        } else {
            let info = USER_INFO_1 {
                usri1_name: name.as_ptr() as _,
                usri1_password: password.as_ptr() as _,
                usri1_password_age: 0,
                usri1_priv: USER_PRIV_USER,
                usri1_home_dir: ptr::null_mut(),
                usri1_comment: ptr::null_mut(),
                usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
                usri1_script_path: ptr::null_mut(),
            };
            let status = NetUserAdd(
                ptr::null(),
                1,
                (&info as *const USER_INFO_1).cast_mut().cast(),
                ptr::null_mut(),
            );
            if status != NERR_Success {
                bail!(
                    "NetUserAdd failed: {status}; if the account already exists, recover it manually"
                );
            }
        }
    }
    Ok(())
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as _,
    }
}

pub fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    protect_with_flags(
        bytes,
        CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
    )
}

pub fn protect_user(bytes: &[u8]) -> Result<Vec<u8>> {
    protect_with_flags(bytes, CRYPTPROTECT_UI_FORBIDDEN)
}

fn protect_with_flags(bytes: &[u8], flags: u32) -> Result<Vec<u8>> {
    let input = blob(bytes);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    unsafe {
        if CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            &mut output,
        ) == 0
        {
            return Err(error());
        }
        let data = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as _);
        Ok(data)
    }
}

pub fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    let input = blob(bytes);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    unsafe {
        if CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) == 0
        {
            return Err(error());
        }
        let data = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as _);
        Ok(data)
    }
}

pub fn unprotect_user(bytes: &[u8]) -> Result<Vec<u8>> {
    unprotect(bytes)
}

pub fn prompt_secret(provider: &str) -> Result<Zeroizing<String>> {
    struct EchoGuard(HANDLE, u32);
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            unsafe { SetConsoleMode(self.0, self.1) };
        }
    }
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        bail!("login requires an interactive host console");
    }
    print!("Enter {provider} API key: ");
    io::stdout().flush()?;
    if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(error());
    }
    let guard = EchoGuard(handle, mode);
    let mut secret = Zeroizing::new(String::new());
    let read = io::stdin().read_line(&mut secret)?;
    drop(guard);
    println!();
    if read == 0 {
        bail!("no API key entered");
    }
    while matches!(secret.chars().last(), Some('\r' | '\n')) {
        secret.pop();
    }
    if secret.is_empty() {
        bail!("empty API key");
    }
    Ok(secret)
}

pub fn protect_state_dir(path: &Path, owner_sid: &str) -> Result<()> {
    set_dacl(
        path,
        &format!("D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;{owner_sid})"),
    )
}

fn set_dacl(path: &Path, text: &str) -> Result<()> {
    let sddl = wide(text);
    let mut descriptor = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(error());
        }
        let result = SetFileSecurityW(
            wide(path).as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        LocalFree(descriptor as _);
        if result == 0 {
            return Err(error());
        }
    }
    Ok(())
}

pub fn prepare_helper(
    state: &Path,
    host_sid: &str,
    sandbox_sid: &str,
) -> Result<std::path::PathBuf> {
    let bin = state.join("bin");
    std::fs::create_dir_all(&bin)?;
    set_dacl(
        &bin,
        &format!(
            "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;{host_sid})(A;OICI;GRGX;;;{sandbox_sid})"
        ),
    )?;
    let source = std::env::current_exe()?;
    let data = std::fs::read(&source)?;
    let hash = blake3::hash(&data).to_hex();
    let target = bin.join(format!("helper-{}.exe", &hash[..12]));
    if !target.exists() {
        let staging = bin.join(format!("helper-{}.tmp", &hash[..12]));
        std::fs::write(&staging, data)?;
        std::fs::rename(staging, &target)?;
    }
    Ok(target)
}

pub fn grant_workspace(path: &Path, sid: &str) -> Result<()> {
    let status = Command::new("icacls.exe")
        .arg(path)
        .arg("/grant:r")
        .arg(format!("*{sid}:(OI)(CI)M"))
        .arg("/T")
        .status()?;
    if !status.success() {
        bail!("icacls workspace grant failed: {status}");
    }
    Ok(())
}

fn quote(s: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in s.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                result.push_str(&"\\".repeat(slashes * 2 + 1));
                result.push('"');
                slashes = 0;
            }
            _ => {
                result.push_str(&"\\".repeat(slashes));
                slashes = 0;
                result.push(ch);
            }
        }
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    result
}

pub fn elevate_setup(state: &Path, owner_sid: &str) -> Result<()> {
    let report = state.join("setup-error.txt");
    match std::fs::remove_file(&report) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("clear old setup error"),
    }
    let exe = std::env::current_exe()?;
    let params = wide(format!(
        "__setup-elevated {} {}",
        quote(&state.to_string_lossy()),
        quote(owner_sid)
    ));
    let verb = wide("runas");
    let executable = wide(&exe);
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = executable.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = 1;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(error());
        }
        if info.hProcess.is_null() {
            bail!("setup did not start");
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut exit = 1;
        let ok = GetExitCodeProcess(info.hProcess, &mut exit);
        CloseHandle(info.hProcess);
        if ok == 0 {
            return Err(error());
        }
        if exit != 0 {
            let detail = std::fs::read_to_string(&report)
                .unwrap_or_else(|_| "elevated error report is unavailable".to_string());
            bail!("elevated setup failed with exit code {exit}: {detail}");
        }
    }
    Ok(())
}

fn spawn_as(
    user: &str,
    password: &[u8],
    exe: &Path,
    args: &[String],
    cwd: &Path,
    flags: u32,
) -> Result<OwnedHandle> {
    let pass_w = Zeroizing::new(wide(std::str::from_utf8(password)?));
    let user_w = wide(user);
    let domain = wide(".");
    let executable = wide(exe);
    let current_dir = spawn_cwd(cwd);
    let command = std::iter::once(quote(&exe.to_string_lossy()))
        .chain(args.iter().map(|arg| quote(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    if command.encode_utf16().count() > 1023 {
        bail!("Windows logon command line exceeds 1024 characters");
    }
    let mut cmd = wide(command);
    unsafe {
        let mut start: STARTUPINFOW = std::mem::zeroed();
        start.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessWithLogonW(
            user_w.as_ptr(),
            domain.as_ptr(),
            pass_w.as_ptr(),
            LOGON_WITH_PROFILE,
            executable.as_ptr(),
            cmd.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT | flags,
            ptr::null(),
            current_dir.as_ptr(),
            &start,
            &mut process,
        ) == 0
        {
            return Err(error()).context("start sandbox process");
        }
        CloseHandle(process.hThread);
        Ok(OwnedHandle::from_raw_handle(process.hProcess))
    }
}

pub fn run_as(user: &str, password: &[u8], exe: &Path, args: &[String], cwd: &Path) -> Result<i32> {
    let process = spawn_as(user, password, exe, args, cwd, 0)?;
    unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    let mut exit = 1;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        return Err(error());
    }
    Ok(exit as i32)
}

pub fn spawn_hidden_as(
    user: &str,
    password: &[u8],
    exe: &Path,
    args: &[String],
    cwd: &Path,
) -> Result<OwnedHandle> {
    spawn_as(user, password, exe, args, cwd, CREATE_NO_WINDOW)
}

pub fn child_exit_if_done(process: &OwnedHandle) -> Result<Option<u32>> {
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
        return Ok(None);
    }
    let mut exit = 1;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        return Err(error());
    }
    Ok(Some(exit))
}

pub fn stop_child(process: &OwnedHandle) -> Result<()> {
    if unsafe { TerminateProcess(process.as_raw_handle(), 1) } == 0 {
        return Err(error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_user_dpapi_roundtrip() {
        let secret = b"provider-key-test";
        let encrypted = super::protect_user(secret).unwrap();
        assert_ne!(encrypted, secret);
        assert_eq!(super::unprotect_user(&encrypted).unwrap(), secret);
    }

    #[test]
    fn child_cwd_avoids_verbatim_question_mark() {
        let path = super::spawn_cwd(std::path::Path::new(r"\\?\C:\Users\Alice\project"));
        assert_eq!(
            String::from_utf16(&path[..path.len() - 1]).unwrap(),
            r"C:\Users\Alice\project"
        );
    }

    #[test]
    fn machine_dpapi_roundtrip() {
        let secret = super::random_password().unwrap();
        let encrypted = super::protect(secret.as_bytes()).unwrap();
        assert_ne!(encrypted, secret.as_bytes());
        assert_eq!(super::unprotect(&encrypted).unwrap(), secret.as_bytes());
    }
}
