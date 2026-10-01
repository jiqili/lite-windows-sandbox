use anyhow::{Context, Result, bail};
use serde_json::json;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    mem::size_of,
    net::{Shutdown, TcpListener, TcpStream},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Console::{
            CONSOLE_SCREEN_BUFFER_INFO, COORD, ClosePseudoConsole, CreatePseudoConsole,
            ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
            ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleOutputCP,
            GetConsoleScreenBufferInfo, GetStdHandle, HPCON, ReadConsoleW, STD_INPUT_HANDLE,
            STD_OUTPUT_HANDLE, SetConsoleMode, SetConsoleOutputCP,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

use crate::{pi_guard, proxy, runtime, win};

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.as_ref().encode_wide().chain([0]).collect()
}

fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
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

fn pipe() -> Result<(File, File)> {
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        bail!("CreatePipe: {}", unsafe { GetLastError() });
    }
    Ok(unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) })
}

struct Pty {
    hpc: HPCON,
    _input: File,
    _output: File,
}
impl Drop for Pty {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.hpc) };
    }
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn new(hpc: HPCON) -> Result<Self> {
        let mut size = 0;
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
        if unsafe { InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut size) }
            == 0
        {
            bail!("InitializeProcThreadAttributeList: {}", unsafe {
                GetLastError()
            });
        }
        let mut attrs = Self(buffer);
        if unsafe {
            UpdateProcThreadAttribute(
                attrs.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpc as *const std::ffi::c_void,
                size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            bail!("UpdateProcThreadAttribute: {}", unsafe { GetLastError() });
        }
        Ok(attrs)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}

fn terminal_size(handle: HANDLE) -> COORD {
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } != 0 {
        COORD {
            X: (info.srWindow.Right - info.srWindow.Left + 1).max(1),
            Y: (info.srWindow.Bottom - info.srWindow.Top + 1).max(1),
        }
    } else {
        COORD { X: 80, Y: 24 }
    }
}

struct ConsoleMode {
    handle: HANDLE,
    original: u32,
}
impl Drop for ConsoleMode {
    fn drop(&mut self) {
        unsafe { SetConsoleMode(self.handle, self.original) };
    }
}
fn set_mode(handle: HANDLE, change: impl FnOnce(u32) -> u32) -> Option<ConsoleMode> {
    let mut mode = 0;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return None;
    }
    if unsafe { SetConsoleMode(handle, change(mode)) } == 0 {
        return None;
    }
    Some(ConsoleMode {
        handle,
        original: mode,
    })
}

struct OutputCodePage(u32);
impl Drop for OutputCodePage {
    fn drop(&mut self) {
        unsafe { SetConsoleOutputCP(self.0) };
    }
}

fn utf8_output() -> Result<Option<OutputCodePage>> {
    let original = unsafe { GetConsoleOutputCP() };
    if original == 0 || original == 65001 {
        return Ok(None);
    }
    if unsafe { SetConsoleOutputCP(65001) } == 0 {
        bail!("SetConsoleOutputCP: {}", unsafe { GetLastError() });
    }
    Ok(Some(OutputCodePage(original)))
}

#[derive(Default)]
struct ConsoleDecoder {
    pending_high: Option<u16>,
}

impl ConsoleDecoder {
    fn utf8(&mut self, chunk: &[u16]) -> Vec<u8> {
        let mut units = Vec::with_capacity(chunk.len() + 1);
        units.extend(self.pending_high.take());
        units.extend_from_slice(chunk);
        if units
            .last()
            .is_some_and(|unit| (0xd800..=0xdbff).contains(unit))
        {
            self.pending_high = units.pop();
        }
        std::char::decode_utf16(units)
            .map(|ch| ch.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
            .into_bytes()
    }
}

#[derive(Default)]
struct InputNormalizer {
    previous_cr: bool,
}

impl InputNormalizer {
    fn normalize(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            match byte {
                b'\x08' => result.push(b'\x7f'),
                b'\n' if !self.previous_cr => result.push(b'\r'),
                b'\n' => {}
                other => result.push(other),
            }
            self.previous_cr = byte == b'\r';
        }
        result
    }
}

fn spawn_in_pty(exe: &Path, args: &[String], cwd: &Path, hpc: HPCON) -> Result<OwnedHandle> {
    let mut attrs = Attributes::new(hpc)?;
    let command = std::iter::once(quote(&exe.to_string_lossy()))
        .chain(args.iter().map(|arg| quote(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = wide(command);
    let program = wide(exe);
    let cwd = wide(cwd);
    let mut start: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    start.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    start.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    start.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    start.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    start.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    start.lpAttributeList = attrs.0.as_mut_ptr().cast();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        CreateProcessW(
            program.as_ptr(),
            cmd.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            cwd.as_ptr(),
            &start.StartupInfo,
            &mut process,
        )
    } == 0
    {
        bail!("CreateProcessW ConPTY: {}", unsafe { GetLastError() });
    }
    unsafe { CloseHandle(process.hThread) };
    Ok(unsafe { OwnedHandle::from_raw_handle(process.hProcess) })
}

fn serve(socket: TcpStream, mode: &str, size: COORD) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let base = Path::new(&std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is missing")?)
        .join("agent-sandbox-runtime");
    let (exe, args) = if mode == "probe" {
        (
            Path::new(r"C:\Windows\System32\whoami.exe").to_path_buf(),
            vec!["/user".to_string()],
        )
    } else {
        let cli = base
            .join("pi")
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-coding-agent")
            .join("dist")
            .join("bundle")
            .join("cli.js");
        let mut arguments = vec![cli.to_string_lossy().into_owned()];
        if mode == "version" {
            arguments.push("--version".to_string());
        } else if mode == "pi" {
            arguments.push("--extension".to_string());
            arguments.push(pi_guard::path()?.to_string_lossy().into_owned());
        }
        (
            base.join(runtime::node_folder()?).join("node.exe"),
            arguments,
        )
    };
    let (input_read, mut input_write) = pipe()?;
    let (mut output_read, output_write) = pipe()?;
    let mut hpc = 0;
    let status = unsafe {
        CreatePseudoConsole(
            size,
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &mut hpc,
        )
    };
    if status < 0 {
        bail!("CreatePseudoConsole: {status:#x}");
    }
    let pty = Pty {
        hpc,
        _input: input_read,
        _output: output_write,
    };
    let process = spawn_in_pty(&exe, &args, &cwd, hpc)?;
    let mut input = socket.try_clone()?;
    let input_thread = thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        let mut normalizer = InputNormalizer::default();
        while let Ok(n) = input.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let bytes = normalizer.normalize(&buffer[..n]);
            if input_write.write_all(&bytes).is_err() || input_write.flush().is_err() {
                break;
            }
        }
    });
    let mut output = socket.try_clone()?;
    let output_thread = thread::spawn(move || {
        let _ = io::copy(&mut output_read, &mut output);
    });
    unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    drop(pty);
    output_thread.join().ok();
    let _ = socket.shutdown(Shutdown::Both);
    input_thread.join().ok();
    let mut exit = 1;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        bail!("GetExitCodeProcess: {}", unsafe { GetLastError() });
    }
    if exit != 0 {
        bail!("Pi exited with code {exit}");
    }
    Ok(())
}

pub fn helper(port: u16, key: &str, mode: &str) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let (mut socket, _) = listener.accept()?;
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    let mut reader = BufReader::new(socket.try_clone()?);
    reader.read_line(&mut line)?;
    if line.trim_end() != key {
        bail!("helper handshake rejected");
    }
    line.clear();
    reader.read_line(&mut line)?;
    let config: serde_json::Value = serde_json::from_str(&line)?;
    if mode == "pi"
        && let Err(error) = proxy::configure_sandbox(&config["providers"])
            .and_then(|_| pi_guard::install().map(|_| ()))
    {
        let _ = writeln!(socket, "0{error}");
        return Err(error);
    }
    for (name, value) in [
        ("HTTP_PROXY", &config["http"]),
        ("HTTPS_PROXY", &config["https"]),
    ] {
        if let Some(value) = value.as_str().filter(|v| !v.is_empty()) {
            unsafe { std::env::set_var(name, value) };
        }
    }
    let no_proxy = std::env::var("NO_PROXY").unwrap_or_default();
    unsafe { std::env::set_var("NO_PROXY", format!("{no_proxy},localhost,127.0.0.1")) };
    socket.write_all(b"1\n")?;
    socket.set_read_timeout(None)?;
    let size = COORD {
        X: config["cols"]
            .as_i64()
            .unwrap_or(80)
            .clamp(1, i16::MAX as i64) as i16,
        Y: config["rows"]
            .as_i64()
            .unwrap_or(24)
            .clamp(1, i16::MAX as i64) as i16,
    };
    serve(socket, mode, size)
}

pub fn connect(
    user: &str,
    password: &[u8],
    helper: &Path,
    workspace: &Path,
    mode: &str,
    routes: serde_json::Value,
) -> Result<()> {
    let port_holder = TcpListener::bind("127.0.0.1:0")?;
    let port = port_holder.local_addr()?.port();
    drop(port_holder);
    let key = win::random_password()?;
    let args = vec![
        "__helper".into(),
        port.to_string(),
        key.clone(),
        mode.into(),
    ];
    let process = win::spawn_hidden_as(user, password, helper, &args, workspace)?;
    let address = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut socket = loop {
        if let Ok(socket) = TcpStream::connect(&address) {
            break socket;
        }
        if let Some(exit) = win::child_exit_if_done(&process)? {
            bail!("terminal helper exited: {exit}");
        }
        if Instant::now() >= deadline {
            bail!("terminal helper did not listen within 10 seconds");
        }
        thread::sleep(Duration::from_millis(50));
    };
    socket.set_nodelay(true)?;
    let size = terminal_size(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) });
    let config = json!({"http": runtime::proxy_value("HTTP_PROXY")?,
        "https": runtime::proxy_value("HTTPS_PROXY")?, "cols": size.X, "rows": size.Y,
        "providers": routes});
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(socket, "{key}\n{config}\n")?;
    let mut response = [0u8; 2];
    socket.read_exact(&mut response)?;
    if response[0] == b'0' {
        let mut message = String::new();
        BufReader::new(socket.try_clone()?).read_line(&mut message)?;
        bail!(
            "sandbox provider setup failed: {}{}",
            response[1] as char,
            message.trim_end()
        );
    }
    if &response != b"1\n" {
        bail!("terminal helper rejected the connection");
    }
    socket.set_read_timeout(None)?;
    let input_handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let output_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let input_mode = set_mode(input_handle, |old| {
        (old | ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT)
            & !(ENABLE_ECHO_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_QUICK_EDIT_MODE)
    });
    let _output_mode = set_mode(output_handle, |old| {
        old | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    });
    let _output_code_page = if _output_mode.is_some() {
        utf8_output()?
    } else {
        None
    };
    if input_mode.is_none() {
        eprintln!("Host stdin is not a Windows console; piped input may be line-buffered");
    }
    let raw_input = input_mode.is_some();
    let input_handle = input_handle as usize;
    let mut input = socket.try_clone()?;
    thread::spawn(move || {
        if raw_input {
            let mut buffer = [0u16; 64];
            let mut decoder = ConsoleDecoder::default();
            loop {
                let mut count = 0;
                let ok = unsafe {
                    ReadConsoleW(
                        input_handle as HANDLE,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        &mut count,
                        ptr::null_mut(),
                    )
                };
                if ok == 0 || count == 0 {
                    break;
                }
                let bytes = decoder.utf8(&buffer[..count as usize]);
                if input.write_all(&bytes).is_err() {
                    break;
                }
            }
        } else {
            let _ = io::copy(&mut io::stdin().lock(), &mut input);
        }
    });
    let output_result = (|| -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        let mut buffer = [0u8; 8192];
        loop {
            let n = socket.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            stdout.write_all(&buffer[..n])?;
            stdout.flush()?;
        }
        Ok(())
    })();
    drop(input_mode);
    let _ = socket.shutdown(Shutdown::Both);
    drop(socket);
    for _ in 0..30 {
        if let Some(exit) = win::child_exit_if_done(&process)? {
            if exit != 0 {
                bail!("terminal helper exited with code {exit}");
            }
            output_result?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = win::stop_child(&process);
    output_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn conpty_normalizes_enter_and_backspace_across_chunks() {
        let mut input = super::InputNormalizer::default();
        assert_eq!(input.normalize(b"hello\r"), b"hello\r");
        assert_eq!(input.normalize(b"\nworld\n\x08"), b"world\r\x7f");
    }

    #[test]
    fn console_input_preserves_chinese_and_split_surrogates() {
        let mut decoder = super::ConsoleDecoder::default();
        assert_eq!(decoder.utf8(&['中' as u16, '文' as u16]), "中文".as_bytes());
        assert!(decoder.utf8(&[0xd83d]).is_empty());
        assert_eq!(decoder.utf8(&[0xde00, '\r' as u16]), "😀\r".as_bytes());
    }
}
