//! Optional external dissector bridge. TShark is a separately installed program,
//! not linked or bundled. No shell is used and arguments are never interpolated.
use crate::{Error, Result};
use std::{
    ffi::OsString,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
#[derive(Debug, Clone)]
pub struct TsharkOptions {
    pub executable: PathBuf,
    pub input: PathBuf,
    pub keylog: Option<PathBuf>,
    pub display_filter: Option<String>,
    pub max_line_bytes: usize,
}
impl TsharkOptions {
    pub fn new(input: PathBuf) -> Self {
        Self {
            executable: "tshark".into(),
            input,
            keylog: None,
            display_filter: None,
            max_line_bytes: 16 * 1024 * 1024,
        }
    }
    pub fn arguments(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "-n".into(),
            "-l".into(),
            "-r".into(),
            self.input.as_os_str().into(),
            "-T".into(),
            "ek".into(),
        ];
        if let Some(path) = &self.keylog {
            args.push("-o".into());
            let mut option = OsString::from("tls.keylog_file:");
            option.push(path);
            args.push(option);
        }
        if let Some(filter) = &self.display_filter {
            args.push("-Y".into());
            args.push(filter.into());
        }
        args
    }
}
pub fn version(executable: &std::path::Path) -> Result<String> {
    let result = Command::new(executable)
        .arg("--version")
        .output()
        .map_err(|e| Error::Unavailable(format!("TShark: {e}")))?;
    if !result.status.success() {
        return Err(Error::Unavailable("TShark --version failed".into()));
    }
    Ok(String::from_utf8_lossy(&result.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .into())
}
pub fn analyze<F: FnMut(serde_json::Value) -> Result<()>>(
    options: &TsharkOptions,
    cancelled: Arc<AtomicBool>,
    mut emit: F,
) -> Result<()> {
    if options.max_line_bytes < 1024 || options.max_line_bytes > 64 * 1024 * 1024 {
        return Err(Error::Invalid(
            "external JSON line limit must be 1 KiB..64 MiB".into(),
        ));
    }
    let mut child = Command::new(&options.executable)
        .args(options.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Unavailable(format!("TShark must be installed separately: {e}")))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut reader = BufReader::new(stderr);
        let mut chunk = [0; 4096];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let keep = (65536usize.saturating_sub(bytes.len())).min(n);
            bytes.extend(&chunk[..keep]);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    });
    // Read in a worker so cancellation can terminate a quiet external process.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<serde_json::Value>>(16);
    let max = options.max_line_bytes;
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            let result = (&mut reader)
                .take(max as u64 + 1)
                .read_until(b'\n', &mut line);
            match result {
                Ok(0) => break,
                Ok(_) if line.len() > max => {
                    let _ = tx.send(Err(Error::Limit("TShark JSON line exceeds bound".into())));
                    break;
                }
                Ok(_) => {
                    if tx
                        .send(serde_json::from_slice(&line).map_err(Error::from))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.into()));
                    break;
                }
            }
        }
    });
    let mut failure = None;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            let _ = child.kill();
            break;
        }
        match rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(Ok(value)) => {
                if value.get("layers").is_some() {
                    if let Err(e) = emit(value) {
                        failure = Some(e);
                        let _ = child.kill();
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                failure = Some(e);
                let _ = child.kill();
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    drop(rx);
    let status = child.wait()?;
    let _ = reader.join();
    let stderr = errors.join().unwrap_or_default();
    if let Some(error) = failure {
        return Err(error);
    }
    if !status.success() && !cancelled.load(Ordering::Relaxed) {
        return Err(Error::Invalid(format!("TShark failed: {}", stderr.trim())));
    }
    Ok(())
}
