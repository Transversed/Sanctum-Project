//! Drive the real `sanctum` binary from tests: isolated HOME, scripted
//! stdin, captured stdout/stderr lines.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const PASSPHRASE: &str = "integration-test-passphrase";

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sanctum")
}

/// A throw-away user: its own HOME with an initialized profile.
pub struct User {
    _dir: tempfile::TempDir,
    pub home: PathBuf,
    pub alias: String,
    pub fingerprint: String,
}

impl User {
    pub fn init(alias: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("sanctum-bin-{alias}-"))
            .tempdir()
            .unwrap();
        let home = dir.path().to_path_buf();
        let out = Command::new(bin())
            .args(["--no-banner", "init", "--alias", alias])
            .env("HOME", &home)
            .env("SANCTUM_PASSPHRASE", PASSPHRASE)
            .output()
            .unwrap();
        assert!(out.status.success(), "init failed: {out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let fingerprint = stdout
            .lines()
            .find_map(|l| l.strip_prefix("[sanctum] fingerprint: "))
            .expect("fingerprint printed")
            .trim()
            .to_string();
        Self {
            _dir: dir,
            home,
            alias: alias.to_string(),
            fingerprint,
        }
    }

    pub fn spawn(&self, args: &[&str]) -> Proc {
        let mut child = Command::new(bin())
            .arg("--no-banner")
            .args(args)
            .env("HOME", &self.home)
            .env("SANCTUM_PASSPHRASE", PASSPHRASE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let sink = lines.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    sink.lock().unwrap().push(line);
                }
            });
        }
        let stdin = child.stdin.take();
        Proc {
            child,
            stdin,
            lines,
        }
    }
}

/// A running `sanctum` process.
pub struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Proc {
    pub fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    pub fn output(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    pub fn raw_output(&self) -> String {
        self.output().join("\n")
    }

    /// Wait until a line contains `needle`.
    pub fn wait_for(&self, needle: &str, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.output().iter().any(|l| l.contains(needle)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Ask `/who` until `peers` members are listed as encrypted (🔒).
    pub fn wait_encrypted_with(&mut self, peers: usize, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let before = self.output().len();
            self.send("/who");
            std::thread::sleep(Duration::from_millis(400));
            let fresh = self.output().split_off(before);
            if fresh.iter().filter(|l| l.contains("🔒 chiffré")).count() >= peers {
                return true;
            }
        }
        false
    }

    /// Wait for the process to exit; returns its success flag.
    pub fn wait_exit(&mut self, timeout: Duration) -> Option<bool> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status.success());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
