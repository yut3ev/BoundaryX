// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tauri::State;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IPCRequest {
    protocol_version: String,
    request_id: String,
    command: String,
    payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IPCResponse {
    protocol_version: String,
    request_id: String,
    success: bool,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

type ResponseMap = HashMap<String, oneshot::Sender<Result<serde_json::Value, String>>>;

pub struct EngineSupervisor {
    stdin_tx: Mutex<Option<mpsc::Sender<String>>>,
    pending_requests: Arc<Mutex<ResponseMap>>,
    child_process: Arc<Mutex<Option<Child>>>,
}

impl EngineSupervisor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stdin_tx: Mutex::new(None),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            child_process: Arc::new(Mutex::new(None)),
        })
    }

    /// Locates the boundaryx-engine executable or Python fallback
    pub fn resolve_engine_target() -> Result<(PathBuf, Vec<String>), String> {
        // 1. Explicit environment override
        if let Ok(env_path) = std::env::var("BOUNDARYX_ENGINE_PATH") {
            let p = PathBuf::from(&env_path);
            if p.exists() {
                eprintln!("[supervisor] Using BOUNDARYX_ENGINE_PATH: {}", p.display());
                return Ok((p, vec!["--ipc".to_string()]));
            }
        }

        // Determine platform target triplet
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let triple_bin = "boundaryx-engine-x86_64-pc-windows-msvc.exe";
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let triple_bin = "boundaryx-engine-x86_64-unknown-linux-gnu";
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        let triple_bin = "boundaryx-engine-x86_64-apple-darwin";
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let triple_bin = "boundaryx-engine-aarch64-apple-darwin";
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        )))]
        let triple_bin = "boundaryx-engine";

        #[cfg(windows)]
        let plain_bin = "boundaryx-engine.exe";
        #[cfg(not(windows))]
        let plain_bin = "boundaryx-engine";

        // 2. Next to running executable (installed package / bundle)
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(exe_dir) = current_exe.parent() {
                let adjacent_plain = exe_dir.join(plain_bin);
                if adjacent_plain.exists() {
                    eprintln!("[supervisor] Found adjacent engine: {}", adjacent_plain.display());
                    return Ok((adjacent_plain, vec!["--ipc".to_string()]));
                }
                let adjacent_triple = exe_dir.join(triple_bin);
                if adjacent_triple.exists() {
                    eprintln!("[supervisor] Found adjacent triple engine: {}", adjacent_triple.display());
                    return Ok((adjacent_triple, vec!["--ipc".to_string()]));
                }
                let in_binaries = exe_dir.join("binaries").join(triple_bin);
                if in_binaries.exists() {
                    eprintln!("[supervisor] Found engine in binaries/: {}", in_binaries.display());
                    return Ok((in_binaries, vec!["--ipc".to_string()]));
                }
            }
        }

        // 3. Development working directories
        let search_dirs = [
            PathBuf::from("."),
            PathBuf::from("src-tauri"),
            PathBuf::from("apps/desktop/src-tauri"),
            PathBuf::from("../src-tauri"),
            PathBuf::from("../../apps/desktop/src-tauri"),
        ];

        for base in &search_dirs {
            let candidate = base.join("binaries").join(triple_bin);
            if candidate.exists() {
                eprintln!("[supervisor] Found candidate engine in search path: {}", candidate.display());
                return Ok((candidate, vec!["--ipc".to_string()]));
            }
        }

        // 4. Python virtualenv fallback for local development
        let venv_candidates = [
            PathBuf::from("../../engine/.venv/bin/python"),
            PathBuf::from("../../engine/.venv/Scripts/python.exe"),
            PathBuf::from("../engine/.venv/bin/python"),
            PathBuf::from("../engine/.venv/Scripts/python.exe"),
            PathBuf::from("engine/.venv/bin/python"),
            PathBuf::from("engine/.venv/Scripts/python.exe"),
        ];

        for venv_py in &venv_candidates {
            if venv_py.exists() {
                eprintln!("[supervisor] Falling back to engine venv Python: {}", venv_py.display());
                return Ok((
                    venv_py.clone(),
                    vec!["-m".to_string(), "boundaryx.cli".to_string(), "--ipc".to_string()],
                ));
            }
        }

        // 5. System Python fallback
        #[cfg(windows)]
        let sys_python = "python";
        #[cfg(not(windows))]
        let sys_python = "python3";

        eprintln!("[supervisor] Falling back to system {}: running module boundaryx.cli --ipc", sys_python);
        Ok((
            PathBuf::from(sys_python),
            vec!["-m".to_string(), "boundaryx.cli".to_string(), "--ipc".to_string()],
        ))
    }

    /// Spawns the boundaryx-engine child process and hooks up stdio piping
    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        let (program, args) = Self::resolve_engine_target()?;
        eprintln!("[supervisor] Launching engine sidecar: {} {:?}", program.display(), args);

        let mut cmd = Command::new(&program);
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW
            cmd.creation_flags(0x08000000);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn engine sidecar process: {}", e))?;

        let child_stdin = child.stdin.take().ok_or("Failed to open engine stdin")?;
        let child_stdout = child.stdout.take().ok_or("Failed to open engine stdout")?;
        let child_stderr = child.stderr.take().ok_or("Failed to open engine stderr")?;

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(128);

        // STDIN writer task
        tokio::spawn(async move {
            let mut writer = BufWriter::new(child_stdin);
            while let Some(line) = stdin_rx.recv().await {
                if let Err(e) = writer.write_all(line.as_bytes()).await {
                    eprintln!("[supervisor stdin] Failed to write to engine: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    eprintln!("[supervisor stdin] Failed to flush to engine: {}", e);
                    break;
                }
            }
        });

        // STDOUT reader task
        let pending = Arc::clone(&self.pending_requests);
        tokio::spawn(async move {
            let reader = BufReader::new(child_stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<IPCResponse>(trimmed) {
                    Ok(resp) => {
                        let mut map = pending.lock().await;
                        if let Some(sender) = map.remove(&resp.request_id) {
                            if resp.success {
                                let data = resp.data.unwrap_or(serde_json::Value::Null);
                                let _ = sender.send(Ok(data));
                            } else {
                                let err_msg = resp
                                    .error
                                    .map(|e| e.to_string())
                                    .unwrap_or_else(|| "Unknown engine error".to_string());
                                let _ = sender.send(Err(err_msg));
                            }
                        } else {
                            eprintln!("[supervisor stdout] Received unmapped response for request_id: {}", resp.request_id);
                        }
                    }
                    Err(e) => {
                        eprintln!("[supervisor stdout] Non-IPC message from engine: {} (raw: {})", e, trimmed);
                    }
                }
            }
            eprintln!("[supervisor stdout] Engine stdout stream closed.");
        });

        // STDERR logging task
        tokio::spawn(async move {
            let reader = BufReader::new(child_stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[engine log] {}", line);
            }
            eprintln!("[supervisor stderr] Engine stderr stream closed.");
        });

        *self.stdin_tx.lock().await = Some(stdin_tx);
        *self.child_process.lock().await = Some(child);

        eprintln!("[supervisor] Engine sidecar supervisor initialized successfully.");
        Ok(())
    }

    /// Dispatches an allowlisted command to the running engine sidecar
    pub async fn send_command(
        self: &Arc<Self>,
        request_id: String,
        command: String,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // Ensure child process is active, if not restart
        let needs_start = self.stdin_tx.lock().await.is_none();
        if needs_start {
            if let Err(e) = self.start().await {
                return Err(format!("Engine sidecar is not available: {}", e));
            }
        }

        let stdin_tx = {
            let guard = self.stdin_tx.lock().await;
            guard.clone().ok_or("Engine stdin channel closed")?
        };

        let req = IPCRequest {
            protocol_version: "1.0".to_string(),
            request_id: request_id.clone(),
            command,
            payload,
        };

        let serialized = serde_json::to_string(&req)
            .map_err(|e| format!("Failed to serialize IPC request: {}", e))?
            + "\n";

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut map = self.pending_requests.lock().await;
            map.insert(request_id.clone(), resp_tx);
        }

        if let Err(e) = stdin_tx.send(serialized).await {
            let mut map = self.pending_requests.lock().await;
            map.remove(&request_id);
            return Err(format!("Failed to transmit command to engine: {}", e));
        }

        // Wait with a 30-second timeout
        match tokio::time::timeout(Duration::from_secs(30), resp_rx).await {
            Ok(Ok(response_result)) => response_result,
            Ok(Err(_)) => {
                let mut map = self.pending_requests.lock().await;
                map.remove(&request_id);
                Err("Engine process terminated or connection was lost".to_string())
            }
            Err(_) => {
                let mut map = self.pending_requests.lock().await;
                map.remove(&request_id);
                Err("Engine command timed out after 30 seconds".to_string())
            }
        }
    }

    pub async fn shutdown(self: &Arc<Self>) {
        eprintln!("[supervisor] Shutting down engine sidecar...");
        let mut child_guard = self.child_process.lock().await;
        if let Some(mut child) = child_guard.take() {
            let _ = child.kill().await;
        }
        *self.stdin_tx.lock().await = None;
    }
}

#[tauri::command]
async fn ipc_command(
    request_id: String,
    command: String,
    payload: serde_json::Value,
    state: State<'_, Arc<EngineSupervisor>>,
) -> Result<serde_json::Value, String> {
    state.send_command(request_id, command, payload).await
}

fn main() {
    let supervisor = EngineSupervisor::new();
    let supervisor_clone = Arc::clone(&supervisor);

    tauri::Builder::default()
        .manage(supervisor)
        .setup(move |_app| {
            let sup = Arc::clone(&supervisor_clone);
            tauri::async_runtime::spawn(async move {
                if let Err(e) = sup.start().await {
                    eprintln!("[supervisor init warning] Could not start engine on launch: {}", e);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![ipc_command])
        .run(tauri::generate_context!())
        .expect("error while running BoundaryX Tauri desktop application");
}
