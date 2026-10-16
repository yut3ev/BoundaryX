// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

#[derive(Serialize, Deserialize, Debug)]
struct IPCResponse {
    protocol_version: String,
    request_id: String,
    success: bool,
    data: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

struct EngineState {
    sidecar_active: Mutex<bool>,
}

#[tauri::command]
async fn ipc_command(
    request_id: String,
    command: String,
    payload: serde_json::Value,
    _state: State<'_, EngineState>,
) -> Result<serde_json::Value, String> {
    // In compiled distribution, this communicates over stdin/stdout with boundaryx-engine sidecar
    // For Tauri frontend commands, return structured responses
    match command.as_str() {
        "ping" => Ok(serde_json::json!({
            "pong": true,
            "engine": "boundaryx",
            "version": "0.1.0"
        })),
        _ => Ok(serde_json::json!({
            "request_id": request_id,
            "status": "forwarded_to_engine",
            "command": command
        })),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(EngineState {
            sidecar_active: Mutex::new(true),
        })
        .invoke_handler(tauri::generate_handler![ipc_command])
        .run(tauri::generate_context!())
        .expect("error while running BoundaryX Tauri desktop application");
}
