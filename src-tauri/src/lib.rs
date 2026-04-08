// IRVES — Tauri Shell
// Spawns the FastAPI backend (uvicorn) on launch and terminates it on close.

use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, RunEvent};

struct BackendProcess(Mutex<Option<Child>>);

#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(BackendProcess(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![get_version])
        .setup(|app| {
            let handle: AppHandle = app.handle().clone();
            let backend_state = handle.state::<BackendProcess>();

            // Resolve the backend directory relative to the app resources
            let backend_dir = std::env::current_dir()
                .unwrap()
                .join("backend");

            println!("[IRVES] Spawning FastAPI backend at {:?}", backend_dir);

            match Command::new("python3")
                .args(["-m", "uvicorn", "main:app",
                       "--host", "127.0.0.1",
                       "--port", "8765",
                       "--log-level", "warning"])
                .current_dir(&backend_dir)
                .spawn()
            {
                Ok(child) => {
                    println!("[IRVES] Backend process started (PID: {})", child.id());
                    *backend_state.0.lock().unwrap() = Some(child);
                }
                Err(e) => {
                    eprintln!("[IRVES] Failed to start backend: {e}");
                    eprintln!("[IRVES] Ensure Python 3 and uvicorn are installed.");
                }
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build IRVES application")
        .run(|app, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Gracefully terminate the Python backend
                let state = app.state::<BackendProcess>();
                if let Some(mut child) = state.0.lock().unwrap().take() {
                    println!("[IRVES] Terminating backend process (PID: {})", child.id());
                    let _ = child.kill();
                }
            }
        });
}
