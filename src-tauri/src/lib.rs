//! BreachFrame desktop application (Tauri 2).

pub mod commands;
pub mod db;
pub mod discovery;
pub mod service;

use commands::AppState;
use std::sync::Mutex;
use tauri::Manager;

/// The main window is created in code so that debug builds can expose the
/// WebView2 DevTools protocol for end-to-end tests (`BREACHFRAME_CDP_PORT`).
/// Release builds never enable remote debugging.
fn create_main_window(app: &tauri::App) -> tauri::Result<()> {
    #[allow(unused_mut)]
    let mut builder = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
        .title("BreachFrame")
        .inner_size(1440.0, 900.0)
        .min_inner_size(1024.0, 640.0)
        .center()
        .background_color(tauri::window::Color(11, 14, 20, 255));
    #[cfg(all(debug_assertions, windows))]
    if let Some(port) = std::env::var("BREACHFRAME_CDP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
    {
        builder = builder.additional_browser_args(&format!(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-port={port}"
        ));
    }
    builder.build()?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // BREACHFRAME_DATA_DIR overrides the OS default (portable mode, tests).
            let data_dir = match std::env::var_os("BREACHFRAME_DATA_DIR") {
                Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
                _ => app.path().app_data_dir()?,
            };
            std::fs::create_dir_all(&data_dir)?;
            let db_path = data_dir.join("breachframe.db");
            let conn = db::open(&db_path)
                .map_err(|e| format!("cannot open database {}: {e}", db_path.display()))?;
            app.manage(AppState {
                db: Mutex::new(conn),
                data_dir,
                db_path,
            });
            create_main_window(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::get_dashboard,
            commands::list_activity,
            commands::list_projects,
            commands::get_project,
            commands::create_project,
            commands::update_project,
            commands::delete_project,
            commands::list_artifacts,
            commands::import_files,
            commands::import_text,
            commands::artifact_content,
            commands::remove_artifact,
            commands::run_analysis,
            commands::list_analyses,
            commands::get_analysis,
            commands::delete_analysis,
            commands::compare_analyses,
            commands::simulate,
            commands::list_findings,
            commands::update_finding,
            commands::render_report,
            commands::export_report,
            commands::list_labs,
            commands::run_lab,
            commands::import_lab,
            commands::discover_mcp_configs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running BreachFrame");
}
