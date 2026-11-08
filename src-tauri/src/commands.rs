//! Tauri command handlers: thin wrappers around `service`.
//!
//! All commands run off the main thread (`async`) so long analyses never
//! freeze the window.

use crate::discovery::{self, DiscoveredConfig};
use crate::service::{self as svc, *};
use breachframe_engine::compare::Comparison;
use breachframe_engine::labs::{Lab, LabRun};
use breachframe_engine::simulate::Simulation;
use breachframe_engine::Graph;
use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
}

type Res<T> = std::result::Result<T, AppError>;

fn with_db<T>(state: &State<AppState>, f: impl FnOnce(&mut Connection) -> Res<T>) -> Res<T> {
    let mut guard = state
        .db
        .lock()
        .map_err(|_| AppError::Invalid("database lock poisoned".into()))?;
    f(&mut guard)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub engine_version: String,
    pub data_dir: String,
    pub db_path: String,
    pub os: String,
    pub arch: String,
}

#[tauri::command(async)]
pub fn app_info(state: State<AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        engine_version: breachframe_engine::ENGINE_VERSION.into(),
        data_dir: state.data_dir.display().to_string(),
        db_path: state.db_path.display().to_string(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
    }
}

#[tauri::command(async)]
pub fn get_dashboard(state: State<AppState>) -> Res<Dashboard> {
    with_db(&state, |db| svc::dashboard(db))
}

#[tauri::command(async)]
pub fn list_activity(
    state: State<AppState>,
    project_id: Option<i64>,
    limit: Option<i64>,
) -> Res<Vec<ActivityRow>> {
    with_db(&state, |db| {
        svc::list_activity(db, project_id, limit.unwrap_or(100))
    })
}

#[tauri::command(async)]
pub fn list_projects(state: State<AppState>) -> Res<Vec<ProjectSummary>> {
    with_db(&state, |db| svc::list_projects(db))
}

#[tauri::command(async)]
pub fn get_project(state: State<AppState>, id: i64) -> Res<ProjectSummary> {
    with_db(&state, |db| svc::get_project(db, id))
}

#[tauri::command(async)]
pub fn create_project(
    state: State<AppState>,
    name: String,
    description: Option<String>,
) -> Res<ProjectSummary> {
    with_db(&state, |db| {
        svc::create_project(db, &name, description.as_deref().unwrap_or(""))
    })
}

#[tauri::command(async)]
pub fn update_project(
    state: State<AppState>,
    id: i64,
    name: String,
    description: Option<String>,
) -> Res<ProjectSummary> {
    with_db(&state, |db| {
        svc::rename_project(db, id, &name, description.as_deref().unwrap_or(""))
    })
}

#[tauri::command(async)]
pub fn delete_project(state: State<AppState>, id: i64) -> Res<()> {
    with_db(&state, |db| svc::delete_project(db, id))
}

#[tauri::command(async)]
pub fn list_artifacts(state: State<AppState>, project_id: i64) -> Res<Vec<ArtifactRow>> {
    with_db(&state, |db| svc::list_artifacts(db, project_id))
}

#[tauri::command(async)]
pub fn import_files(
    state: State<AppState>,
    project_id: i64,
    paths: Vec<String>,
) -> Res<Vec<ImportResult>> {
    if paths.len() > 200 {
        return Err(AppError::Invalid(
            "at most 200 files can be imported at once".into(),
        ));
    }
    with_db(&state, |db| {
        Ok(paths
            .iter()
            .map(|p| svc::import_path(db, project_id, std::path::Path::new(p)))
            .collect())
    })
}

#[tauri::command(async)]
pub fn import_text(
    state: State<AppState>,
    project_id: i64,
    name: String,
    content: String,
) -> Res<ArtifactRow> {
    with_db(&state, |db| {
        svc::import_artifact(db, project_id, &name, content.as_bytes(), "pasted")
    })
}

#[tauri::command(async)]
pub fn artifact_content(state: State<AppState>, id: i64) -> Res<String> {
    with_db(&state, |db| svc::artifact_content(db, id))
}

#[tauri::command(async)]
pub fn remove_artifact(state: State<AppState>, id: i64) -> Res<()> {
    with_db(&state, |db| svc::remove_artifact(db, id))
}

#[tauri::command(async)]
pub fn run_analysis(
    state: State<AppState>,
    project_id: i64,
    label: Option<String>,
) -> Res<RunOutcome> {
    with_db(&state, |db| {
        svc::run_analysis(db, project_id, label.as_deref().unwrap_or(""))
    })
}

#[tauri::command(async)]
pub fn list_analyses(state: State<AppState>, project_id: i64) -> Res<Vec<AnalysisRow>> {
    with_db(&state, |db| svc::list_analyses(db, project_id))
}

#[tauri::command(async)]
pub fn get_analysis(state: State<AppState>, id: i64) -> Res<AnalysisDetail> {
    with_db(&state, |db| svc::get_analysis(db, id))
}

#[tauri::command(async)]
pub fn delete_analysis(state: State<AppState>, id: i64) -> Res<()> {
    with_db(&state, |db| svc::delete_analysis(db, id))
}

#[tauri::command(async)]
pub fn compare_analyses(state: State<AppState>, before_id: i64, after_id: i64) -> Res<Comparison> {
    with_db(&state, |db| svc::compare_analyses(db, before_id, after_id))
}

#[tauri::command(async)]
pub fn simulate(graph: Graph, start: String, max_steps: Option<usize>) -> Res<Simulation> {
    svc::simulate_graph(&graph, &start, max_steps)
}

#[tauri::command(async)]
pub fn list_findings(state: State<AppState>, filter: FindingFilter) -> Res<Vec<StoredFinding>> {
    with_db(&state, |db| svc::list_findings(db, &filter))
}

#[tauri::command(async)]
pub fn update_finding(
    state: State<AppState>,
    id: i64,
    status: Option<String>,
    notes: Option<String>,
) -> Res<StoredFinding> {
    with_db(&state, |db| {
        svc::update_finding(db, id, status.as_deref(), notes.as_deref())
    })
}

#[tauri::command(async)]
pub fn render_report(state: State<AppState>, analysis_id: i64, format: String) -> Res<String> {
    with_db(&state, |db| svc::render_report(db, analysis_id, &format))
}

#[tauri::command(async)]
pub fn export_report(
    state: State<AppState>,
    analysis_id: i64,
    format: String,
    path: String,
) -> Res<()> {
    with_db(&state, |db| {
        svc::export_report(db, analysis_id, &format, std::path::Path::new(&path))
    })
}

#[tauri::command(async)]
pub fn list_labs() -> Vec<Lab> {
    svc::list_labs()
}

#[tauri::command(async)]
pub fn run_lab(id: String) -> Res<LabRun> {
    svc::run_lab(&id)
}

#[tauri::command(async)]
pub fn import_lab(state: State<AppState>, id: String) -> Res<ProjectSummary> {
    with_db(&state, |db| svc::import_lab(db, &id))
}

#[tauri::command(async)]
pub fn discover_mcp_configs() -> Vec<DiscoveredConfig> {
    discovery::discover()
}
