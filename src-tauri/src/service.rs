//! Application service layer: projects, artifacts, analyses, findings,
//! reports and labs. Pure Rust over a SQLite connection so it can be unit
//! tested without a Tauri runtime.

use breachframe_engine::compare::{compare, Comparison};
use breachframe_engine::input::limits::MAX_ARTIFACT_BYTES;
use breachframe_engine::labs::{self, Lab, LabRun};
use breachframe_engine::report::{self, ReportMeta};
use breachframe_engine::simulate::{blast_radius, Simulation};
use breachframe_engine::{
    analyze, analyze_artifact, AnalysisResult, ArtifactInput, Finding, Graph, Severity,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(String),
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

pub const STATUSES: [&str; 5] = [
    "open",
    "in_progress",
    "resolved",
    "accepted_risk",
    "false_positive",
];
const MAX_NAME: usize = 120;
const MAX_DESCRIPTION: usize = 2000;
const MAX_NOTES: usize = 10_000;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn sev_rank(s: Severity) -> i64 {
    s as i64
}

fn clean_name(name: &str, what: &str) -> Result<String> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if n.is_empty() {
        return Err(AppError::Invalid(format!("{what} must not be empty")));
    }
    if n.chars().count() > MAX_NAME {
        return Err(AppError::Invalid(format!(
            "{what} must be at most {MAX_NAME} characters"
        )));
    }
    Ok(n)
}

// ---------------------------------------------------------------- types

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub artifact_count: i64,
    pub analysis_count: i64,
    pub latest_analysis_id: Option<i64>,
    pub latest_risk: Option<i64>,
    pub open_findings: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRow {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub kind: String,
    pub sha256: String,
    pub size: i64,
    pub origin: String,
    pub imported_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub name: String,
    pub artifact: Option<ArtifactRow>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRow {
    pub id: i64,
    pub project_id: i64,
    pub created_at: i64,
    pub label: String,
    pub risk_score: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub nodes: i64,
    pub edges: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDetail {
    pub row: AnalysisRow,
    pub result: AnalysisResult,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RunOutcome {
    pub analysis: AnalysisRow,
    pub new_findings: i64,
    pub resolved_findings: i64,
    pub reopened_findings: i64,
    pub artifact_errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StoredFinding {
    pub id: i64,
    pub project_id: i64,
    pub project_name: String,
    pub status: String,
    pub notes: String,
    pub present: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_analysis_id: i64,
    pub finding: Finding,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct FindingFilter {
    pub project_id: Option<i64>,
    pub severities: Vec<String>,
    pub statuses: Vec<String>,
    pub categories: Vec<String>,
    pub search: Option<String>,
    pub include_absent: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ActivityRow {
    pub id: i64,
    pub project_id: Option<i64>,
    pub project_name: Option<String>,
    pub ts: i64,
    pub kind: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecentAnalysis {
    pub id: i64,
    pub project_id: i64,
    pub project_name: String,
    pub created_at: i64,
    pub risk_score: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub projects: i64,
    pub artifacts: i64,
    pub analyses: i64,
    pub open_by_severity: BTreeMap<String, i64>,
    pub by_status: BTreeMap<String, i64>,
    pub by_category: BTreeMap<String, i64>,
    pub top_rules: Vec<(String, i64)>,
    pub recent_analyses: Vec<RecentAnalysis>,
    pub activity: Vec<ActivityRow>,
}

// ------------------------------------------------------------- activity

pub fn log(db: &Connection, project_id: Option<i64>, kind: &str, message: &str) -> Result<()> {
    db.execute(
        "INSERT INTO activity(project_id, ts, kind, message) VALUES (?1, ?2, ?3, ?4)",
        params![project_id, now_ms(), kind, message],
    )?;
    Ok(())
}

pub fn list_activity(
    db: &Connection,
    project_id: Option<i64>,
    limit: i64,
) -> Result<Vec<ActivityRow>> {
    let mut stmt = db.prepare(
        "SELECT a.id, a.project_id, p.name, a.ts, a.kind, a.message FROM activity a
         LEFT JOIN projects p ON p.id = a.project_id
         WHERE (?1 IS NULL OR a.project_id = ?1) ORDER BY a.ts DESC, a.id DESC LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![project_id, limit.clamp(1, 500)], |r| {
            Ok(ActivityRow {
                id: r.get(0)?,
                project_id: r.get(1)?,
                project_name: r.get(2)?,
                ts: r.get(3)?,
                kind: r.get(4)?,
                message: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ------------------------------------------------------------- projects

pub fn create_project(db: &Connection, name: &str, description: &str) -> Result<ProjectSummary> {
    let name = clean_name(name, "Project name")?;
    let description: String = description.trim().chars().take(MAX_DESCRIPTION).collect();
    let now = now_ms();
    db.execute(
        "INSERT INTO projects(name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        params![name, description, now],
    )?;
    let id = db.last_insert_rowid();
    log(
        db,
        Some(id),
        "project",
        &format!("Created project “{name}”"),
    )?;
    get_project(db, id)
}

pub fn rename_project(
    db: &Connection,
    id: i64,
    name: &str,
    description: &str,
) -> Result<ProjectSummary> {
    let name = clean_name(name, "Project name")?;
    let description: String = description.trim().chars().take(MAX_DESCRIPTION).collect();
    let n = db.execute(
        "UPDATE projects SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
        params![name, description, now_ms(), id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound(format!("project {id}")));
    }
    get_project(db, id)
}

pub fn delete_project(db: &Connection, id: i64) -> Result<()> {
    let name: Option<String> = db
        .query_row("SELECT name FROM projects WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    let Some(name) = name else {
        return Err(AppError::NotFound(format!("project {id}")));
    };
    db.execute("DELETE FROM projects WHERE id = ?1", [id])?;
    log(db, None, "project", &format!("Deleted project “{name}”"))?;
    Ok(())
}

const PROJECT_SELECT: &str = "SELECT p.id, p.name, p.description, p.created_at, p.updated_at,
    (SELECT COUNT(*) FROM artifacts a WHERE a.project_id = p.id),
    (SELECT COUNT(*) FROM analyses an WHERE an.project_id = p.id),
    (SELECT id FROM analyses an WHERE an.project_id = p.id ORDER BY created_at DESC, id DESC LIMIT 1),
    (SELECT risk_score FROM analyses an WHERE an.project_id = p.id ORDER BY created_at DESC, id DESC LIMIT 1),
    (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.present = 1 AND f.status IN ('open','in_progress'))
    FROM projects p";

fn project_from_row(r: &rusqlite::Row) -> rusqlite::Result<ProjectSummary> {
    Ok(ProjectSummary {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
        artifact_count: r.get(5)?,
        analysis_count: r.get(6)?,
        latest_analysis_id: r.get(7)?,
        latest_risk: r.get(8)?,
        open_findings: r.get(9)?,
    })
}

pub fn list_projects(db: &Connection) -> Result<Vec<ProjectSummary>> {
    let mut stmt = db.prepare(&format!(
        "{PROJECT_SELECT} ORDER BY p.updated_at DESC, p.id DESC"
    ))?;
    let rows = stmt
        .query_map([], project_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_project(db: &Connection, id: i64) -> Result<ProjectSummary> {
    db.query_row(
        &format!("{PROJECT_SELECT} WHERE p.id = ?1"),
        [id],
        project_from_row,
    )
    .optional()?
    .ok_or_else(|| AppError::NotFound(format!("project {id}")))
}

fn touch(db: &Connection, project_id: i64) -> Result<()> {
    db.execute(
        "UPDATE projects SET updated_at = ?1 WHERE id = ?2",
        params![now_ms(), project_id],
    )?;
    Ok(())
}

// ------------------------------------------------------------ artifacts

fn artifact_from_row(r: &rusqlite::Row) -> rusqlite::Result<ArtifactRow> {
    Ok(ArtifactRow {
        id: r.get(0)?,
        project_id: r.get(1)?,
        name: r.get(2)?,
        kind: r.get(3)?,
        sha256: r.get(4)?,
        size: r.get(5)?,
        origin: r.get(6)?,
        imported_at: r.get(7)?,
    })
}

/// Validate and store an artifact. Content is parsed (never executed) to make
/// sure it is a supported format before it is accepted.
pub fn import_artifact(
    db: &Connection,
    project_id: i64,
    name: &str,
    content: &[u8],
    origin: &str,
) -> Result<ArtifactRow> {
    get_project(db, project_id)?;
    let name = clean_name(name, "File name")?;
    let input = ArtifactInput::new(name.clone(), content.to_vec());
    let (kind, _) =
        analyze_artifact(&input).map_err(|e| AppError::Invalid(format!("{name}: {e}")))?;
    let kind_s = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let sha = breachframe_engine::util::sha256_hex(content);
    let dup: Option<i64> = db
        .query_row(
            "SELECT id FROM artifacts WHERE project_id = ?1 AND sha256 = ?2",
            params![project_id, sha],
            |r| r.get(0),
        )
        .optional()?;
    if dup.is_some() {
        return Err(AppError::Invalid(format!(
            "{name}: an identical file is already in this project"
        )));
    }
    db.execute(
        "INSERT INTO artifacts(project_id, name, kind, sha256, size, content, origin, imported_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![project_id, name, kind_s, sha, content.len() as i64, content, origin, now_ms()],
    )?;
    let id = db.last_insert_rowid();
    touch(db, project_id)?;
    log(
        db,
        Some(project_id),
        "import",
        &format!("Imported {name} ({})", kind.label()),
    )?;
    db.query_row(
        "SELECT id, project_id, name, kind, sha256, size, origin, imported_at FROM artifacts WHERE id = ?1",
        [id],
        artifact_from_row,
    )
    .map_err(Into::into)
}

/// Read a file from disk with size limits, then import it.
pub fn import_path(db: &Connection, project_id: i64, path: &Path) -> ImportResult {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let result = (|| {
        let meta = std::fs::metadata(path).map_err(|e| AppError::Io(format!("{name}: {e}")))?;
        if !meta.is_file() {
            return Err(AppError::Invalid(format!("{name}: not a regular file")));
        }
        if meta.len() > MAX_ARTIFACT_BYTES as u64 {
            return Err(AppError::Invalid(format!(
                "{name}: file is larger than the 5 MiB limit"
            )));
        }
        let bytes = std::fs::read(path).map_err(|e| AppError::Io(format!("{name}: {e}")))?;
        import_artifact(db, project_id, &name, &bytes, "file")
    })();
    match result {
        Ok(a) => ImportResult {
            name,
            artifact: Some(a),
            error: None,
        },
        Err(e) => ImportResult {
            name,
            artifact: None,
            error: Some(e.to_string()),
        },
    }
}

pub fn list_artifacts(db: &Connection, project_id: i64) -> Result<Vec<ArtifactRow>> {
    let mut stmt = db.prepare(
        "SELECT id, project_id, name, kind, sha256, size, origin, imported_at FROM artifacts WHERE project_id = ?1 ORDER BY imported_at, id",
    )?;
    let rows = stmt
        .query_map([project_id], artifact_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn artifact_content(db: &Connection, artifact_id: i64) -> Result<String> {
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT content FROM artifacts WHERE id = ?1",
            [artifact_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("artifact {artifact_id}")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn remove_artifact(db: &Connection, artifact_id: i64) -> Result<()> {
    let row: Option<(i64, String)> = db
        .query_row(
            "SELECT project_id, name FROM artifacts WHERE id = ?1",
            [artifact_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((pid, name)) = row else {
        return Err(AppError::NotFound(format!("artifact {artifact_id}")));
    };
    db.execute("DELETE FROM artifacts WHERE id = ?1", [artifact_id])?;
    touch(db, pid)?;
    log(db, Some(pid), "import", &format!("Removed {name}"))?;
    Ok(())
}

// ------------------------------------------------------------- analyses

fn analysis_from_row(r: &rusqlite::Row) -> rusqlite::Result<AnalysisRow> {
    Ok(AnalysisRow {
        id: r.get(0)?,
        project_id: r.get(1)?,
        created_at: r.get(2)?,
        label: r.get(3)?,
        risk_score: r.get(4)?,
        critical: r.get(5)?,
        high: r.get(6)?,
        medium: r.get(7)?,
        low: r.get(8)?,
        info: r.get(9)?,
        nodes: r.get(10)?,
        edges: r.get(11)?,
    })
}

const ANALYSIS_COLS: &str = "id, project_id, created_at, label, risk_score, critical, high, medium, low, info, nodes, edges";

/// Analyse every artifact in the project, store the snapshot and reconcile
/// the findings register (new / still present / resolved / regressed).
pub fn run_analysis(db: &mut Connection, project_id: i64, label: &str) -> Result<RunOutcome> {
    let project = get_project(db, project_id)?;
    let inputs: Vec<ArtifactInput> = {
        let mut stmt = db.prepare(
            "SELECT name, content FROM artifacts WHERE project_id = ?1 ORDER BY imported_at, id",
        )?;
        let rows = stmt
            .query_map([project_id], |r| {
                Ok(ArtifactInput::new(
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if inputs.is_empty() {
        return Err(AppError::Invalid(
            "Import at least one artifact before running an analysis".into(),
        ));
    }
    let now = now_ms();
    let result = analyze(&inputs, now);
    let count = |s: Severity| *result.stats.by_severity.get(&s).unwrap_or(&0) as i64;
    let label: String = label.trim().chars().take(MAX_NAME).collect();

    let tx = db.transaction()?;
    tx.execute(
        "INSERT INTO analyses(project_id, created_at, label, risk_score, critical, high, medium, low, info, nodes, edges, result_json)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            project_id,
            now,
            label,
            result.risk_score as i64,
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium),
            count(Severity::Low),
            count(Severity::Info),
            result.stats.nodes as i64,
            result.stats.edges as i64,
            serde_json::to_string(&result).map_err(|e| AppError::Invalid(e.to_string()))?
        ],
    )?;
    let analysis_id = tx.last_insert_rowid();

    let existing: HashMap<String, (i64, String, bool)> = {
        let mut stmt = tx.prepare(
            "SELECT fingerprint, id, status, present FROM findings WHERE project_id = ?1",
        )?;
        let rows = stmt
            .query_map([project_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    (
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)? == 1,
                    ),
                ))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?;
        rows
    };
    let mut new_findings = 0;
    let mut reopened = 0;
    let mut seen = HashSet::new();
    for f in &result.findings {
        seen.insert(f.id.clone());
        let data = serde_json::to_string(f).map_err(|e| AppError::Invalid(e.to_string()))?;
        let category = serde_json::to_value(f.category)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        match existing.get(&f.id) {
            None => {
                new_findings += 1;
                tx.execute(
                    "INSERT INTO findings(project_id, fingerprint, rule_id, title, severity, severity_rank, category, status, present, first_seen, last_seen, last_analysis_id, data_json)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,'open',1,?8,?8,?9,?10)",
                    params![project_id, f.id, f.rule_id, f.title, f.severity.as_str(), sev_rank(f.severity), category, now, analysis_id, data],
                )?;
            }
            Some((id, status, _present)) => {
                let new_status = if status == "resolved" {
                    reopened += 1;
                    "open"
                } else {
                    status.as_str()
                };
                tx.execute(
                    "UPDATE findings SET rule_id=?1, title=?2, severity=?3, severity_rank=?4, category=?5, status=?6, present=1, last_seen=?7, last_analysis_id=?8, data_json=?9 WHERE id=?10",
                    params![f.rule_id, f.title, f.severity.as_str(), sev_rank(f.severity), category, new_status, now, analysis_id, data, id],
                )?;
            }
        }
    }
    let mut resolved = 0;
    for (fp, (id, status, present)) in &existing {
        if seen.contains(fp) || !*present {
            continue;
        }
        let new_status = if status == "open" || status == "in_progress" {
            resolved += 1;
            "resolved"
        } else {
            status.as_str()
        };
        tx.execute(
            "UPDATE findings SET present = 0, status = ?1 WHERE id = ?2",
            params![new_status, id],
        )?;
    }
    tx.execute(
        "UPDATE projects SET updated_at = ?1 WHERE id = ?2",
        params![now, project_id],
    )?;
    tx.commit()?;

    let artifact_errors: Vec<String> = result
        .artifacts
        .iter()
        .filter_map(|a| a.error.as_ref().map(|e| format!("{}: {e}", a.name)))
        .collect();
    log(
        db,
        Some(project_id),
        "analysis",
        &format!(
            "Analysis #{analysis_id} of “{}”: risk {} · {} findings ({} new, {} resolved, {} reopened)",
            project.name,
            result.risk_score,
            result.findings.len(),
            new_findings,
            resolved,
            reopened
        ),
    )?;
    let analysis = db.query_row(
        &format!("SELECT {ANALYSIS_COLS} FROM analyses WHERE id = ?1"),
        [analysis_id],
        analysis_from_row,
    )?;
    Ok(RunOutcome {
        analysis,
        new_findings,
        resolved_findings: resolved,
        reopened_findings: reopened,
        artifact_errors,
    })
}

pub fn list_analyses(db: &Connection, project_id: i64) -> Result<Vec<AnalysisRow>> {
    let mut stmt = db.prepare(&format!("SELECT {ANALYSIS_COLS} FROM analyses WHERE project_id = ?1 ORDER BY created_at DESC, id DESC"))?;
    let rows = stmt
        .query_map([project_id], analysis_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_analysis(db: &Connection, analysis_id: i64) -> Result<AnalysisDetail> {
    let (row, json): (AnalysisRow, String) = db
        .query_row(
            &format!("SELECT {ANALYSIS_COLS}, result_json FROM analyses WHERE id = ?1"),
            [analysis_id],
            |r| Ok((analysis_from_row(r)?, r.get(12)?)),
        )
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("analysis {analysis_id}")))?;
    let result: AnalysisResult = serde_json::from_str(&json)
        .map_err(|e| AppError::Invalid(format!("stored analysis is corrupt: {e}")))?;
    Ok(AnalysisDetail { row, result })
}

pub fn delete_analysis(db: &Connection, analysis_id: i64) -> Result<()> {
    let n = db.execute("DELETE FROM analyses WHERE id = ?1", [analysis_id])?;
    if n == 0 {
        return Err(AppError::NotFound(format!("analysis {analysis_id}")));
    }
    Ok(())
}

pub fn compare_analyses(db: &Connection, before_id: i64, after_id: i64) -> Result<Comparison> {
    let b = get_analysis(db, before_id)?;
    let a = get_analysis(db, after_id)?;
    Ok(compare(&b.result, &a.result))
}

pub fn simulate_graph(graph: &Graph, start: &str, max_steps: Option<usize>) -> Result<Simulation> {
    blast_radius(graph, start, max_steps).ok_or_else(|| AppError::NotFound(format!("node {start}")))
}

// ------------------------------------------------------------- findings

fn finding_from_row(r: &rusqlite::Row) -> rusqlite::Result<(StoredFinding, String)> {
    let data: String = r.get(9)?;
    Ok((
        StoredFinding {
            id: r.get(0)?,
            project_id: r.get(1)?,
            project_name: r.get(2)?,
            status: r.get(3)?,
            notes: r.get(4)?,
            present: r.get::<_, i64>(5)? == 1,
            first_seen: r.get(6)?,
            last_seen: r.get(7)?,
            last_analysis_id: r.get(8)?,
            finding: serde_json::from_str(&data).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        },
        data,
    ))
}

pub fn list_findings(db: &Connection, filter: &FindingFilter) -> Result<Vec<StoredFinding>> {
    let mut stmt = db.prepare(
        "SELECT f.id, f.project_id, p.name, f.status, f.notes, f.present, f.first_seen, f.last_seen, f.last_analysis_id, f.data_json, f.severity, f.category
         FROM findings f JOIN projects p ON p.id = f.project_id
         WHERE (?1 IS NULL OR f.project_id = ?1) AND (?2 = 1 OR f.present = 1)
         ORDER BY f.present DESC, f.severity_rank DESC, f.last_seen DESC, f.id",
    )?;
    let search = filter
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    let mut out = Vec::new();
    let rows = stmt.query_map(
        params![filter.project_id, filter.include_absent as i64],
        |r| {
            let (f, data) = finding_from_row(r)?;
            Ok((f, data, r.get::<_, String>(10)?, r.get::<_, String>(11)?))
        },
    )?;
    for row in rows {
        let (f, data, severity, category) = row?;
        if !filter.severities.is_empty() && !filter.severities.contains(&severity) {
            continue;
        }
        if !filter.statuses.is_empty() && !filter.statuses.contains(&f.status) {
            continue;
        }
        if !filter.categories.is_empty() && !filter.categories.contains(&category) {
            continue;
        }
        if let Some(q) = &search {
            if !data.to_lowercase().contains(q) && !f.notes.to_lowercase().contains(q) {
                continue;
            }
        }
        out.push(f);
    }
    Ok(out)
}

pub fn update_finding(
    db: &Connection,
    id: i64,
    status: Option<&str>,
    notes: Option<&str>,
) -> Result<StoredFinding> {
    let row: Option<(i64, String, String)> = db
        .query_row(
            "SELECT project_id, title, status FROM findings WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((pid, title, old_status)) = row else {
        return Err(AppError::NotFound(format!("finding {id}")));
    };
    if let Some(s) = status {
        if !STATUSES.contains(&s) {
            return Err(AppError::Invalid(format!("unknown status `{s}`")));
        }
        db.execute(
            "UPDATE findings SET status = ?1 WHERE id = ?2",
            params![s, id],
        )?;
        if s != old_status {
            log(
                db,
                Some(pid),
                "finding",
                &format!(
                    "“{}” → {}",
                    breachframe_engine::util::clip(&title, 80),
                    s.replace('_', " ")
                ),
            )?;
        }
    }
    if let Some(n) = notes {
        if n.chars().count() > MAX_NOTES {
            return Err(AppError::Invalid(format!(
                "notes must be at most {MAX_NOTES} characters"
            )));
        }
        db.execute(
            "UPDATE findings SET notes = ?1 WHERE id = ?2",
            params![n, id],
        )?;
    }
    let f = db.query_row(
        "SELECT f.id, f.project_id, p.name, f.status, f.notes, f.present, f.first_seen, f.last_seen, f.last_analysis_id, f.data_json
         FROM findings f JOIN projects p ON p.id = f.project_id WHERE f.id = ?1",
        [id],
        finding_from_row,
    )?;
    Ok(f.0)
}

// ------------------------------------------------------------ dashboard

pub fn dashboard(db: &Connection) -> Result<Dashboard> {
    let scalar = |sql: &str| -> Result<i64> { Ok(db.query_row(sql, [], |r| r.get(0))?) };
    let mut open_by_severity = BTreeMap::new();
    for s in ["critical", "high", "medium", "low", "info"] {
        open_by_severity.insert(s.to_string(), 0);
    }
    {
        let mut stmt = db.prepare("SELECT severity, COUNT(*) FROM findings WHERE present = 1 AND status IN ('open','in_progress') GROUP BY severity")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = row?;
            open_by_severity.insert(k, v);
        }
    }
    let mut by_status = BTreeMap::new();
    for s in STATUSES {
        by_status.insert(s.to_string(), 0);
    }
    {
        let mut stmt = db.prepare("SELECT status, COUNT(*) FROM findings GROUP BY status")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = row?;
            by_status.insert(k, v);
        }
    }
    let mut by_category = BTreeMap::new();
    {
        let mut stmt = db.prepare("SELECT category, COUNT(*) FROM findings WHERE present = 1 AND status IN ('open','in_progress') GROUP BY category")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, v) = row?;
            by_category.insert(k, v);
        }
    }
    let top_rules = {
        let mut stmt = db.prepare(
            "SELECT CASE WHEN rule_id LIKE 'POLICY:%' THEN 'POLICY' ELSE rule_id END AS r, COUNT(*) c FROM findings
             WHERE present = 1 AND status IN ('open','in_progress') GROUP BY r ORDER BY c DESC, r LIMIT 8",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let recent_analyses = {
        let mut stmt = db.prepare(
            "SELECT a.id, a.project_id, p.name, a.created_at, a.risk_score, a.critical, a.high, a.medium, a.low
             FROM analyses a JOIN projects p ON p.id = a.project_id ORDER BY a.created_at DESC, a.id DESC LIMIT 30",
        )?;
        let mut rows = stmt
            .query_map([], |r| {
                Ok(RecentAnalysis {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    project_name: r.get(2)?,
                    created_at: r.get(3)?,
                    risk_score: r.get(4)?,
                    critical: r.get(5)?,
                    high: r.get(6)?,
                    medium: r.get(7)?,
                    low: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        rows
    };
    Ok(Dashboard {
        projects: scalar("SELECT COUNT(*) FROM projects")?,
        artifacts: scalar("SELECT COUNT(*) FROM artifacts")?,
        analyses: scalar("SELECT COUNT(*) FROM analyses")?,
        open_by_severity,
        by_status,
        by_category,
        top_rules,
        recent_analyses,
        activity: list_activity(db, None, 12)?,
    })
}

// -------------------------------------------------------------- reports

pub fn render_report(db: &Connection, analysis_id: i64, format: &str) -> Result<String> {
    let detail = get_analysis(db, analysis_id)?;
    let project = get_project(db, detail.row.project_id)?;
    let mut statuses = HashMap::new();
    let mut notes = HashMap::new();
    {
        let mut stmt =
            db.prepare("SELECT fingerprint, status, notes FROM findings WHERE project_id = ?1")?;
        for row in stmt.query_map([project.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (fp, s, n) = row?;
            statuses.insert(fp.clone(), s);
            if !n.is_empty() {
                notes.insert(fp, n);
            }
        }
    }
    let meta = ReportMeta {
        tool: "BreachFrame".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        project: project.name,
        generated_at: now_ms(),
        statuses,
        notes,
    };
    match format {
        "html" => Ok(report::to_html(meta, &detail.result)),
        "json" => Ok(report::to_json(meta, &detail.result)),
        other => Err(AppError::Invalid(format!(
            "unsupported report format `{other}`"
        ))),
    }
}

pub fn export_report(db: &Connection, analysis_id: i64, format: &str, path: &Path) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if ext.as_deref() != Some(format) {
        return Err(AppError::Invalid(format!(
            "the file name must end with .{format}"
        )));
    }
    let content = render_report(db, analysis_id, format)?;
    std::fs::write(path, content).map_err(|e| AppError::Io(e.to_string()))?;
    let pid: i64 = db.query_row(
        "SELECT project_id FROM analyses WHERE id = ?1",
        [analysis_id],
        |r| r.get(0),
    )?;
    log(
        db,
        Some(pid),
        "report",
        &format!(
            "Exported {} report to {}",
            format.to_uppercase(),
            path.display()
        ),
    )?;
    Ok(())
}

// ----------------------------------------------------------------- labs

pub fn list_labs() -> Vec<Lab> {
    labs::all()
}

pub fn run_lab(id: &str) -> Result<LabRun> {
    labs::run(id, now_ms()).ok_or_else(|| AppError::NotFound(format!("lab {id}")))
}

/// Create a project from a lab: analyse the vulnerable variant, then replace
/// the artifacts with the fixed variant and analyse again, so the project's
/// history and Before & After view show the remediation.
pub fn import_lab(db: &mut Connection, id: &str) -> Result<ProjectSummary> {
    let lab = labs::get(id).ok_or_else(|| AppError::NotFound(format!("lab {id}")))?;
    let project = create_project(db, &format!("Lab · {}", lab.title), &lab.summary)?;
    for a in &lab.vulnerable {
        import_artifact(
            db,
            project.id,
            &a.name,
            a.content.as_bytes(),
            "lab:vulnerable",
        )?;
    }
    run_analysis(db, project.id, "Vulnerable")?;
    db.execute("DELETE FROM artifacts WHERE project_id = ?1", [project.id])?;
    for a in &lab.fixed {
        import_artifact(db, project.id, &a.name, a.content.as_bytes(), "lab:fixed")?;
    }
    run_analysis(db, project.id, "Fixed")?;
    get_project(db, project.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    const ADMIN: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    const SCOPED: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}"#;

    #[test]
    fn project_crud_and_validation() {
        let db = open_in_memory().unwrap();
        assert!(create_project(&db, "   ", "").is_err());
        assert!(create_project(&db, &"x".repeat(200), "").is_err());
        let p = create_project(&db, "  Prod audit ", "desc").unwrap();
        assert_eq!(p.name, "Prod audit");
        assert_eq!(list_projects(&db).unwrap().len(), 1);
        let p = rename_project(&db, p.id, "Prod", "d2").unwrap();
        assert_eq!(p.name, "Prod");
        delete_project(&db, p.id).unwrap();
        assert!(list_projects(&db).unwrap().is_empty());
        assert!(delete_project(&db, p.id).is_err());
    }

    #[test]
    fn import_rejects_invalid_and_duplicate_files() {
        let db = open_in_memory().unwrap();
        let p = create_project(&db, "P", "").unwrap();
        assert!(import_artifact(&db, p.id, "x.bin", &[0, 1, 2], "file").is_err());
        assert!(import_artifact(&db, p.id, "x.yaml", b"hello: world", "file").is_err());
        let a = import_artifact(&db, p.id, "admin.json", ADMIN.as_bytes(), "file").unwrap();
        assert_eq!(a.kind, "aws_iam");
        assert!(import_artifact(&db, p.id, "again.json", ADMIN.as_bytes(), "file").is_err());
        assert!(import_artifact(&db, 9999, "a.json", ADMIN.as_bytes(), "file").is_err());
    }

    #[test]
    fn import_path_enforces_limits() {
        let db = open_in_memory().unwrap();
        let p = create_project(&db, "P", "").unwrap();
        let dir = std::env::temp_dir().join(format!("bf-test-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("policy.json");
        std::fs::write(&ok, ADMIN).unwrap();
        assert!(import_path(&db, p.id, &ok).artifact.is_some());
        let r = import_path(&db, p.id, &dir);
        assert!(r.error.unwrap().contains("not a regular file"));
        let r = import_path(&db, p.id, &dir.join("missing.json"));
        assert!(r.error.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn analysis_lifecycle_tracks_finding_status() {
        let mut db = open_in_memory().unwrap();
        let p = create_project(&db, "P", "").unwrap();
        assert!(run_analysis(&mut db, p.id, "").is_err(), "empty project");
        let a = import_artifact(&db, p.id, "admin.json", ADMIN.as_bytes(), "file").unwrap();
        let r1 = run_analysis(&mut db, p.id, "first").unwrap();
        assert_eq!(r1.new_findings, 1);
        assert_eq!(r1.analysis.critical, 1);

        let all = list_findings(
            &db,
            &FindingFilter {
                project_id: Some(p.id),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(all.len(), 1);
        let f = update_finding(&db, all[0].id, Some("in_progress"), Some("ticket SEC-1")).unwrap();
        assert_eq!(f.status, "in_progress");
        assert!(update_finding(&db, f.id, Some("bogus"), None).is_err());

        // Re-running keeps the workflow status.
        let r2 = run_analysis(&mut db, p.id, "").unwrap();
        assert_eq!(r2.new_findings, 0);
        let f = &list_findings(&db, &FindingFilter::default()).unwrap()[0];
        assert_eq!(f.status, "in_progress");
        assert_eq!(f.notes, "ticket SEC-1");

        // Fix: replace the admin policy with a scoped one.
        remove_artifact(&db, a.id).unwrap();
        import_artifact(&db, p.id, "scoped.json", SCOPED.as_bytes(), "file").unwrap();
        let r3 = run_analysis(&mut db, p.id, "").unwrap();
        assert_eq!(r3.resolved_findings, 1);
        assert_eq!(r3.analysis.risk_score, 0);
        assert!(list_findings(&db, &FindingFilter::default())
            .unwrap()
            .is_empty());
        let hist = list_findings(
            &db,
            &FindingFilter {
                include_absent: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(hist[0].status, "resolved");
        assert!(!hist[0].present);

        // Regression: the admin policy comes back.
        import_artifact(&db, p.id, "admin.json", ADMIN.as_bytes(), "file").unwrap();
        let r4 = run_analysis(&mut db, p.id, "").unwrap();
        assert_eq!(r4.reopened_findings, 1);

        let cmp = compare_analyses(&db, r1.analysis.id, r3.analysis.id).unwrap();
        assert_eq!(cmp.resolved.len(), 1);
        assert_eq!(cmp.risk_before, 35);
        assert_eq!(cmp.risk_after, 0);
        assert_eq!(list_analyses(&db, p.id).unwrap().len(), 4);
    }

    #[test]
    fn filters_work() {
        let mut db = open_in_memory().unwrap();
        let p = create_project(&db, "P", "").unwrap();
        for lab in labs::all().iter().take(1) {
            for a in &lab.vulnerable {
                import_artifact(&db, p.id, &a.name, a.content.as_bytes(), "lab").unwrap();
            }
        }
        run_analysis(&mut db, p.id, "").unwrap();
        let all = list_findings(&db, &FindingFilter::default()).unwrap();
        assert!(all.len() > 3);
        let crit = list_findings(
            &db,
            &FindingFilter {
                severities: vec!["critical".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(crit
            .iter()
            .all(|f| f.finding.severity == Severity::Critical));
        assert!(!crit.is_empty());
        let mcp = list_findings(
            &db,
            &FindingFilter {
                categories: vec!["mcp".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(mcp.iter().all(|f| f.finding.rule_id.starts_with("MCP-")));
        let q = list_findings(
            &db,
            &FindingFilter {
                search: Some("unpinned".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!q.is_empty() && q.len() < all.len());
    }

    #[test]
    fn dashboard_and_reports() {
        let mut db = open_in_memory().unwrap();
        let p = import_lab(&mut db, "api-bola").unwrap();
        assert_eq!(p.analysis_count, 2);
        let d = dashboard(&db).unwrap();
        assert_eq!(d.projects, 1);
        assert_eq!(d.analyses, 2);
        assert_eq!(d.recent_analyses.len(), 2);
        assert!(d.recent_analyses[0].risk_score > d.recent_analyses[1].risk_score);
        assert!(!d.activity.is_empty());

        let analyses = list_analyses(&db, p.id).unwrap();
        let vuln = analyses.iter().find(|a| a.label == "Vulnerable").unwrap();
        let html = render_report(&db, vuln.id, "html").unwrap();
        assert!(html.contains("P-TENANT-01"));
        let json = render_report(&db, vuln.id, "json").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!v["analysis"]["findings"].as_array().unwrap().is_empty());
        assert!(render_report(&db, vuln.id, "pdf").is_err());

        let out = std::env::temp_dir().join(format!("bf-report-{}.html", now_ms()));
        export_report(&db, vuln.id, "html", &out).unwrap();
        assert!(std::fs::read_to_string(&out)
            .unwrap()
            .starts_with("<!doctype html>"));
        std::fs::remove_file(&out).ok();
        assert!(export_report(&db, vuln.id, "json", &std::env::temp_dir().join("x.html")).is_err());
    }

    #[test]
    fn simulation_and_deletes_cascade() {
        let mut db = open_in_memory().unwrap();
        let p = import_lab(&mut db, "k8s-ci-escalation").unwrap();
        let analyses = list_analyses(&db, p.id).unwrap();
        let vuln = analyses.iter().find(|a| a.label == "Vulnerable").unwrap();
        let detail = get_analysis(&db, vuln.id).unwrap();
        let sim = simulate_graph(&detail.result.graph, "agent:pr-pipeline", None).unwrap();
        assert!(!sim.reached_sensitive.is_empty());
        assert!(simulate_graph(&detail.result.graph, "nope", None).is_err());
        delete_project(&db, p.id).unwrap();
        let n: i64 = db
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        let n: i64 = db
            .query_row("SELECT COUNT(*) FROM analyses", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn migrations_are_idempotent() {
        let dir = std::env::temp_dir().join(format!("bf-db-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        {
            let db = crate::db::open(&path).unwrap();
            create_project(&db, "keep", "").unwrap();
        }
        let db = crate::db::open(&path).unwrap();
        assert_eq!(list_projects(&db).unwrap()[0].name, "keep");
        drop(db);
        std::fs::remove_dir_all(&dir).ok();
    }
}
