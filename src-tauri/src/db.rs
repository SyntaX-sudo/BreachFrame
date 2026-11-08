//! SQLite storage. One database file per user in the OS application-data
//! directory. Schema migrations are versioned with `PRAGMA user_version`.

use rusqlite::Connection;
use std::path::Path;

pub type Db = Connection;

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE projects (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE artifacts (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        content BLOB NOT NULL,
        origin TEXT NOT NULL DEFAULT 'file',
        imported_at INTEGER NOT NULL
    );
    CREATE INDEX artifacts_project ON artifacts(project_id);
    CREATE TABLE analyses (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        risk_score INTEGER NOT NULL,
        critical INTEGER NOT NULL,
        high INTEGER NOT NULL,
        medium INTEGER NOT NULL,
        low INTEGER NOT NULL,
        info INTEGER NOT NULL,
        nodes INTEGER NOT NULL,
        edges INTEGER NOT NULL,
        result_json TEXT NOT NULL
    );
    CREATE INDEX analyses_project ON analyses(project_id, created_at);
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        severity_rank INTEGER NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        notes TEXT NOT NULL DEFAULT '',
        present INTEGER NOT NULL DEFAULT 1,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        last_analysis_id INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        UNIQUE(project_id, fingerprint)
    );
    CREATE INDEX findings_project ON findings(project_id, severity_rank);
    CREATE TABLE activity (
        id INTEGER PRIMARY KEY,
        project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        message TEXT NOT NULL
    );
    CREATE INDEX activity_ts ON activity(ts);
    "#,
];

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")?;
    Ok(())
}

pub fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    Ok(())
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    configure(&conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    configure(&conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}
