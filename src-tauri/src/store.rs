//! Local SQLite store. Lives in ~/Library/Application Support/CryptiQ Personal.
//! Asset inventory, scan history, and the remediation log never leave this file.

use crate::scanner::Finding;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Store(pub Mutex<Connection>);

#[derive(Serialize)]
pub struct RemediationEntry {
    pub id: i64,
    pub finding_id: String,
    pub action: String,
    pub detail: String,
    pub applied_at: String,
}

fn db_path() -> PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("CryptiQ Personal");
    std::fs::create_dir_all(&dir).ok();
    dir.join("cryptiq.db")
}

pub fn open() -> Store {
    open_at(&db_path())
}

/// Open a store at an explicit path (separated out for tests).
pub fn open_at(path: &std::path::Path) -> Store {
    let conn = Connection::open(path).expect("failed to open local database");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            detail TEXT NOT NULL,
            severity TEXT NOT NULL,
            current_crypto TEXT NOT NULL,
            target_crypto TEXT NOT NULL,
            remediation TEXT NOT NULL,
            last_seen TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ran_at TEXT NOT NULL DEFAULT (datetime('now')),
            total INTEGER NOT NULL,
            critical INTEGER NOT NULL,
            warn INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS remediations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .expect("failed to run migrations");
    Store(Mutex::new(conn))
}

impl Store {
    pub fn record_scan(&self, findings: &[Finding]) {
        let conn = self.0.lock().unwrap();
        for f in findings {
            conn.execute(
                "INSERT INTO findings (id, category, name, detail, severity, current_crypto, target_crypto, remediation, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                   detail=excluded.detail, severity=excluded.severity,
                   current_crypto=excluded.current_crypto, target_crypto=excluded.target_crypto,
                   remediation=excluded.remediation, last_seen=excluded.last_seen",
                params![f.id, f.category, f.name, f.detail, f.severity, f.current_crypto, f.target_crypto, f.remediation],
            )
            .ok();
        }
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let warn = findings.iter().filter(|f| f.severity == "warn").count();
        conn.execute(
            "INSERT INTO scans (total, critical, warn) VALUES (?1, ?2, ?3)",
            params![findings.len(), critical, warn],
        )
        .ok();
    }

    pub fn log_remediation(&self, finding_id: &str, action: &str, detail: &str) {
        let conn = self.0.lock().unwrap();
        conn.execute(
            "INSERT INTO remediations (finding_id, action, detail) VALUES (?1, ?2, ?3)",
            params![finding_id, action, detail],
        )
        .ok();
    }

    pub fn remediation_log(&self) -> Vec<RemediationEntry> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, finding_id, action, detail, applied_at FROM remediations ORDER BY id DESC LIMIT 50")
            .unwrap();
        stmt.query_map([], |row| {
            Ok(RemediationEntry {
                id: row.get(0)?,
                finding_id: row.get(1)?,
                action: row.get(2)?,
                detail: row.get(3)?,
                applied_at: row.get(4)?,
            })
        })
        .unwrap()
        .flatten()
        .collect()
    }
}
