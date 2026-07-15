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

pub struct Snapshot {
    pub file_path: String,
    /// None means the file did not exist before the migration.
    pub content: Option<Vec<u8>>,
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
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            content BLOB,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
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

    pub fn save_snapshot(&self, finding_id: &str, file_path: &str, content: Option<&str>) {
        let conn = self.0.lock().unwrap();
        conn.execute(
            "INSERT INTO snapshots (finding_id, file_path, content) VALUES (?1, ?2, ?3)",
            params![finding_id, file_path, content.map(|c| c.as_bytes())],
        )
        .ok();
    }

    pub fn latest_snapshot(&self, finding_id: &str) -> Option<Snapshot> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT file_path, content FROM snapshots WHERE finding_id = ?1 ORDER BY id DESC LIMIT 1",
            params![finding_id],
            |row| {
                Ok(Snapshot {
                    file_path: row.get(0)?,
                    content: row.get(1)?,
                })
            },
        )
        .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        let conn = self.0.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )
        .ok();
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .ok()
    }

    /// Finding ids whose most recent remediation action is not a rollback —
    /// i.e. migrations that are currently in effect. Lets the UI show applied
    /// state across app restarts.
    pub fn applied_findings(&self) -> Vec<String> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT finding_id FROM remediations r1
                 WHERE id = (SELECT MAX(id) FROM remediations r2 WHERE r2.finding_id = r1.finding_id)
                   AND action != 'rollback'",
            )
            .unwrap();
        stmt.query_map([], |row| row.get(0)).unwrap().flatten().collect()
    }

    pub fn latest_remediation(&self, finding_id: &str) -> Option<RemediationEntry> {
        let conn = self.0.lock().unwrap();
        conn.query_row(
            "SELECT id, finding_id, action, detail, applied_at FROM remediations
             WHERE finding_id = ?1 AND action != 'rollback' ORDER BY id DESC LIMIT 1",
            params![finding_id],
            |row| {
                Ok(RemediationEntry {
                    id: row.get(0)?,
                    finding_id: row.get(1)?,
                    action: row.get(2)?,
                    detail: row.get(3)?,
                    applied_at: row.get(4)?,
                })
            },
        )
        .ok()
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
