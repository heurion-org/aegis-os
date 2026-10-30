//! SQLite memory data plane for Aegis OS (`aos-memory-store`).
//!
//! This is the Rust-side foundation for the UOMP memory store: the schema
//! matches `uomp-mvp` (`memory_items`), so existing data can be opened without
//! a migration. The Markdown importer covers the common Obsidian/Markdown path;
//! richer connectors remain in the UOMP reference implementation for now.

use std::collections::BTreeSet;
use std::path::Path;

use aos_memory::Sensitivity;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    pub key: String,
    pub value: Value,
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub source: String,
    pub created_at: String,
    pub updated_at: String,
    pub description: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

pub struct SqliteMemoryStore {
    conn: Connection,
}

impl SqliteMemoryStore {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS memory_items (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                tags TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                description TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memory_items_tags ON memory_items(tags);
            CREATE INDEX IF NOT EXISTS idx_memory_items_source ON memory_items(source);
            "#,
        )?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> anyhow::Result<Option<MemoryItem>> {
        let row = self
            .conn
            .query_row(
                "SELECT key, value, tags, sensitivity, source, created_at, updated_at, description
                 FROM memory_items WHERE key = ?",
                params![key],
                row_to_item,
            )
            .optional()?;
        Ok(row)
    }

    pub fn get_by_tag(&self, tag: &str) -> anyhow::Result<Vec<MemoryItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, value, tags, sensitivity, source, created_at, updated_at, description
             FROM memory_items
             WHERE EXISTS (SELECT 1 FROM json_each(tags) WHERE value = ?)
             ORDER BY key",
        )?;
        let rows = stmt.query_map(params![tag], row_to_item)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set(&self, item: &MemoryItem) -> anyhow::Result<bool> {
        let existing_created: Option<String> = self
            .conn
            .query_row(
                "SELECT created_at FROM memory_items WHERE key = ?",
                params![item.key],
                |row| row.get(0),
            )
            .optional()?;
        let created_at = existing_created.unwrap_or_else(|| item.created_at.clone());
        let updated_at = if item.updated_at.is_empty() {
            Utc::now().to_rfc3339()
        } else {
            item.updated_at.clone()
        };

        self.conn.execute(
            "INSERT INTO memory_items
             (key, value, tags, sensitivity, source, created_at, updated_at, description)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET
               value = excluded.value,
               tags = excluded.tags,
               sensitivity = excluded.sensitivity,
               source = excluded.source,
               updated_at = excluded.updated_at,
               description = excluded.description",
            params![
                item.key,
                serde_json::to_string(&item.value)?,
                serde_json::to_string(&item.tags)?,
                sensitivity_str(item.sensitivity),
                item.source,
                created_at,
                updated_at,
                item.description,
            ],
        )?;
        Ok(true)
    }

    pub fn delete(&self, key: &str) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM memory_items WHERE key = ?", params![key])?
            > 0)
    }

    pub fn list_tags(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT tags FROM memory_items")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut tags = BTreeSet::new();
        for row in rows {
            let raw = row?;
            if let Ok(values) = serde_json::from_str::<Vec<String>>(&raw) {
                tags.extend(values);
            }
        }
        Ok(tags.into_iter().collect())
    }

    pub fn count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM memory_items", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Import a Markdown directory using the same path-derived tags as UOMP:
    /// `projects/uomp/plan.md` -> `notes`, `notes/projects`, `notes/projects/uomp`.
    pub fn import_markdown_dir(
        &self,
        root: impl AsRef<Path>,
        base_tag: &str,
    ) -> anyhow::Result<ImportResult> {
        let root = root.as_ref();
        let mut result = ImportResult::default();
        if !root.is_dir() {
            anyhow::bail!("not a directory: {}", root.display());
        }
        self.walk_markdown(root, root, base_tag, &mut result)?;
        Ok(result)
    }

    fn walk_markdown(
        &self,
        root: &Path,
        dir: &Path,
        base_tag: &str,
        result: &mut ImportResult,
    ) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    result.errors.push(error.to_string());
                    continue;
                }
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if name.starts_with('.') || name == "node_modules" {
                    result.skipped += 1;
                    continue;
                }
                self.walk_markdown(root, &path, base_tag, result)?;
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("md") {
                result.skipped += 1;
                continue;
            }
            match self.import_markdown_file(root, &path, base_tag) {
                Ok(()) => result.imported += 1,
                Err(error) => result.errors.push(format!("{}: {error}", path.display())),
            }
        }
        Ok(())
    }

    fn import_markdown_file(&self, root: &Path, path: &Path, base_tag: &str) -> anyhow::Result<()> {
        let relative = path.strip_prefix(root).unwrap_or(path);
        let content = std::fs::read_to_string(path)?;
        let mut tags = vec![base_tag.to_string()];
        let mut accumulated = base_tag.to_string();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                let part = component.as_os_str().to_string_lossy();
                if part.is_empty() || part == "." {
                    continue;
                }
                accumulated = format!("{accumulated}/{part}");
                tags.push(accumulated.clone());
            }
        }

        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("note");
        let key = format!(
            "note.{}",
            relative
                .with_extension("")
                .to_string_lossy()
                .replace(['/', '\\'], ".")
        );
        let title = content
            .lines()
            .find_map(|line| line.strip_prefix("# ").map(str::trim))
            .filter(|line| !line.is_empty())
            .unwrap_or(stem)
            .to_string();
        let sensitivity = parse_sensitivity(&content);
        let now = Utc::now().to_rfc3339();

        self.set(&MemoryItem {
            key,
            value: json!({
                "title": title,
                "body": content,
                "path": relative.to_string_lossy(),
            }),
            tags,
            sensitivity,
            source: "user".to_string(),
            created_at: now.clone(),
            updated_at: now,
            description: Some(title),
        })?;
        Ok(())
    }
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryItem> {
    let value: String = row.get(1)?;
    let tags: String = row.get(2)?;
    let sensitivity: String = row.get(3)?;
    Ok(MemoryItem {
        key: row.get(0)?,
        value: serde_json::from_str(&value).unwrap_or(Value::Null),
        tags: serde_json::from_str(&tags).unwrap_or_default(),
        sensitivity: parse_sensitivity_str(&sensitivity),
        source: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        description: row.get(7)?,
    })
}

fn sensitivity_str(value: Sensitivity) -> &'static str {
    match value {
        Sensitivity::Low => "low",
        Sensitivity::Medium => "medium",
        Sensitivity::High => "high",
    }
}

fn parse_sensitivity_str(value: &str) -> Sensitivity {
    match value {
        "high" => Sensitivity::High,
        "medium" => Sensitivity::Medium,
        _ => Sensitivity::Low,
    }
}

fn parse_sensitivity(content: &str) -> Sensitivity {
    for line in content.lines().take(30) {
        if let Some(value) = line.trim().strip_prefix("sensitivity:") {
            return parse_sensitivity_str(value.trim().trim_matches('"').trim_matches('\''));
        }
    }
    Sensitivity::Low
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, tags: &[&str]) -> MemoryItem {
        let now = Utc::now().to_rfc3339();
        MemoryItem {
            key: key.to_string(),
            value: json!({ "title": key }),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            sensitivity: Sensitivity::Low,
            source: "user".to_string(),
            created_at: now.clone(),
            updated_at: now,
            description: None,
        }
    }

    #[test]
    fn stores_reads_and_deletes_items() {
        let store = SqliteMemoryStore::in_memory().unwrap();
        store
            .set(&item("note.projects.plan", &["notes", "notes/projects"]))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(
            store.get("note.projects.plan").unwrap().unwrap().key,
            "note.projects.plan"
        );
        assert_eq!(store.get_by_tag("notes/projects").unwrap().len(), 1);
        assert_eq!(store.list_tags().unwrap(), vec!["notes", "notes/projects"]);
        assert!(store.delete("note.projects.plan").unwrap());
        assert!(store.get("note.projects.plan").unwrap().is_none());
    }

    #[test]
    fn imports_markdown_with_path_tags_and_sensitivity() {
        let dir = tempfile::tempdir().unwrap();
        let projects = dir.path().join("projects").join("uomp");
        std::fs::create_dir_all(&projects).unwrap();
        std::fs::write(
            projects.join("plan.md"),
            "---\nsensitivity: high\n---\n# Plan\n\nShip it.\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Readme\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".obsidian")).unwrap();
        std::fs::write(dir.path().join(".obsidian").join("x.md"), "# Hidden\n").unwrap();

        let store = SqliteMemoryStore::in_memory().unwrap();
        let result = store.import_markdown_dir(dir.path(), "notes").unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(store.count().unwrap(), 2);

        let plan = store.get("note.projects.uomp.plan").unwrap().unwrap();
        assert_eq!(
            plan.tags,
            vec!["notes", "notes/projects", "notes/projects/uomp"]
        );
        assert_eq!(plan.sensitivity, Sensitivity::High);
        assert_eq!(plan.value["title"], "Plan");
        assert!(store.get("note..obsidian.x").unwrap().is_none());
    }
}
