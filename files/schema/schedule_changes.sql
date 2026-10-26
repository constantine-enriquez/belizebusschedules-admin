-- Change history for schedule edits (bus_schedule_v2), manual and AI import.
-- The admin API creates/migrates this automatically; run manually only if needed.

CREATE TABLE IF NOT EXISTS schedule_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bid INTEGER,
  company TEXT,
  action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'restore')),
  before_json TEXT,
  after_json TEXT,
  actor TEXT,
  created_at TEXT NOT NULL,
  batch_id TEXT -- groups rows from one AI import (ai-…) or one batch undo (undo-…)
);

CREATE INDEX IF NOT EXISTS idx_schedule_changes_company
  ON schedule_changes(company, created_at);

CREATE INDEX IF NOT EXISTS idx_schedule_changes_batch
  ON schedule_changes(batch_id);

-- Saved AI Upload settings (system prompt, model). Also auto-created.
CREATE TABLE IF NOT EXISTS ai_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL
);
