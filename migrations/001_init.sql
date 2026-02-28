CREATE TABLE IF NOT EXISTS scan_runs (
  id SERIAL PRIMARY KEY,
  started_at TIMESTAMP NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP NULL,
  status VARCHAR(32) NOT NULL,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  warnings JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  entity_kind VARCHAR(32) NOT NULL,
  entity_id VARCHAR(128) NOT NULL,
  display_name VARCHAR(256) NULL,
  severity VARCHAR(16) NOT NULL,
  category VARCHAR(64) NOT NULL,
  type VARCHAR(64) NOT NULL,
  description TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
