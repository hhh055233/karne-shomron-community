================================================================================
CREATE TABLE IF NOT EXISTS board_tasks(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_board_tasks_user_status ON board_tasks(user_id,status,expires_at);
