CREATE TABLE IF NOT EXISTS board_tasks (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  message TEXT NOT NULL,
  task_type TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  plan_json TEXT,
  result_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_board_tasks_status
ON board_tasks(status);

CREATE INDEX IF NOT EXISTS idx_board_tasks_username
ON board_tasks(username);
