================================================================================
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS posts(id TEXT PRIMARY KEY,cat TEXT,title TEXT,desc TEXT,age TEXT,salary TEXT,location TEXT,phone TEXT,author TEXT,status TEXT,promo INTEGER,date TEXT,created_at INTEGER);
CREATE TABLE IF NOT EXISTS categories(name TEXT PRIMARY KEY,icon TEXT,color TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,action TEXT,details TEXT,created_at INTEGER);
