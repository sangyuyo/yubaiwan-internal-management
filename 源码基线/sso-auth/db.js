// 统一身份认证服务（SSO）数据库
// 职责：只存账号身份（用户名/密码哈希/姓名/角色/门店编码）与登录会话，不存任何业务数据
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'sso.db'));
db.pragma('journal_mode = WAL');

// 角色约定（与各业务工具一致）：
//   super_admin = 项目负责人（不限门店）
//   manager     = 店长（绑定单一门店）
//   employee    = 店员（绑定单一门店）
// 门店用 store_code（dyz/rt/jz/wj ...）跨工具统一，避免各工具门店 id 不一致
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    real_name TEXT DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('super_admin','manager','employee')),
    store_code TEXT,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    real_name TEXT DEFAULT '',
    role TEXT NOT NULL,
    store_code TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`);

module.exports = { db };
