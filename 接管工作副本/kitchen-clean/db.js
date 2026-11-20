const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'kitchen.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Only initialize the schema + seed on a brand-new database.
// On an existing database we open it as-is so restarts never destroy data.
const initialized = db.prepare(
  "SELECT name FROM sqlite_master WHERE type='table' AND name='stores'"
).get();

if (!initialized) {
  db.exec(`
    CREATE TABLE stores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );

    CREATE TABLE form_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      btn_color TEXT NOT NULL,
      card_bg TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    CREATE TABLE cleaning_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_code TEXT NOT NULL,
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0,
      standard_photo_path TEXT DEFAULT '',
      standard_note TEXT DEFAULT ''
    );

    CREATE TABLE records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id INTEGER NOT NULL,
      form_code TEXT NOT NULL,
      record_date TEXT NOT NULL,
      inspector_name TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now','localtime')),
      updated_at TEXT DEFAULT (datetime('now','localtime')),
      UNIQUE(store_id, form_code, record_date),
      FOREIGN KEY (store_id) REFERENCES stores(id)
    );

    CREATE TABLE record_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      record_id INTEGER NOT NULL,
      item_id INTEGER NOT NULL,
      is_done INTEGER DEFAULT 0,
      cleaner_name TEXT DEFAULT '',
      photo_path TEXT DEFAULT '',
      UNIQUE(record_id, item_id),
      FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE,
      FOREIGN KEY (item_id) REFERENCES cleaning_items(id)
    );

    CREATE TABLE gallery_photos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      store_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      note TEXT DEFAULT '',
      uploaded_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (store_id) REFERENCES stores(id)
    );

    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      real_name TEXT DEFAULT '',
      role TEXT NOT NULL CHECK (role IN ('super_admin','manager','employee')),
      store_id INTEGER,
      active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (store_id) REFERENCES stores(id)
    );
  `);

  // Stores
  const insertStore = db.prepare('INSERT INTO stores (code, name) VALUES (?, ?)');
  insertStore.run('dyz', '大悦城店');
  insertStore.run('rt', '日坛店');
  insertStore.run('jz', '金盏店');
  insertStore.run('wj', '望京店');

  // Form templates (colors extracted from Saizeriya)
  const insertTpl = db.prepare(`
    INSERT INTO form_templates (code, name, description, btn_color, card_bg, sort_order)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertTpl.run('daily', '每日清洁报告', '请按照要求，仔细填写表单', '#5758C2', '#F2F2F9', 1);
  insertTpl.run('weekly', '每周深度清洁', '请按照要求，仔细填写表单', '#C74C49', '#FBF6F6', 2);
  insertTpl.run('monthly', '月度清洁追踪', '请按照要求，仔细填写表单', '#2D77C7', '#F3F6F9', 3);
  insertTpl.run('photos', '卫生照片上传', '现场卫生照片，随时上传更新', '#1BA04C', '#F1F8F4', 4);

  // Cleaning items (standard fields start empty; super admin sets them)
  const insertItem = db.prepare(`
    INSERT INTO cleaning_items (form_code, name, sort_order) VALUES (?, ?, ?)
  `);
  const dailyItems = [
    '操作台/砧板清洁消毒', '炸炉/锅具清洁', '冰柜/冷藏柜清洁', '地面/排水沟清洁',
    '餐具/容器清洗消毒', '墙面/排烟罩清洁', '垃圾桶/潲水桶清理', '洗手区/卫生间清洁',
    '食材留样记录', '员工健康晨检'
  ];
  const weeklyItems = [
    '排烟罩/油烟机深度清洗', '冰柜除霜/内部深度清洁', '炸炉深度清洗/换油',
    '墙面瓷砖/踢脚线刷洗', '排水沟/地漏疏通消毒', '储物柜/货架整理清洁',
    '灭蝇灯/虫害设施检查'
  ];
  const monthlyItems = [
    '油烟管道/风机深度清洗', '冰柜/冷库压缩机清洁', '厨房设备全面检修',
    '墙面/天花板除霉', '地面深度刷洗/油污处理', '灭火器/消防设施检查',
    '给水/排水系统检查'
  ];
  dailyItems.forEach((n, i) => insertItem.run('daily', n, i + 1));
  weeklyItems.forEach((n, i) => insertItem.run('weekly', n, i + 1));
  monthlyItems.forEach((n, i) => insertItem.run('monthly', n, i + 1));

  // Users: one super admin + one manager per store
  const insertUser = db.prepare(`
    INSERT INTO users (username, password_hash, real_name, role, store_id)
    VALUES (?, ?, ?, ?, ?)
  `);
  const adminHash = bcrypt.hashSync(require('node:crypto').randomBytes(32).toString('hex'), 10);
  const mgrHash = bcrypt.hashSync(require('node:crypto').randomBytes(32).toString('hex'), 10);
  insertUser.run('admin', adminHash, '项目负责人', 'super_admin', null);
  const stores = db.prepare('SELECT id, code FROM stores ORDER BY id').all();
  stores.forEach(s => {
    insertUser.run(`${s.code}_mgr`, mgrHash, `${s.code}店长`, 'manager', s.id);
  });
}

// Ensure additional tables on ANY database (idempotent; safe on existing DBs too)
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expire INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);

  CREATE TABLE IF NOT EXISTS sop_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    orig_name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_by INTEGER NOT NULL,
    uploaded_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);

module.exports = db;
