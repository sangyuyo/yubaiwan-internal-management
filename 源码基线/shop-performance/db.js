// shop-performance 数据库（幂等建表，重启不丢数据）
// 注意：与 QSC 数据库完全独立，不共用
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'shop.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ---------- 平台枚举（统一口径） ----------
// meituan      美团外卖
// taobao_flash 淘宝闪购（淘鲜达）
// jd           京东外卖

// ---------- 门店表 ----------
db.exec(`
CREATE TABLE IF NOT EXISTS stores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,          -- 门店编码：dyz / rt / jz / wj ...
  name TEXT NOT NULL,                 -- 门店名：大悦城店 / 日坛店 ...
  active INTEGER NOT NULL DEFAULT 1,  -- 1=营业中(前端展示) 0=已闭店(保留数据，前端隐藏)
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
`);

// 幂等迁移：旧库补 active 列
const storeCols = db.prepare('PRAGMA table_info(stores)').all().map(c => c.name);
if (!storeCols.includes('active')) {
  db.exec("ALTER TABLE stores ADD COLUMN active INTEGER NOT NULL DEFAULT 1");
  console.log('[db] 迁移：stores 新增 active 列');
}

// 大悦城店已闭店：前端隐藏但数据字段全部保留（历史 records 不受影响）。
// 未来重新启用时，把下面 0 改为 1 并重启即可立即恢复展示。
db.prepare("UPDATE stores SET active = 0 WHERE code = 'dyz'").run();

// 种子：与 QSC 四家门店对齐（仅当门店表为空时写入）
const storeCount = db.prepare('SELECT COUNT(*) AS c FROM stores').get().c;
if (storeCount === 0) {
  const ins = db.prepare('INSERT INTO stores (code, name) VALUES (?, ?)');
  const seeds = [
    ['dyz', '大悦城店'],
    ['rt',  '日坛店'],
    ['jz',  '金盏店'],
    ['wj',  '望京店'],
  ];
  for (const [code, name] of seeds) ins.run(code, name);
  console.log('[db] 初始化 4 家门店种子');
}

// ---------- 门店×平台×日期 目标表 ----------
db.exec(`
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  store_id INTEGER NOT NULL REFERENCES stores(id),
  platform TEXT NOT NULL,             -- meituan / taobao_flash / jd
  date TEXT NOT NULL,                 -- YYYY-MM-DD
  target_amount REAL NOT NULL,        -- 目标营业额（元）
  target_orders INTEGER NOT NULL,     -- 目标有效单量（单）
  created_at TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE (store_id, platform, date)
);
CREATE INDEX IF NOT EXISTS idx_targets_date ON targets(date);
`);

// ---------- 实际营业数据表（Excel 解析入库） ----------
db.exec(`
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  store_id INTEGER NOT NULL REFERENCES stores(id),
  platform TEXT NOT NULL,             -- meituan / taobao_flash / jd
  date TEXT NOT NULL,                 -- 营业日期 YYYY-MM-DD
  turnover REAL NOT NULL DEFAULT 0,   -- 营业额（折前 GMV，元）
  income REAL NOT NULL DEFAULT 0,     -- 营业收入（到手，元）
  discount REAL NOT NULL DEFAULT 0,   -- 优惠金额（元）
  orders INTEGER NOT NULL DEFAULT 0,  -- 订单量（单）
  avg_pre REAL NOT NULL DEFAULT 0,    -- 折前单均（元）
  avg_post REAL NOT NULL DEFAULT 0,   -- 折后单均（元）
  dine_in_turnover REAL NOT NULL DEFAULT 0, -- 堂食营业额（元）
  dine_in_income REAL NOT NULL DEFAULT 0,   -- 堂食营业收入（元）
  dine_in_orders INTEGER NOT NULL DEFAULT 0,-- 堂食订单量
  groupon_income REAL NOT NULL DEFAULT 0,   -- 美团/大众点评团购核销营收（元）
  refund_amount REAL NOT NULL DEFAULT 0, -- 退款金额（元，本报表无，预留）
  raw_json TEXT,                      -- 原始行 JSON（留痕，便于口径核对）
  uploaded_at TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE (store_id, platform, date)
);
CREATE INDEX IF NOT EXISTS idx_records_date ON records(date);
CREATE INDEX IF NOT EXISTS idx_records_store ON records(store_id);
`);


// 幂等迁移：为旧 records 表补充缺失列（新库直接建表则跳过）
const recCols = db.prepare('PRAGMA table_info(records)').all().map(c => c.name);
const addCols = [
  ['turnover', 'REAL NOT NULL DEFAULT 0'],
  ['income', 'REAL NOT NULL DEFAULT 0'],
  ['discount', 'REAL NOT NULL DEFAULT 0'],
  ['avg_pre', 'REAL NOT NULL DEFAULT 0'],
  ['avg_post', 'REAL NOT NULL DEFAULT 0'],
  ['dine_in_turnover', 'REAL NOT NULL DEFAULT 0'],
  ['dine_in_income', 'REAL NOT NULL DEFAULT 0'],
  ['dine_in_orders', 'INTEGER NOT NULL DEFAULT 0'],
  ['groupon_income', 'REAL NOT NULL DEFAULT 0'],
];
for (const [name, ddl] of addCols) {
  if (!recCols.includes(name)) {
    db.exec(`ALTER TABLE records ADD COLUMN ${name} ${ddl}`);
    console.log('[db] 迁移：records 新增列', name);
  }
}

// ---------- 月度目标表（门店 × 自然月） ----------
db.exec(`
CREATE TABLE IF NOT EXISTS monthly_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  store_id INTEGER NOT NULL REFERENCES stores(id),
  month TEXT NOT NULL,                -- YYYY-MM
  target_amount REAL NOT NULL,        -- 全店营业收入月目标（到手收入，元）
  created_at TEXT DEFAULT (datetime('now','localtime')),
  updated_at TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE (store_id, month)
);
CREATE INDEX IF NOT EXISTS idx_mt_month ON monthly_targets(month);
`);

// ---------- 登录会话表（独立登录态，服务重启不丢） ----------
db.exec(`
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  real_name TEXT NOT NULL,
  store_id INTEGER,
  expire INTEGER NOT NULL,
  sso_token TEXT,                     -- 签发时拿到的 SSO 令牌，用于定期回验账号是否仍有效
  sso_checked_at INTEGER              -- 上次回验时间（毫秒），避免每个请求都打 SSO
);
`);

// 幂等迁移：旧库补 sso_token / sso_checked_at（2026-11 新增，解决"账号停用后仍可用 7 天"）
const sessCols = db.prepare('PRAGMA table_info(sessions)').all().map(c => c.name);
if (!sessCols.includes('sso_token')) {
  db.exec('ALTER TABLE sessions ADD COLUMN sso_token TEXT');
  console.log('[db] 迁移：sessions 新增 sso_token 列');
}
if (!sessCols.includes('sso_checked_at')) {
  db.exec('ALTER TABLE sessions ADD COLUMN sso_checked_at INTEGER');
  console.log('[db] 迁移：sessions 新增 sso_checked_at 列');
}

module.exports = db;
