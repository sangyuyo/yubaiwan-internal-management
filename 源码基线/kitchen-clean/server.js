const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const QRCode = require('qrcode');
const db = require('./db');
// 公共运行时核心（shared/ybw-core.js，部署时自动注入本目录）
const core = require('./ybw-core');

const app = express();
const PORT = process.env.PORT || 3000;
// 在 Nginx 反向代理之后：让 req.protocol 识别 X-Forwarded-Proto（二维码域名、secure cookie 依赖）
app.set('trust proxy', 1);

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const sopDir = path.join(__dirname, 'sop');
if (!fs.existsSync(sopDir)) fs.mkdirSync(sopDir, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ---------- 登录限流（防暴力破解） ----------
// 实现下沉到 core，四个应用共用同一套逻辑与参数
const clientIpOf = core.clientIp;
const rateLimit = core.createRateLimiter({
  windowMs: 60 * 1000,
  maxHits: 10,
  message: '尝试过于频繁，请 1 分钟后再试'
});
// 会话持久化到 SQLite：7 天免登录（同一设备），服务重启不丢
// 注意：express-session 的 store 必须是 EventEmitter（继承 session.Store）
class SqliteSessionStore extends session.Store {
  constructor(db) { super(); this.db = db; }
  get(sid, cb) {
    try {
      const r = this.db.prepare('SELECT data FROM sessions WHERE sid=? AND expire>?').get(sid, Date.now());
      cb(null, r ? JSON.parse(r.data) : null);
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const data = JSON.stringify(sess);
      this.db.prepare('INSERT INTO sessions (sid, data, expire) VALUES (?,?,?) ON CONFLICT(sid) DO UPDATE SET data=excluded.data, expire=excluded.expire')
        .run(sid, data, Date.now() + 7 * 24 * 3600 * 1000);
      cb(null);
    } catch (e) { cb(e); }
  }
  destroy(sid, cb) {
    try { this.db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); cb(null); } catch (e) { cb(e); }
  }
  touch(sid, sess, cb) { cb(null); }
}
// 会话密钥：2026-11 起从环境变量读取（/etc/ybw/env），不再硬编码
// 泄漏该密钥即可伪造任意用户（含超管）的会话，所以必须外置且足够长
const SESSION_SECRET = core.requireEnv('SESSION_SECRET', 24);
app.use(session({
  secret: SESSION_SECRET,
  store: new SqliteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 3600 * 1000,
    httpOnly: true,
    // 生产全站 HTTPS，禁止明文回传；预发布走 http 隧道时用 COOKIE_INSECURE=1 关闭
    // 判定逻辑统一在 core，同时兼容旧变量名 SSO_COOKIE_INSECURE
    secure: !core.isCookieInsecure(),
    sameSite: 'lax'
  }
}));

// ===== 共享登录态：门户登录一次，本工具自动免登 =====
const SSO_COOKIE_NAME = core.SHARED_COOKIE_NAME;

function getSharedToken(req) {
  const token = core.parseCookies(req)[SSO_COOKIE_NAME];
  return token ? decodeURIComponent(token) : null;
}

function appendCookies(res, setCookie) {
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  list.forEach((c) => { if (c) res.append('Set-Cookie', c); });
}

// 用 SSO 共享会话同步本地影子用户（业务记录依赖本地 user_id 稳定）
function syncShadowUserFromSSO(info) {
  const username = info.username;
  let user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user) {
    db.prepare("INSERT INTO users (username, password_hash, real_name, role, store_id, active) VALUES (?, 'sso-managed', ?, ?, ?, 1)")
      .run(username, info.real_name || username, info.role, storeIdByCode(info.store_code));
  } else {
    db.prepare('UPDATE users SET real_name=?, role=?, store_id=?, active=1 WHERE id=?')
      .run(info.real_name || username, info.role, storeIdByCode(info.store_code), user.id);
  }
  return db.prepare('SELECT * FROM users WHERE username=?').get(username);
}

app.use(async (req, res, next) => {
  if (/^\/(css|js|img|images|uploads|sop|favicon)/.test(req.path)) return next();
  try {
    const shared = getSharedToken(req);
    if (!shared) return next();
    const hasLocal = !!(req.session && req.session.userId);
    if (hasLocal && Date.now() - (req.session.ssoCheckedAt || 0) < 60000) return next();
    const r = await ssoRequest('GET', '/api/auth/session', null, false, shared);
    if (r.status === 200 && r.json && r.json.ok) {
      const user = syncShadowUserFromSSO(r.json);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      req.session.realName = user.real_name;
      req.session.storeId = user.store_id;
      req.session.ssoCheckedAt = Date.now();
      return next();
    }
    if (hasLocal) req.session.destroy(() => {});
    return next();
  } catch (e) {
    return next();
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));
app.use('/sop', express.static(sopDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  defParamCharset: 'utf8', // 中文文件名不乱码
  // 2026-11：扩展名与 mimetype 双重校验。
  // 原来只看 mimetype，而 mimetype 由客户端提供可伪造，能让 .html 落到 /uploads 下形成同源 XSS。
  fileFilter: (req, file, cb) => {
    const okExt = /\.(jpe?g|png|gif|webp)$/i.test(file.originalname || '');
    const okMime = /^image\/(jpe?g|png|gif|webp)$/i.test(file.mimetype || '');
    if (okExt && okMime) cb(null, true);
    else cb(new Error('仅支持 jpg / png / gif / webp 图片'));
  }
});

// SOP 标准化文件上传（PDF / 图片 / Office 文档，最大 20MB）
const sopStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, sopDir),
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase();
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const sopUpload = multer({
  storage: sopStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  defParamCharset: 'utf8', // 中文文件名不乱码
  fileFilter: (req, file, cb) => {
    if (/\.(pdf|jpe?g|png|gif|webp|doc|docx|xls|xlsx|ppt|pptx)$/i.test(file.originalname || '')) {
      cb(null, true);
    } else cb(new Error('仅支持 PDF / 图片 / Office 文档'));
  }
});

// ================= AUTH MIDDLEWARE =================
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: '未登录或登录已过期' });
}
function requireSuperAdmin(req, res, next) {
  if (req.session && req.session.role === 'super_admin') return next();
  return res.status(403).json({ error: '无权限，仅项目负责人可操作' });
}
function canAccessStore(req, storeId) {
  if (req.session.role === 'super_admin') return true;
  return Number(req.session.storeId) === Number(storeId);
}

// ================= SHARED QUERIES =================
function getRecordDetail(storeId, formCode, date) {
  const record = db.prepare(`
    SELECT * FROM records WHERE store_id=? AND form_code=? AND record_date=?
  `).get(storeId, formCode, date);

  const items = db.prepare(`
    SELECT ci.id AS item_id, ci.name, ci.sort_order,
      COALESCE(ci.standard_photo_path,'') AS standard_photo_path,
      COALESCE(ci.standard_note,'') AS standard_note,
      COALESCE(ri.is_done,0) AS is_done,
      COALESCE(ri.cleaner_name,'') AS cleaner_name,
      COALESCE(ri.photo_path,'') AS photo_path
    FROM cleaning_items ci
    LEFT JOIN record_items ri ON ri.item_id=ci.id AND ri.record_id=?
    WHERE ci.form_code=?
    ORDER BY ci.sort_order
  `).all(record ? record.id : -1, formCode);

  return {
    form_code: formCode,
    record_date: date,
    store_id: storeId,
    inspector_name: record ? record.inspector_name : '',
    notes: record ? record.notes : '',
    exists: !!record,
    items
  };
}

function getPortalData(storeId) {
  const templates = db.prepare('SELECT * FROM form_templates ORDER BY sort_order').all();
  const latestStmt = db.prepare(`
    SELECT updated_at, inspector_name, record_date FROM records
    WHERE store_id=? AND form_code=? ORDER BY record_date DESC LIMIT 1
  `);
  // 今日是否有提交：门店首页要给顾客看的是「今天做没做」，不是「历史上最后一次是什么时候」
  const todayStmt = db.prepare(`
    SELECT 1 FROM records WHERE store_id=? AND form_code=? AND record_date=?
  `);
  const gallery = db.prepare(`
    SELECT uploaded_at FROM gallery_photos WHERE store_id=?
    ORDER BY uploaded_at DESC LIMIT 1
  `).get(storeId);
  const today = new Date();
  const todayStr = today.getFullYear() + '-' +
    String(today.getMonth() + 1).padStart(2, '0') + '-' +
    String(today.getDate()).padStart(2, '0');

  return templates.map(t => {
    let latest = null;
    let inspector = '';
    let todayDone = false;
    if (t.code === 'photos') {
      latest = gallery ? gallery.uploaded_at : null;
      // 照片墙没有「按日期归档」的概念，当天有上传即视为今日已更新
      todayDone = !!(latest && String(latest).slice(0, 10) === todayStr);
    } else {
      const r = latestStmt.get(storeId, t.code);
      latest = r ? r.updated_at : null;
      // 门店首页对外展示：最近一次检查的负责人（老板确认公示责任人）
      inspector = r ? (r.inspector_name || '') : '';
      todayDone = !!todayStmt.get(storeId, t.code, todayStr);
    }
    return { ...t, latest_update: latest, latest_inspector: inspector, today_done: todayDone };
  });
}

function getDashboard(date) {
  const allStores = db.prepare('SELECT id, code, name FROM stores ORDER BY id').all();
  const forms = db.prepare(`
    SELECT code, name, btn_color FROM form_templates
    WHERE code != 'photos' ORDER BY sort_order
  `).all();

  return allStores.map(st => {
    const entry = { id: st.id, code: st.code, name: st.name, forms: {}, gallery_count: 0 };
    forms.forEach(f => {
      const total = db.prepare('SELECT COUNT(*) c FROM cleaning_items WHERE form_code=?').get(f.code).c;
      const r = db.prepare(`
        SELECT * FROM records WHERE store_id=? AND form_code=? AND record_date=?
      `).get(st.id, f.code, date);
      let status = { code: f.code, name: f.name, btn_color: f.btn_color,
        submitted: false, total, done: 0, rate: 0, inspector: '', updated_at: null, notes: '' };
      if (r) {
        const done = db.prepare(`
          SELECT COUNT(*) c FROM record_items WHERE record_id=? AND is_done=1
        `).get(r.id).c;
        status = { ...status, submitted: true, done,
          rate: total ? Math.round(done / total * 100) : 0,
          inspector: r.inspector_name, updated_at: r.updated_at, notes: r.notes };
      }
      entry.forms[f.code] = status;
    });
    entry.gallery_count = db.prepare(
      'SELECT COUNT(*) c FROM gallery_photos WHERE store_id=?').get(st.id).c;
    return entry;
  });
}

// ================= PUBLIC =================
app.get('/s/:code', (req, res) => {
  const store = db.prepare('SELECT * FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).send('门店不存在');
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

app.get('/api/public/stores', (req, res) => {
  res.json(db.prepare('SELECT id, code, name FROM stores ORDER BY id').all());
});

app.get('/api/public/stores/:code', (req, res) => {
  const store = db.prepare('SELECT id, code, name FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).json({ error: '门店不存在' });
  res.json(store);
});

app.get('/api/public/stores/:code/portal', (req, res) => {
  const store = db.prepare('SELECT * FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).json({ error: '门店不存在' });
  res.json(getPortalData(store.id));
});

app.get('/api/public/stores/:code/records', (req, res) => {
  const store = db.prepare('SELECT * FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).json({ error: '门店不存在' });
  const form = req.query.form;
  const date = req.query.date;
  if (!form || !/^\d{4}-\d{2}-\d{2}$/.test(date || '')) return res.status(400).json({ error: '参数错误' });
  const data = getRecordDetail(store.id, form, date);
  // 该接口同时服务「消费者扫码查看卫生公示」和「店员登录后填报」两种场景。
  // 公示口径（老板确认）：检查负责人、清洁责任人对外可见——写清谁负责，是给顾客的信任凭证；
  // 内部备注（可能含员工考勤、纠纷等管理信息）不对访客下发。
  const internalViewer = !!(req.session && req.session.userId) && canAccessStore(req, store.id);
  if (!internalViewer) {
    data.notes = '';
    res.setHeader('Cache-Control', 'public, max-age=60');
  }
  res.json(data);
});

app.get('/api/public/stores/:code/gallery', (req, res) => {
  const store = db.prepare('SELECT * FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).json({ error: '门店不存在' });
  const rows = db.prepare(`
    SELECT id, filename, note, uploaded_at FROM gallery_photos
    WHERE store_id=? ORDER BY uploaded_at DESC
  `).all(store.id);
  res.json(rows);
});

// ================= BANNER / SOP (public read) =================
app.get('/api/public/banner', (req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key='banner_path'").get();
  const fn = row && row.value ? row.value : '';
  // 未设置时回退到默认 banner.jpg；文件名（banner_<时间戳>.ext）本身唯一即版本号，
  // 不加 Date.now() 随机参数，否则每次请求 URL 都变化，浏览器缓存完全失效、图片反复重新下载
  res.json({ url: fn ? '/' + fn : '/banner.jpg' });
});

app.get('/api/public/sop', (req, res) => {
  res.json(db.prepare(`
    SELECT id, filename, orig_name, mime, size, uploaded_at
    FROM sop_files ORDER BY id DESC
  `).all());
});

// ================= AUTH =================
// 账号密码校验统一转发独立身份服务（sso-auth）：本工具不存密码、不校验密码
// 启动即校验管理密钥（缺失或过短直接启动失败）；实际读取由 core.ssoRequest 内部完成
core.requireEnv('SSO_KEY', 24);
// 实现在 core.ssoRequest，此处保留原签名以维持全部调用点不变
function ssoRequest(method, pathname, bodyObj, withKey, token, clientIp) {
  return core.ssoRequest({
    method: method,
    path: pathname,
    body: bodyObj,
    withKey: withKey,
    token: token,
    clientIp: clientIp
  });
}
// 门店编码 <-> 本地门店 id
function storeIdByCode(code) {
  if (!code) return null;
  const st = db.prepare('SELECT id FROM stores WHERE code=?').get(code);
  return st ? st.id : null;
}
function storeCodeById(id) {
  if (id == null) return null;
  const st = db.prepare('SELECT code FROM stores WHERE id=?').get(id);
  return st ? st.code : null;
}

app.post('/api/auth/login', rateLimit, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: '请输入账号和密码' });
  try {
    const sso = await ssoRequest('POST', '/api/auth/login', { username, password }, false, null, clientIpOf(req));
    if (sso.status !== 200 || !sso.json || !sso.json.ok) {
      return res.status(401).json({ error: '账号或密码错误（使用于百万统一账号）' });
    }
    const info = sso.json;
    // 影子用户表：保持本地 user id 稳定（业务记录引用 user_id），档案随 SSO 同步
    let user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!user) {
      db.prepare("INSERT INTO users (username, password_hash, real_name, role, store_id, active) VALUES (?, 'sso-managed', ?, ?, ?, 1)")
        .run(username, info.real_name || username, info.role, storeIdByCode(info.store_code));
    } else {
      db.prepare('UPDATE users SET real_name=?, role=?, store_id=?, active=1 WHERE id=?')
        .run(info.real_name || username, info.role, storeIdByCode(info.store_code), user.id);
    }
    if (sso.setCookie) appendCookies(res, sso.setCookie);
    user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.realName = user.real_name;
    req.session.storeId = user.store_id;
    res.json({ ok: true, username: user.username, role: user.role,
      real_name: user.real_name, store_id: user.store_id });
  } catch (e) {
    res.status(502).json({ error: '账号服务暂不可用，请稍后再试' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = getSharedToken(req);
  if (token) {
    try {
      const r = await ssoRequest('POST', '/api/auth/logout', null, false, token);
      if (r.setCookie) appendCookies(res, r.setCookie);
    } catch (e) {}
  }
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok: true, username: req.session.username, role: req.session.role,
    real_name: req.session.realName, store_id: req.session.storeId });
});

// ================= USER MANAGEMENT (super admin) =================
// 账号权威数据在 SSO；本工具仅同步"影子用户表"（供业务记录引用 user_id，保持历史数据稳定）
app.get('/api/admin/users', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const sso = await ssoRequest('GET', '/api/admin/users', null, true);
    if (sso.status !== 200 || !sso.json || !sso.json.ok) return res.status(502).json({ error: '账号服务暂不可用' });
    // SSO 用户 -> 本工具影子表对齐（新账号自动落影子表），再按影子表返回（保持前端结构不变）
    for (const u of sso.json.users) {
      const local = db.prepare('SELECT id FROM users WHERE username=?').get(u.username);
      if (!local) {
        db.prepare("INSERT INTO users (username, password_hash, real_name, role, store_id, active) VALUES (?, 'sso-managed', ?, ?, ?, ?)")
          .run(u.username, u.real_name || '', u.role, storeIdByCode(u.store_code), u.active);
      } else {
        db.prepare('UPDATE users SET real_name=?, role=?, store_id=?, active=? WHERE id=?')
          .run(u.real_name || '', u.role, storeIdByCode(u.store_code), u.active ? 1 : 0, local.id);
      }
    }
    const rows = db.prepare(`
      SELECT u.id, u.username, u.real_name, u.role, u.store_id, u.active, u.created_at,
        s.name AS store_name
      FROM users u LEFT JOIN stores s ON s.id = u.store_id
      ORDER BY u.id
    `).all();
    res.json(rows);
  } catch (e) {
    res.status(502).json({ error: '账号服务暂不可用，请稍后再试' });
  }
});

app.post('/api/admin/users', requireAuth, requireSuperAdmin, async (req, res) => {
  const { username, password, real_name, role, store_id } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: '账号和初始密码必填' });
  if (!['super_admin', 'manager', 'employee'].includes(role)) {
    return res.status(400).json({ error: '角色不合法' });
  }
  if (role !== 'super_admin' && !store_id) {
    return res.status(400).json({ error: '请选择所属门店' });
  }
  try {
    const sso = await ssoRequest('POST', '/api/admin/users', {
      username, password, real_name: real_name || '', role,
      store_code: role === 'super_admin' ? null : storeCodeById(Number(store_id)),
    }, true);
    if (sso.status !== 200 || !sso.json || !sso.json.ok) {
      return res.status(sso.status === 409 ? 400 : 502).json({ error: sso.json && sso.json.error ? sso.json.error : '账号服务异常' });
    }
    // 同步影子表
    let local = db.prepare('SELECT id FROM users WHERE username=?').get(username);
    if (!local) {
      const info = db.prepare("INSERT INTO users (username, password_hash, real_name, role, store_id, active) VALUES (?, 'sso-managed', ?, ?, ?, 1)")
        .run(username, real_name || '', role, role === 'super_admin' ? null : Number(store_id));
      res.json({ ok: true, id: info.lastInsertRowid });
    } else {
      res.json({ ok: true, id: local.id });
    }
  } catch (e) {
    res.status(502).json({ error: '账号服务暂不可用，请稍后再试' });
  }
});

app.post('/api/admin/users/:id', requireAuth, requireSuperAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  const { real_name, role, store_id, active, password } = req.body || {};
  if (role && !['super_admin', 'manager', 'employee'].includes(role)) {
    return res.status(400).json({ error: '角色不合法' });
  }
  const newRole = role || user.role;
  const newStore = newRole === 'super_admin' ? null
    : (store_id ? Number(store_id) : user.store_id);
  try {
    const sso = await ssoRequest('POST', '/api/admin/users/update', {
      username: user.username,
      real_name: real_name !== undefined ? real_name : user.real_name,
      role: newRole,
      store_code: newRole === 'super_admin' ? null : storeCodeById(newStore),
      active: active !== undefined ? (active ? 1 : 0) : user.active,
      password: password || undefined,
    }, true);
    if (sso.status !== 200 || !sso.json || !sso.json.ok) {
      return res.status(502).json({ error: sso.json && sso.json.error ? sso.json.error : '账号服务异常' });
    }
    db.prepare('UPDATE users SET real_name=?, role=?, store_id=?, active=? WHERE id=?')
      .run(real_name !== undefined ? real_name : user.real_name,
        newRole, newStore, active !== undefined ? (active ? 1 : 0) : user.active, id);
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: '账号服务暂不可用，请稍后再试' });
  }
});

// ================= STANDARD MANAGEMENT (super admin) =================
app.post('/api/admin/standard/photo', requireAuth, requireSuperAdmin, (req, res) => {
  upload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const itemId = Number(req.body.item_id);
    const item = db.prepare('SELECT * FROM cleaning_items WHERE id=?').get(itemId);
    if (!item) return res.status(404).json({ error: '清洁项不存在' });
    // remove old standard photo file
    if (item.standard_photo_path) {
      const old = path.join(uploadsDir, item.standard_photo_path);
      if (fs.existsSync(old)) { try { fs.unlinkSync(old); } catch (e) {} }
    }
    db.prepare('UPDATE cleaning_items SET standard_photo_path=? WHERE id=?')
      .run(req.file.filename, itemId);
    res.json({ ok: true, filename: req.file.filename });
  });
});

app.post('/api/admin/standard/note', requireAuth, requireSuperAdmin, (req, res) => {
  const { item_id, standard_note } = req.body || {};
  const item = db.prepare('SELECT * FROM cleaning_items WHERE id=?').get(Number(item_id));
  if (!item) return res.status(404).json({ error: '清洁项不存在' });
  db.prepare('UPDATE cleaning_items SET standard_note=? WHERE id=?')
    .run(standard_note || '', item.id);
  res.json({ ok: true });
});

app.delete('/api/admin/standard/photo', requireAuth, requireSuperAdmin, (req, res) => {
  const { item_id } = req.body || {};
  const item = db.prepare('SELECT * FROM cleaning_items WHERE id=?').get(Number(item_id));
  if (!item) return res.status(404).json({ error: '清洁项不存在' });
  if (item.standard_photo_path) {
    const old = path.join(uploadsDir, item.standard_photo_path);
    if (fs.existsSync(old)) { try { fs.unlinkSync(old); } catch (e) {} }
  }
  db.prepare('UPDATE cleaning_items SET standard_photo_path=? WHERE id=?').run('', item.id);
  res.json({ ok: true });
});

// ================= STORES / PORTAL (admin) =================
app.get('/api/admin/stores', requireAuth, (req, res) => {
  if (req.session.role === 'super_admin') {
    return res.json(db.prepare('SELECT id, code, name FROM stores ORDER BY id').all());
  }
  return res.json(db.prepare('SELECT id, code, name FROM stores WHERE id=?')
    .all(req.session.storeId));
});

app.get('/api/admin/dashboard', requireAuth, (req, res) => {
  const date = req.query.date;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date || '')) return res.status(400).json({ error: '日期参数错误' });
  let data = getDashboard(date);
  if (req.session.role !== 'super_admin') {
    data = data.filter(s => s.id === Number(req.session.storeId));
  }
  res.json(data);
});

app.get('/api/admin/records', requireAuth, (req, res) => {
  const storeId = Number(req.query.store_id);
  const form = req.query.form;
  const date = req.query.date;
  if (!storeId || !form || !/^\d{4}-\d{2}-\d{2}$/.test(date || '')) {
    return res.status(400).json({ error: '参数错误' });
  }
  if (!canAccessStore(req, storeId)) return res.status(403).json({ error: '无权操作其他门店' });
  res.json(getRecordDetail(storeId, form, date));
});

app.post('/api/admin/records', requireAuth, (req, res) => {
  const { store_id, form_code, record_date, inspector_name, notes, items } = req.body || {};
  if (!store_id || !form_code || !/^\d{4}-\d{2}-\d{2}$/.test(record_date || '')) {
    return res.status(400).json({ error: '参数错误' });
  }
  if (!canAccessStore(req, store_id)) return res.status(403).json({ error: '无权操作其他门店' });
  if (!Array.isArray(items)) return res.status(400).json({ error: '清洁项目数据错误' });

  const recordId = db.transaction(() => {
    let rec = db.prepare(`
      SELECT * FROM records WHERE store_id=? AND form_code=? AND record_date=?
    `).get(store_id, form_code, record_date);

    if (!rec) {
      const info = db.prepare(`
        INSERT INTO records (store_id, form_code, record_date, inspector_name, notes)
        VALUES (?, ?, ?, ?, ?)
      `).run(store_id, form_code, record_date, inspector_name || '', notes || '');
      rec = { id: info.lastInsertRowid };
    } else {
      db.prepare(`
        UPDATE records SET inspector_name=?, notes=?, updated_at=datetime('now','localtime')
        WHERE id=?
      `).run(inspector_name || '', notes || '', rec.id);
    }

    const upsert = db.prepare(`
      INSERT INTO record_items (record_id, item_id, is_done, cleaner_name, photo_path)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(record_id, item_id) DO UPDATE SET
        is_done=excluded.is_done,
        cleaner_name=excluded.cleaner_name,
        photo_path=excluded.photo_path
    `);
    items.forEach(it => {
      upsert.run(rec.id, Number(it.item_id), it.is_done ? 1 : 0,
        it.cleaner_name || '', it.photo_path || '');
    });
    return rec.id;
  })();

  res.json({ ok: true, record_id: recordId });
});

// Generic photo upload (any authenticated user; scope enforced on record save)
app.post('/api/admin/upload', requireAuth, (req, res) => {
  upload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    res.json({ ok: true, filename: req.file.filename, url: '/uploads/' + req.file.filename });
  });
});

app.delete('/api/admin/photo', requireAuth, (req, res) => {
  const { filename } = req.body || {};
  if (!filename || /[\\/]|\.\./.test(filename)) return res.status(400).json({ error: '参数错误' });
  const fp = path.join(uploadsDir, filename);
  if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch (e) {} }
  res.json({ ok: true });
});

// Gallery
app.post('/api/admin/gallery', requireAuth, (req, res) => {
  upload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const storeId = Number(req.body.store_id);
    if (!canAccessStore(req, storeId)) return res.status(403).json({ error: '无权操作其他门店' });
    const note = req.body.note || '';
    const info = db.prepare(`
      INSERT INTO gallery_photos (store_id, filename, note) VALUES (?, ?, ?)
    `).run(storeId, req.file.filename, note);
    res.json({ ok: true, id: info.lastInsertRowid, filename: req.file.filename });
  });
});

app.delete('/api/admin/gallery/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM gallery_photos WHERE id=?').get(Number(req.params.id));
  if (!row) return res.json({ ok: true });
  if (!canAccessStore(req, row.store_id)) return res.status(403).json({ error: '无权操作其他门店' });
  const fp = path.join(uploadsDir, row.filename);
  if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch (e) {} }
  db.prepare('DELETE FROM gallery_photos WHERE id=?').run(row.id);
  res.json({ ok: true });
});

app.get('/api/admin/gallery', requireAuth, (req, res) => {
  const storeId = Number(req.query.store_id);
  if (!storeId) return res.status(400).json({ error: '参数错误' });
  if (!canAccessStore(req, storeId)) return res.status(403).json({ error: '无权操作其他门店' });
  res.json(db.prepare(`
    SELECT id, filename, note, uploaded_at FROM gallery_photos
    WHERE store_id=? ORDER BY uploaded_at DESC
  `).all(storeId));
});

app.get('/api/admin/qrcode/:code', requireAuth, requireSuperAdmin, async (req, res) => {
  const store = db.prepare('SELECT * FROM stores WHERE code=?').get(req.params.code);
  if (!store) return res.status(404).json({ error: '门店不存在' });
  const url = `${req.protocol}://${req.get('host')}/s/${store.code}`;
  try {
    const dataUrl = await QRCode.toDataURL(url, { width: 480, margin: 2 });
    res.json({ ok: true, url, dataUrl, store_name: store.name });
  } catch (e) {
    res.status(500).json({ error: '二维码生成失败' });
  }
});

// ================= BANNER (super admin) =================
app.post('/api/admin/banner', requireAuth, requireSuperAdmin, (req, res) => {
  upload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const ext = (path.extname(req.file.originalname) || '.jpg').toLowerCase();
    const newName = 'banner_' + Date.now() + ext;
    const target = path.join(__dirname, 'public', newName);
    try {
      fs.renameSync(req.file.path, target);
    } catch (e) {
      return res.status(500).json({ error: '保存失败，请重试' });
    }
    // 删除旧的 banner 文件（仅删除 settings 记录指向的文件）
    const row = db.prepare("SELECT value FROM settings WHERE key='banner_path'").get();
    if (row && row.value) {
      const old = path.join(__dirname, 'public', row.value);
      if (old !== target && fs.existsSync(old)) {
        try { fs.unlinkSync(old); } catch (e) {}
      }
    }
    db.prepare(`
      INSERT INTO settings (key, value) VALUES ('banner_path', ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `).run(newName);
    res.json({ ok: true, url: '/' + newName + '?v=' + Date.now() });
  });
});

// ================= SOP FILES (super admin upload/delete, everyone reads) =================
app.post('/api/admin/sop', requireAuth, requireSuperAdmin, (req, res) => {
  sopUpload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: '未收到文件' });
    const info = db.prepare(`
      INSERT INTO sop_files (filename, orig_name, mime, size, uploaded_by)
      VALUES (?, ?, ?, ?, ?)
    `).run(req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, req.session.userId);
    res.json({ ok: true, id: info.lastInsertRowid, filename: req.file.filename });
  });
});

app.delete('/api/admin/sop/:id', requireAuth, requireSuperAdmin, (req, res) => {
  const row = db.prepare('SELECT * FROM sop_files WHERE id=?').get(Number(req.params.id));
  if (!row) return res.json({ ok: true });
  const fp = path.join(sopDir, row.filename);
  if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch (e) {} }
  db.prepare('DELETE FROM sop_files WHERE id=?').run(row.id);
  res.json({ ok: true });
});

// 健康检查（部署脚本与监控用；顺带验证数据库可读）
app.get('/api/health', (req, res) => {
  try {
    const stores = db.prepare('SELECT COUNT(*) AS c FROM stores').get().c;
    res.json({ ok: true, service: 'kitchen-clean', stores, ts: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, service: 'kitchen-clean', error: String(e && e.message) });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// 仅监听本机回环地址：外网不能直连，统一由 Nginx 反向代理对外
// 过期会话清理：启动清一次，之后每小时清一次。
// store 的 get() 会按 expire 过滤，所以过期会话在功能上已经失效，但行会一直堆在表里。
// 留 24 小时宽限期，避免删掉正在被并发请求使用的那一条。
function purgeExpiredSessions() {
  try {
    const r = db.prepare('DELETE FROM sessions WHERE expire < ?').run(Date.now() - 24 * 60 * 60 * 1000);
    if (r.changes) console.log(`[kitchen-clean] 清理过期会话 ${r.changes} 条`);
  } catch (e) {
    console.error('[kitchen-clean] 清理过期会话失败:', e.message);
  }
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, '127.0.0.1', () => {
  console.log(`于百万·QSC管理系统运行中，端口 ${PORT}（仅本机，Nginx 反向代理对外）`);
});
