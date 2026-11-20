// 于百万·外卖业绩通晒系统（Excel 上传解析版） - 服务入口
// 架构规范：
//   - 独立项目：代码 /home/sangyu/apps/shop-performance；数据 /opt/app-data/shop-performance
//   - 账号体系：完全复用 QSC 系统（唯一身份源，代理验证，本服务不存账号/密码）
//   - 角色：super_admin 项目负责人 / manager 店长 / employee 店员
// 权限矩阵：
//   super_admin: 全部门店 + 配置目标 + 上传数据 + 排名海报
//   manager:     仅本店（上传本店、看本店、海报本店）
//   employee:    仅本店只读
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const db = require('./db');
const { parseGuandian } = require('./parsers/meituan_guandian');
// 公共运行时核心（shared/ybw-core.js，部署时自动注入本目录）
const core = require('./ybw-core');

const app = express();
const PORT = process.env.PORT || 3101;
// 生产全站 HTTPS：cookie 必须带 Secure。预发布走 http 隧道时用 COOKIE_INSECURE=1 关闭
// 判定统一在 core，同时兼容旧变量名 SSO_COOKIE_INSECURE
const COOKIE_SECURE = core.isCookieInsecure() ? '' : '; Secure';

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- 独立登录会话（账号复用 QSC，登录态本服务独立、持久化） ----------
// 设计：本工具打开后先登录（QSC 账号密码），登录成功后本服务签发 sp_sid 会话，
// 会话存入本地数据库（服务重启不丢）；后续接口只认 sp_sid，不依赖 QSC 侧登录态。
// QSC 是唯一身份源，本服务不存密码。
const SESSION_MS = 7 * 24 * 60 * 60 * 1000; // 7 天免登录（同一设备）
const SSO_RECHECK_MS = 60 * 1000;           // 每 60 秒回验一次 SSO，账号停用后本地会话立即失效

// ---------- 登录限流（防暴力破解） ----------
// 实现下沉到 core，四个应用共用同一套逻辑与参数
const clientIpOf = core.clientIp;
const rateLimit = core.createRateLimiter({
  windowMs: 60 * 1000,
  maxHits: 10,
  message: '尝试过于频繁，请 1 分钟后再试'
});

// 调用 SSO（内部回环），实现在 core.ssoRequest，此处保留原签名
function httpJson(method, pathname, bodyObj, token, clientIp) {
  return core.ssoRequest({
    method: method,
    path: pathname,
    body: bodyObj,
    token: token,
    clientIp: clientIp
  });
}

function getSid(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/sp_sid=([^;]+)/);
  return m ? m[1] : null;
}

async function requireAuth(req, res, next) {
  if (req.user) return next();
  const sid = getSid(req);
  if (!sid) return res.status(401).json({ error: '未登录' });
  const row = db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
  if (!row || row.expire < Date.now()) {
    if (row) db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
  req.user = { username: row.username, role: row.role, real_name: row.real_name, store_id: row.store_id != null ? row.store_id : null };
  next();
}

// ===== 共享登录态：门户登录一次，本工具自动免登 =====
const SSO_COOKIE_NAME = core.SHARED_COOKIE_NAME;

function getSharedToken(req) {
  const token = core.parseCookies(req)[SSO_COOKIE_NAME];
  return token ? decodeURIComponent(token) : null;
}

// 共享会话有效时，签发本工具本地 sp_sid 会话（业绩接口全部依赖 sp_sid）
function createLocalSession(info, res, ssoToken) {
  let storeId = null;
  if (info.store_code) {
    const st = db.prepare('SELECT id FROM stores WHERE code = ?').get(info.store_code);
    if (st) storeId = st.id;
  }
  const sid = crypto.randomBytes(24).toString('hex');
  const expire = Date.now() + SESSION_MS;
  db.prepare(`
    INSERT INTO sessions (sid, username, role, real_name, store_id, expire, sso_token, sso_checked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(sid) DO UPDATE SET username=excluded.username, role=excluded.role,
      real_name=excluded.real_name, store_id=excluded.store_id, expire=excluded.expire,
      sso_token=excluded.sso_token, sso_checked_at=excluded.sso_checked_at
  `).run(sid, info.username, info.role, info.real_name || info.username, storeId, expire,
         ssoToken || null, Date.now());
  res.append('Set-Cookie', `sp_sid=${sid}; Path=/; HttpOnly; SameSite=Lax${COOKIE_SECURE}; Max-Age=${SESSION_MS / 1000}`);
  return { username: info.username, role: info.role, real_name: info.real_name || info.username, store_id: storeId };
}

app.use(async (req, res, next) => {
  const sid = getSid(req);
  if (sid) {
    let row = db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
    if (row && row.expire >= Date.now()) {
      // 定期回验 SSO：账号被停用/删除/改角色后，本地会话最多 60 秒内失效
      // （改造前是签发后 7 天内不再回查，停用账号可继续使用一周）
      const needsCheck = !row.sso_checked_at || Date.now() - row.sso_checked_at > SSO_RECHECK_MS;
      if (needsCheck && row.sso_token) {
        try {
          const r = await httpJson('GET', '/api/auth/session', null, row.sso_token);
          if (r.status === 401) {
            db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
            row = null;
          } else if (r.status === 200 && r.json && r.json.ok) {
            db.prepare('UPDATE sessions SET sso_checked_at = ?, role = ?, real_name = ? WHERE sid = ?')
              .run(Date.now(), r.json.role, r.json.real_name || row.real_name, sid);
            row.role = r.json.role;
            row.real_name = r.json.real_name || row.real_name;
          } else {
            db.prepare('UPDATE sessions SET sso_checked_at = ? WHERE sid = ?').run(Date.now(), sid);
          }
        } catch (e) {
          // SSO 暂时不可用时放行，避免把所有人挡在门外（可用性优先）
        }
      }
      if (row) {
        req.user = { username: row.username, role: row.role, real_name: row.real_name, store_id: row.store_id != null ? row.store_id : null };
        return next();
      }
    } else if (row) {
      db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
    }
  }
  const token = getSharedToken(req);
  if (!token) return next();
  try {
    const r = await httpJson('GET', '/api/auth/session', null, token);
    if (r.status === 200 && r.json && r.json.ok) {
      req.user = createLocalSession(r.json, res, token);
    }
  } catch (e) {}
  next();
});

// 角色守卫：仅项目负责人
function requireSuper(req, res, next) {
  if (req.user.role !== 'super_admin') return res.status(403).json({ error: '仅项目负责人可操作' });
  next();
}

// 门店范围守卫原为 scopeStore()，实际各处接口都是内联按 store_id 过滤（见 records / targets 查询），
// 该函数从未被调用，2026-11 清理死代码时移除。

// ---------- Excel 上传（20MB 上限，中文文件名兼容） ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + path.extname(file.originalname || '.xlsx').toLowerCase()),
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  defParamCharset: 'utf8',
  fileFilter: (req, file, cb) => {
    const ok = /\.(xlsx|xls|csv)$/i.test(file.originalname);
    if (ok) cb(null, true); else cb(new Error('仅支持 xlsx / xls / csv 文件'));
  },
});

// ---------- 门店（权限过滤；仅展示营业中门店 active=1） ----------
app.get('/api/stores', requireAuth, (req, res) => {
  let rows;
  if (req.user.role === 'super_admin') {
    rows = db.prepare('SELECT id, code, name FROM stores WHERE active=1 ORDER BY id').all();
  } else {
    rows = db.prepare('SELECT id, code, name FROM stores WHERE id=? AND active=1').all(req.user.store_id);
  }
  res.json(rows);
});

// ---------- 目标配置 CRUD（仅项目负责人） ----------
app.get('/api/targets', requireAuth, (req, res) => {
  const { date } = req.query;
  let sql = `SELECT t.id, t.store_id, s.name AS store_name, t.platform, t.date,
                    t.target_amount, t.target_orders
             FROM targets t JOIN stores s ON s.id = t.store_id`;
  const cond = [];
  const params = [];
  if (req.user.role !== 'super_admin') { cond.push('t.store_id = ?'); params.push(req.user.store_id); }
  if (date) { cond.push('t.date = ?'); params.push(date); }
  if (cond.length) sql += ' WHERE ' + cond.join(' AND ');
  sql += ' ORDER BY t.date DESC, s.id, t.platform';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/targets', requireAuth, requireSuper, (req, res) => {
  const { store_id, platform, date, target_amount, target_orders } = req.body || {};
  if (!store_id || !platform || !date) return res.status(400).json({ error: '门店、平台、日期必填' });
  if (!['meituan', 'taobao_flash', 'jd'].includes(platform)) return res.status(400).json({ error: '平台不合法' });
  const amount = Number(target_amount) || 0;
  const orders = Number(target_orders) || 0;
  db.prepare(`
    INSERT INTO targets (store_id, platform, date, target_amount, target_orders)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(store_id, platform, date)
    DO UPDATE SET target_amount=excluded.target_amount, target_orders=excluded.target_orders
  `).run(store_id, platform, date, amount, orders);
  res.json({ ok: true });
});

app.delete('/api/targets/:id', requireAuth, requireSuper, (req, res) => {
  db.prepare('DELETE FROM targets WHERE id=?').run(Number(req.params.id));
  res.json({ ok: true });
});

// ---------- 实际业绩查询（含目标差值计算，门店范围过滤） ----------
app.get('/api/performance', requireAuth, (req, res) => {
  const { date, start, end } = req.query;
  if (!date && !(start && end)) return res.status(400).json({ error: '需要 date 或 start+end' });

  let where, params;
  if (date) { where = 'r.date = ?'; params = [date]; }
  else { where = 'r.date BETWEEN ? AND ?'; params = [start, end]; }
  if (req.user.role !== 'super_admin') { where += ' AND r.store_id = ?'; params.push(req.user.store_id); }

  const rows = db.prepare(`
    SELECT r.store_id, s.name AS store_name, r.platform, r.date,
           r.turnover, r.income, r.discount, r.orders, r.avg_pre, r.avg_post,
           t.target_amount, t.target_orders
    FROM records r
    JOIN stores s ON s.id = r.store_id
    LEFT JOIN targets t ON t.store_id = r.store_id AND t.platform = r.platform AND t.date = r.date
    WHERE ${where}
    ORDER BY s.id, r.platform
  `).all(...params);

  const enriched = rows.map(r => {
    const ta = r.target_amount || 0, to = r.target_orders || 0;
    // 差额口径默认用 营业额(turnover)；后续可按用户要求切换 income
    const gap_amount = Math.round((ta - r.turnover) * 100) / 100; // 营业额差额（负=超额）
    const gap_orders = to - r.orders;                             // 单量差额
    const rate = ta > 0 ? Math.round((r.turnover / ta) * 1000) / 10 : null;
    const orders_rate = to > 0 ? Math.round((r.orders / to) * 1000) / 10 : null;
    return { ...r, gap_amount, gap_orders, rate, orders_rate,
             status: rate == null ? '无目标' : (rate >= 100 ? '超额' : '缺口') };
  });
  res.json(enriched);
});

// ---------- 月度目标 CRUD（仅项目负责人） ----------
app.get('/api/monthly-targets', requireAuth, (req, res) => {
  const { month } = req.query;
  let sql = `SELECT mt.id, mt.store_id, s.name AS store_name, mt.month, mt.target_amount
             FROM monthly_targets mt JOIN stores s ON s.id = mt.store_id
             WHERE s.active = 1`;
  const cond = [], params = [];
  if (req.user.role !== 'super_admin') { cond.push('mt.store_id = ?'); params.push(req.user.store_id); }
  if (month) { cond.push('mt.month = ?'); params.push(month); }
  if (cond.length) sql += ' AND ' + cond.join(' AND ');
  sql += ' ORDER BY mt.month DESC, s.id';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/monthly-targets', requireAuth, requireSuper, (req, res) => {
  const { store_id, month, target_amount } = req.body || {};
  if (!store_id || !month || target_amount == null) return res.status(400).json({ error: '门店、月份、目标金额必填' });
  if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: '月份格式应为 YYYY-MM' });
  db.prepare(`
    INSERT INTO monthly_targets (store_id, month, target_amount)
    VALUES (?, ?, ?)
    ON CONFLICT(store_id, month) DO UPDATE SET
      target_amount=excluded.target_amount, updated_at=datetime('now','localtime')
  `).run(store_id, month, Number(target_amount));
  res.json({ ok: true });
});

app.delete('/api/monthly-targets/:id', requireAuth, requireSuper, (req, res) => {
  db.prepare('DELETE FROM monthly_targets WHERE id=?').run(Number(req.params.id));
  res.json({ ok: true });
});

// ---------- 综合看板：单日完成率 + 累计进度 + 渠道明细 + 排名 ----------
// GET /api/dashboard?date=YYYY-MM-DD
app.get('/api/dashboard', requireAuth, (req, res) => {
  const { date } = req.query;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: '需要 date=YYYY-MM-DD' });
  const month = date.slice(0, 7);
  const dayOfMonth = Number(date.slice(8, 10));
  const daysInMonth = new Date(Number(date.slice(0, 4)), Number(date.slice(5, 7)), 0).getDate();

  // 门店列表（权限过滤 + 仅营业中）
  const stores = req.user.role === 'super_admin'
    ? db.prepare('SELECT id, code, name FROM stores WHERE active=1 ORDER BY id').all()
    : db.prepare('SELECT id, code, name FROM stores WHERE id=? AND active=1').all(req.user.store_id);

  // 当日与当月记录
  const dayRows = db.prepare('SELECT * FROM records WHERE date = ?').all(date);
  const cumRows = db.prepare(
    'SELECT * FROM records WHERE date >= ? AND date <= ?'
  ).all(month + '-01', date);
  const targets = Object.fromEntries(
    db.prepare('SELECT store_id, target_amount FROM monthly_targets WHERE month=?').all(month)
      .map(r => [r.store_id, r.target_amount])
  );

  const storeAgg = (rows) => {
    const m = {};
    for (const r of rows) {
      if (!m[r.store_id]) m[r.store_id] = { income: 0, orders: 0, dine_in_income: 0, dine_in_orders: 0, groupon: 0, meituan: 0, meituan_orders: 0, tf: 0, tf_orders: 0, jd: 0, jd_orders: 0 };
      const a = m[r.store_id];
      a.income += r.income;
      a.orders += r.orders;
      if (r.platform === 'meituan') {
        // 堂食/团购仅存于 meituan 行，只在此累加一次
        a.income += r.dine_in_income;
        a.orders += r.dine_in_orders;
        a.dine_in_income += r.dine_in_income;
        a.dine_in_orders += r.dine_in_orders;
        a.groupon += r.groupon_income;
        a.meituan += r.income; a.meituan_orders += r.orders;
      }
      if (r.platform === 'taobao_flash') { a.tf += r.income; a.tf_orders += r.orders; }
      if (r.platform === 'jd') { a.jd += r.income; a.jd_orders += r.orders; }
    }
    return m;
  };

  const dayAgg = storeAgg(dayRows), cumAgg = storeAgg(cumRows);

  const result = stores.map(st => {
    const t = targets[st.id] || 0;
    const dailyTarget = daysInMonth > 0 ? t / daysInMonth : 0;
    const today = dayAgg[st.id] || { income: 0, orders: 0, dine_in_income: 0, dine_in_orders: 0, groupon: 0, meituan: 0, meituan_orders: 0, tf: 0, tf_orders: 0, jd: 0, jd_orders: 0 };
    const cum = cumAgg[st.id] || { income: 0, orders: 0 };
    const progressTarget = daysInMonth > 0 ? t * (dayOfMonth / daysInMonth) : 0;
    const day_rate = dailyTarget > 0 ? Math.round((today.income / dailyTarget) * 1000) / 10 : null;
    const cum_rate = t > 0 ? Math.round((cum.income / t) * 1000) / 10 : null;
    const cum_progress_rate = progressTarget > 0 ? Math.round((cum.income / progressTarget) * 1000) / 10 : null;
    return {
      store_id: st.id, store_name: st.name,
      month, date, day_of_month: dayOfMonth, days_in_month: daysInMonth,
      target_month: t, target_daily: Math.round(dailyTarget * 100) / 100,
      today_income: Math.round(today.income * 100) / 100,
      today_orders: today.orders,
      today: {
        dine_in: { income: Math.round(today.dine_in_income * 100) / 100, orders: today.dine_in_orders },
        meituan: { income: Math.round(today.meituan * 100) / 100, orders: today.meituan_orders },
        taobao_flash: { income: Math.round(today.tf * 100) / 100, orders: today.tf_orders },
        jd: { income: Math.round(today.jd * 100) / 100, orders: today.jd_orders },
        groupon: Math.round(today.groupon * 100) / 100,
      },
      day_rate, day_status: day_rate == null ? '无目标' : (day_rate >= 100 ? '超额' : '缺口'),
      gap_today: dailyTarget > 0 ? Math.round((dailyTarget - today.income) * 100) / 100 : null,
      gap_month: t > 0 ? Math.round((t - cum.income) * 100) / 100 : null,
      // 按时间进度应达后的累计缺口：正数=还差多少才跟上进度，负数=已超前
      gap_progress: progressTarget > 0 ? Math.round((progressTarget - cum.income) * 100) / 100 : null,
      month_cum: { income: Math.round(cum.income * 100) / 100, orders: cum.orders },
      cum_progress_target: Math.round(progressTarget * 100) / 100,
      cum_progress_rate,
      cum_rate, cum_status: t > 0 ? (cum_rate >= 100 ? '达标' : '未达标') : '无目标',
    };
  });

  // 堂食 TOP 排名（按堂食营收降序 1/2/3；堂食为纯增量渠道，独立标识）
  const dineRank = [...result].sort((a, b) => b.today.dine_in.income - a.today.dine_in.income);
  const dineMap = Object.fromEntries(dineRank.map((r, i) => [r.store_name, i + 1]));
  for (const r of result) r.t_dine_in = dineMap[r.store_name];

  // 排名（按单日完成率，含数据门店优先）
  const withData = result.filter(r => r.today_orders > 0 || r.target_daily > 0);
  const ranking = withData
    .map((r, i) => ({ rank: i + 1, store_name: r.store_name, day_rate: r.day_rate, day_status: r.day_status }))
    .sort((a, b) => (b.day_rate ?? -1) - (a.day_rate ?? -1))
    .map((r, i) => ({ ...r, rank: i + 1 }));

  // 全店月度进度汇总（只汇总配置了月目标的门店，金额均为"元"）
  const tStores = result.filter(r => r.target_month > 0);
  const sumBy = (fn) => Math.round(tStores.reduce((a, r) => a + fn(r), 0) * 100) / 100;
  const totProgress = sumBy(r => r.cum_progress_target);
  const totCum = sumBy(r => r.month_cum.income);
  const totTarget = sumBy(r => r.target_month);
  const totals = {
    store_count: tStores.length,
    target_month: totTarget,
    cum_progress_target: totProgress,
    month_cum_income: totCum,
    month_cum_orders: tStores.reduce((a, r) => a + r.month_cum.orders, 0),
    gap_progress: Math.round((totProgress - totCum) * 100) / 100,
    gap_month: Math.round((totTarget - totCum) * 100) / 100,
    cum_progress_rate: totProgress > 0 ? Math.round((totCum / totProgress) * 1000) / 10 : null,
  };

  res.json({ date, month, day_of_month: dayOfMonth, days_in_month: daysInMonth, stores: result, ranking, totals });
});

// ---------- 最近有数据的日期（前端默认日期用） ----------
app.get('/api/latest-date', requireAuth, (req, res) => {
  const row = db.prepare('SELECT MAX(date) AS d FROM records').get();
  res.json({ latest: row.d || null });
});

// ---------- 月度视图：整月逐日数据（月度复盘表） ----------
// GET /api/month-view?month=YYYY-MM
app.get('/api/month-view', requireAuth, (req, res) => {
  const { month } = req.query;
  if (!month || !/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: '需要 month=YYYY-MM' });
  const stores = req.user.role === 'super_admin'
    ? db.prepare('SELECT id, name FROM stores WHERE active=1 ORDER BY id').all()
    : db.prepare('SELECT id, name FROM stores WHERE id=? AND active=1').all(req.user.store_id);
  const rows = db.prepare('SELECT * FROM records WHERE date >= ? AND date <= ?').all(month + '-01', month + '-31');
  const targets = Object.fromEntries(
    db.prepare('SELECT store_id, target_amount FROM monthly_targets WHERE month=?').all(month).map(r => [r.store_id, r.target_amount])
  );
  const byDay = {};
  for (const r of rows) {
    const d = Number(r.date.slice(8, 10));
    const key = r.store_id + '-' + d;
    if (!byDay[key]) byDay[key] = { income: 0, orders: 0 };
    byDay[key].income += r.income;
    byDay[key].orders += r.orders;
    if (r.platform === 'meituan') {
      byDay[key].income += r.dine_in_income;
      byDay[key].orders += r.dine_in_orders;
    }
  }
  const daysInMonth = new Date(Number(month.slice(0,4)), Number(month.slice(5,7)), 0).getDate();
  // 时间进度的截止日：海报/前端传 asof（查询日）；未传时取该月最后有数据的日期
  let progressDays = daysInMonth;
  const asof = req.query.asof;
  if (asof && /^\d{4}-\d{2}-\d{2}$/.test(asof) && asof.slice(0, 7) === month) {
    progressDays = Math.min(daysInMonth, Number(asof.slice(8, 10)));
  } else {
    const lastRow = db.prepare('SELECT MAX(date) AS d FROM records WHERE date >= ? AND date <= ?').get(month + '-01', month + '-31');
    if (lastRow && lastRow.d) progressDays = Math.min(daysInMonth, Number(lastRow.d.slice(8, 10)));
  }
  const result = stores.map(st => {
    const days = [];
    let cum = 0, cumOrders = 0;
    for (let d = 1; d <= daysInMonth; d++) {
      const v = byDay[st.id + '-' + d];
      const income = v ? Math.round(v.income * 100) / 100 : null;
      const orders = v ? v.orders : null;
      days.push({ day: d, income, orders });
      if (income != null) { cum += income; cumOrders += orders; }
    }
    const t = targets[st.id] || 0;
    const progressTarget = t > 0 ? t * (progressDays / daysInMonth) : 0;
    return {
      store_id: st.id, store_name: st.name, target_amount: t,
      days, month_cum: Math.round(cum * 100) / 100, month_orders: cumOrders,
      cum_rate: t > 0 ? Math.round((cum / t) * 1000) / 10 : null,
      cum_status: t > 0 ? (cum / t >= 1 ? '达标' : '未达标') : '无目标',
      // 按时间进度（截至 progressDays）应达金额与累计缺口
      progress_days: progressDays,
      progress_target: Math.round(progressTarget * 100) / 100,
      gap_progress: t > 0 ? Math.round((progressTarget - cum) * 100) / 100 : null,
    };
  });
  const ranked = [...result].sort((a, b) => {
    const ra = a.cum_rate, rb = b.cum_rate;
    if (ra == null && rb == null) return b.month_cum - a.month_cum;
    if (ra == null) return 1;
    if (rb == null) return -1;
    return rb - ra;
  }).map((r, i) => ({ ...r, rank: i + 1 }));

  // 全店月度进度汇总（只汇总配置了月目标的门店）
  const tStores = ranked.filter(r => r.target_amount > 0);
  const sumBy = (fn) => Math.round(tStores.reduce((a, r) => a + fn(r), 0) * 100) / 100;
  const totProgress = sumBy(r => r.progress_target);
  const totCum = sumBy(r => r.month_cum);
  const totTarget = sumBy(r => r.target_amount);
  const totals = {
    store_count: tStores.length,
    target_month: totTarget,
    progress_target: totProgress,
    month_cum: totCum,
    gap_progress: Math.round((totProgress - totCum) * 100) / 100,
    gap_month: Math.round((totTarget - totCum) * 100) / 100,
    cum_progress_rate: totProgress > 0 ? Math.round((totCum / totProgress) * 1000) / 10 : null,
  };
  res.json({ month, days_in_month: daysInMonth, progress_days: progressDays, stores: ranked, totals });
});

// ---------- 环同比对比（7 天 / 30 天窗口） ----------
// GET /api/compare?date=YYYY-MM-DD&window=7|30
//
// 三个口径：
//   current  本期：[date-(w-1), date]
//   prev     环比：紧邻本期之前、等长的 w 天
//   yoy      同比：本期整体前移一年（去年同期）
//
// 每个口径都给出「营收 / 单量 / 客单价」的绝对值，以及相对本期的百分比与差额，
// 让页面既能说「涨了 12.4%」也能说「多了 ¥3,281」。
// 没有数据的口径不编造 0，而是 available=false 并说明原因（同比通常属于这种情况：
// 系统从 2026-10 才开始有记录，去年同期的自然年区间必然是空的）。

const round2 = (n) => Math.round(n * 100) / 100;

function shiftDate(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function shiftYear(dateStr, years) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCFullYear(d.getUTCFullYear() + years);
  return d.toISOString().slice(0, 10);
}

/** 一段记录的营收/单量汇总。堂食与团购只挂在 meituan 行上，只加一次，避免重复。 */
function sumRecords(rows) {
  let revenue = 0, orders = 0;
  for (const r of rows) {
    revenue += r.income || 0;
    orders += r.orders || 0;
    if (r.platform === 'meituan') {
      revenue += r.dine_in_income || 0;
      orders += r.dine_in_orders || 0;
    }
  }
  return {
    revenue: round2(revenue),
    orders,
    avg_ticket: orders > 0 ? round2(revenue / orders) : null
  };
}

/* ---------- 分析用的基础统计（无第三方依赖，口径写死在这里便于测试） ---------- */
const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
const median = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const stdev = (a, mu) => {
  if (a.length < 2) return null;
  const m = mu == null ? mean(a) : mu;
  return Math.sqrt(a.reduce((s, v) => s + (v - m) ** 2, 0) / (a.length - 1));
};
const isWeekend = (d) => {
  const w = new Date(d + 'T00:00:00Z').getUTCDay();
  return w === 0 || w === 6;
};

const CH_NAME = { dine_in: '堂食', meituan: '美团', taobao_flash: '淘闪', jd: '京东' };

/**
 * 渠道拆分。堂食与团购都只挂在 meituan 行上（入库时为了避免三行重复统计而这么存），
 * 所以只有看到 meituan 行时才累加，否则会翻三倍。
 * 团购已计入堂食营收，单独列出来只作为「堂食里有多少来自团购」的说明，不再叠加进合计。
 */
function channelSum(rows) {
  const v = { dine_in: 0, meituan: 0, taobao_flash: 0, jd: 0, groupon: 0 };
  for (const r of rows) {
    if (r.platform === 'meituan') {
      v.dine_in += r.dine_in_income || 0;
      v.meituan += r.income || 0;
      v.groupon += r.groupon_income || 0;
    } else if (r.platform === 'taobao_flash') {
      v.taobao_flash += r.income || 0;
    } else if (r.platform === 'jd') {
      v.jd += r.income || 0;
    }
  }
  for (const k of Object.keys(v)) v[k] = round2(v[k]);
  v.total = round2(v.dine_in + v.meituan + v.taobao_flash + v.jd);
  return v;
}

/** 相对基准的变化：百分比 + 绝对差额。基准为 0 或缺数时一律不可比，宁可留空也不给出误导性的差额。 */
function deltaOf(cur, base, key) {
  const c = cur[key], b = base[key];
  if (c == null || b == null || b === 0) return { diff: null, pct: null };
  const diff = round2(c - b);
  return { diff, pct: Math.round((diff / b) * 1000) / 10 };
}

app.get('/api/compare', requireAuth, (req, res) => {
  const { date } = req.query;
  const window = Number(req.query.window || 7);
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ error: '需要 date=YYYY-MM-DD' });
  }
  if (![7, 30].includes(window)) {
    return res.status(400).json({ error: 'window 只支持 7 或 30' });
  }

  const span = (end) => ({ start: shiftDate(end, -(window - 1)), end });
  const curR = span(date);
  const prevR = span(shiftDate(curR.start, -1));
  const yoyR = span(shiftYear(date, -1));

  const stores = req.user.role === 'super_admin'
    ? db.prepare('SELECT id, code, name FROM stores WHERE active=1 ORDER BY id').all()
    : db.prepare('SELECT id, code, name FROM stores WHERE id=? AND active=1').all(req.user.store_id);

  // 一次取出覆盖三段的最小区间，避免三次全表扫描。
  // 必须按「当前可见门店」过滤：大悦城店已闭店（active=0），它的历史记录仍在库里，
  // 若混进全店合计，会让环比增速被低估、各店贡献加起来超过 100%。
  const minStart = [curR.start, prevR.start, yoyR.start].sort()[0];
  const maxEnd = [curR.end, prevR.end, yoyR.end].sort().slice(-1)[0];
  const storeIds = new Set(stores.map(s => s.id));
  const allRows = db.prepare('SELECT * FROM records WHERE date >= ? AND date <= ?').all(minStart, maxEnd)
    .filter(r => storeIds.has(r.store_id));

  const inRange = (r, a, b) => r.date >= a && r.date <= b;
  const curRows = allRows.filter(r => inRange(r, curR.start, curR.end));
  const prevRows = allRows.filter(r => inRange(r, prevR.start, prevR.end));
  const yoyRows = allRows.filter(r => inRange(r, yoyR.start, yoyR.end));

  const label = (a, b) => a.slice(5).replace('-', '.') + '–' + b.slice(5).replace('-', '.');

  const pack = (rows, range) => {
    const s = sumRecords(rows);
    const days = new Set(rows.map(r => r.date)).size;
    const empty = days === 0;
    // 没有数据的期间返回 null 而不是 0：0 会被读成"当天真的没卖"，null 才是"没有记录"
    return {
      start: range.start, end: range.end, label: label(range.start, range.end),
      revenue: empty ? null : s.revenue,
      orders: empty ? null : s.orders,
      avg_ticket: empty ? null : s.avg_ticket,
      days_with_data: days,
      available: !empty
    };
  };

  const current = pack(curRows, curR);
  const prev = pack(prevRows, prevR);
  const yoy = pack(yoyRows, yoyR);
  if (!yoy.available) {
    yoy.reason = '去年同期（' + yoy.start + ' 起 ' + window + ' 天）没有数据';
  }
  if (!prev.available) {
    prev.reason = '上个' + window + '天（' + prev.start + ' 起）没有数据';
  }

  const deltaFor = (base) => ({
    revenue: deltaOf(current, base, 'revenue'),
    orders: deltaOf(current, base, 'orders'),
    avg_ticket: deltaOf(current, base, 'avg_ticket')
  });

  // 逐日序列：全店与分店各一份。分店这份是「各门店营收走势图」的数据源，
  // 与全店序列共用同一套按日期对齐的逻辑，缺数的日期给 null（不补 0，避免曲线掉到底）。
  const seriesOf = (rows, range) => {
    const map = {};
    for (const r of rows) {
      const k = r.date;
      if (!map[k]) map[k] = { revenue: 0, orders: 0 };
      map[k].revenue += (r.income || 0) + (r.platform === 'meituan' ? (r.dine_in_income || 0) : 0);
      map[k].orders += (r.orders || 0) + (r.platform === 'meituan' ? (r.dine_in_orders || 0) : 0);
    }
    const out = [];
    for (let i = 0; i < window; i++) {
      const d = shiftDate(range.start, i);
      const v = map[d];
      out.push({
        date: d,
        revenue: v ? round2(v.revenue) : null,
        orders: v ? v.orders : null
      });
    }
    return out;
  };

  const totalCur = seriesOf(curRows, curR);
  const totalPrev = seriesOf(prevRows, prevR);
  const totalYoy = seriesOf(yoyRows, yoyR);

  // 全店渠道拆分（本期 / 环比期）
  const chCur = channelSum(curRows), chPrev = channelSum(prevRows);
  const chRows = ['dine_in', 'meituan', 'taobao_flash', 'jd'].map(k => {
    const cur = chCur[k], prev = chPrev[k];
    const share = chCur.total > 0 ? (cur / chCur.total) * 100 : null;
    const sharePrev = chPrev.total > 0 ? (prev / chPrev.total) * 100 : null;
    return {
      key: k, name: CH_NAME[k],
      current: cur, prev,
      diff: round2(cur - prev),
      pct: deltaOf({ v: cur }, { v: prev }, 'v').pct,
      share: share == null ? null : Math.round(share * 10) / 10,
      share_prev: sharePrev == null ? null : Math.round(sharePrev * 10) / 10,
      share_pp: share == null || sharePrev == null ? null : Math.round((share - sharePrev) * 10) / 10
    };
  });

  // 分门店：汇总 + 逐日序列 + 渠道 + 对大盘变动的贡献
  const totalDiff = current.available && prev.available ? round2(current.revenue - prev.revenue) : null;
  const baseRev = prev.available ? prev.revenue : null;

  const storeRows = stores.map(st => {
    const mine = (rows) => rows.filter(r => r.store_id === st.id);
    const c = pack(mine(curRows), curR);
    const p = pack(mine(prevRows), prevR);
    const y = pack(mine(yoyRows), yoyR);
    const sCur = seriesOf(mine(curRows), curR);
    const sPrev = seriesOf(mine(prevRows), prevR);

    // 对大盘变动的贡献：pp 表示「把全店增速拉动/拖累了多少个百分点」，
    // 比单纯看增量更能解释「谁的变动导致了大盘变动」。
    const diff = c.available && p.available ? round2(c.revenue - p.revenue) : null;
    const pp = diff != null && baseRev > 0 ? Math.round((diff / baseRev) * 1000) / 10 : null;
    const share = diff != null && totalDiff ? Math.round((diff / totalDiff) * 1000) / 10 : null;

    return {
      store_id: st.id, store_name: st.name,
      current: c, prev: p, yoy: y,
      delta: { prev: deltaFor(p), yoy: deltaFor(y) },
      series: { current: sCur, prev: sPrev },
      channels: { current: channelSum(mine(curRows)), prev: channelSum(mine(prevRows)) },
      contrib: { diff, pp, share }
    };
  });

  /* ------------------------------------------------------------------------
     分析层：全部基于上面已经算好的窗口数据，不额外查库
     ---------------------------------------------------------------------- */

  // 0. 缺数据说明：同比大概率没有（系统 2026-10 才有记录），要明确告诉前端「不是 0，是没有」
  const notes = [];
  if (!yoy.available) {
    notes.push(`去年同期（${yoy.label}）没有记录，同比只能显示本期绝对值`);
  }
  if (!prev.available) {
    notes.push(`环比基准（${prev.label}）没有记录，环比与归因暂不可用`);
  }
  if (current.days_with_data < window) {
    notes.push(`本期 ${window} 天里有 ${window - current.days_with_data} 天没有数据，日均类指标按有数据的天数计算`);
  }

  // 1. 目标达成预测：用「近 7 天日均」外推月末，并算出剩余天数每天要卖多少
  const month = date.slice(0, 7);
  const dayOfMonth = Number(date.slice(8, 10));
  const daysInMonth = new Date(Number(date.slice(0, 4)), Number(date.slice(5, 7)), 0).getDate();
  const daysLeft = Math.max(0, daysInMonth - dayOfMonth);

  const monthRows = db.prepare('SELECT * FROM records WHERE date >= ? AND date <= ?').all(month + '-01', date)
    .filter(r => storeIds.has(r.store_id));
  const monthCum = sumRecords(monthRows).revenue;
  const monthOrders = sumRecords(monthRows).orders;
  // 分店月累计：健康度要看「月度进度落后多少」，不能只看单日达标
  const monthByStore = {};
  for (const r of monthRows) {
    monthByStore[r.store_id] = (monthByStore[r.store_id] || 0) + (r.income || 0) +
      (r.platform === 'meituan' ? (r.dine_in_income || 0) : 0);
  }
  const targetMap = Object.fromEntries(
    db.prepare('SELECT store_id, target_amount FROM monthly_targets WHERE month=?').all(month)
      .map(r => [r.store_id, r.target_amount])
  );
  const targetSum = stores.reduce((a, s) => a + (targetMap[s.id] || 0), 0);

  // 近 7 天日均：取本期序列里最后 7 个有数据的日子，窗口只有 7 天时就是本期整体
  const tail = totalCur.filter(p => p.revenue != null).slice(-7).map(p => p.revenue);
  const recentDaily = mean(tail) == null ? null : round2(mean(tail));
  const needDaily = targetSum > 0 && daysLeft > 0 ? round2((targetSum - monthCum) / daysLeft) : null;
  const predicted = recentDaily == null ? null : round2(monthCum + recentDaily * daysLeft);
  const ratio = needDaily != null && recentDaily ? needDaily / recentDaily : null;

  let verdict = 'na', verdictText = '未配置月目标，无法预测';
  if (ratio != null) {
    if (ratio <= 0) { verdict = 'done'; verdictText = '已提前完成整月目标，剩下都是超额'; }
    else if (ratio <= 1) { verdict = 'easy'; verdictText = '按当前节奏就能达标，还有余量'; }
    else if (ratio <= 1.1) { verdict = 'ok'; verdictText = '按当前节奏刚好够，几乎没有缓冲'; }
    else if (ratio <= 1.3) { verdict = 'tight'; verdictText = `剩余 ${daysLeft} 天需要比近 7 天提速 ${Math.round((ratio - 1) * 100)}% 才能达标`; }
    else { verdict = 'hard'; verdictText = `剩余 ${daysLeft} 天需要比近 7 天提速 ${Math.round((ratio - 1) * 100)}%，按现有节奏难以达成`; }
  }

  // 2. 门店健康度：连续低于日均目标的天数 + 波动率 + 周末/工作日差 + 堂食占比
  const health = storeRows.map(s => {
    const targetDaily = (targetMap[s.store_id] || 0) > 0 ? (targetMap[s.store_id] || 0) / daysInMonth : 0;
    const pts = s.series.current.filter(p => p.revenue != null);
    const vals = pts.map(p => p.revenue);
    const avg = mean(vals) == null ? null : round2(mean(vals));
    const cv = stdev(vals, mean(vals)) == null || !mean(vals) ? null : stdev(vals, mean(vals)) / mean(vals);

    let streak = 0;
    for (let i = pts.length - 1; i >= 0; i--) {
      if (targetDaily > 0 && pts[i].revenue < targetDaily) streak++;
      else break;
    }
    const below = targetDaily > 0 ? vals.filter(v => v < targetDaily).length : 0;

    const wk = pts.filter(p => isWeekend(p.date)).map(p => p.revenue);
    const wd = pts.filter(p => !isWeekend(p.date)).map(p => p.revenue);
    const wkAvg = mean(wk) == null ? null : round2(mean(wk));
    const wdAvg = mean(wd) == null ? null : round2(mean(wd));
    const wkGap = wkAvg != null && wdAvg ? Math.round(((wkAvg - wdAvg) / wdAvg) * 1000) / 10 : null;

    const chTotal = s.channels.current.total;
    const dineShare = chTotal > 0 ? Math.round((s.channels.current.dine_in / chTotal) * 1000) / 10 : null;

    // 月进度：完成率 vs 时间进度，负值＝落后。只看单日达标容易漏掉"天天差一点"的店，
    // 所以把月度进度也纳入判断。
    const mTarget = targetMap[s.store_id] || 0;
    const mCum = round2(monthByStore[s.store_id] || 0);
    const mRate = mTarget > 0 ? Math.round((mCum / mTarget) * 1000) / 10 : null;
    const timeRate = Math.round((dayOfMonth / daysInMonth) * 1000) / 10;
    const behind = mRate == null ? null : Math.round((mRate - timeRate) * 10) / 10;

    // 近期趋势：最后 3 天 vs 之前 3 天。比"是否达标"更早暴露问题——目标没变、生意在滑。
    const last3 = vals.slice(-3), prev3 = vals.slice(-6, -3);
    const trend = last3.length === 3 && prev3.length === 3 && mean(prev3)
      ? Math.round(((mean(last3) - mean(prev3)) / mean(prev3)) * 1000) / 10
      : null;

    // 分级以「月度进度」为主，「波动」与「近期趋势」为辅。
    // 单日达标天数只作说明信息：日均目标是一条平线，周末本来就高，用它定级会误伤。
    let level = 'na';
    if (mTarget > 0) {
      if ((behind != null && behind <= -12) || (trend != null && trend <= -20)) level = 'bad';
      else if ((behind != null && behind <= -4) || (trend != null && trend <= -8) || (cv != null && cv > 0.45)) level = 'warn';
      else level = 'ok';
    }

    const bits = [];
    if (vals.length) {
      if (targetDaily > 0) {
        bits.push(below === 0
          ? `近 ${vals.length} 天每天都达到日均目标`
          : `近 ${vals.length} 天有 ${below} 天未达日均目标${streak >= 2 ? `，已连续 ${streak} 天低于目标` : ''}`);
      } else {
        bits.push(`近 ${vals.length} 天日均 ¥${round2(avg)}（未设月目标）`);
      }
      if (behind != null) bits.push(`月度完成 ${mRate}%，比时间进度${behind >= 0 ? '超前' : '落后'} ${Math.abs(behind)} 个百分点`);
      if (trend != null && Math.abs(trend) >= 5) bits.push(`最近 3 天比前 3 天${trend > 0 ? '增长' : '下滑'} ${Math.abs(trend)}%`);
      if (cv != null) bits.push(`日营收波动 ${Math.round(cv * 100)}%${cv > 0.4 ? '（起伏偏大）' : ''}`);
      if (wkGap != null && Math.abs(wkGap) >= 8) bits.push(`周末日均比工作日${wkGap > 0 ? '高' : '低'} ${Math.abs(wkGap)}%`);
      if (dineShare != null) bits.push(`堂食占 ${dineShare}%`);
    } else {
      bits.push('本区间没有数据');
    }

    return {
      store_id: s.store_id, store_name: s.store_name,
      level, avg_daily: avg, target_daily: targetDaily > 0 ? round2(targetDaily) : null,
      below, days: vals.length, streak,
      cv: cv == null ? null : Math.round(cv * 1000) / 10,
      trend,
      weekend_avg: wkAvg, weekday_avg: wdAvg, weekend_gap: wkGap,
      dine_share: dineShare,
      month_cum: mCum, month_target: mTarget, month_rate: mRate, time_rate: timeRate, behind,
      text: bits.join('，') + '。'
    };
  });

  // 3. 异常波动：偏离自身窗口内中位数 40% 以上、且绝对差额够大才算（小店几十块的波动不算异常）
  const anomalies = [];
  for (const s of storeRows) {
    const pts = s.series.current.filter(p => p.revenue != null);
    if (pts.length < 4) continue;
    const med = median(pts.map(p => p.revenue));
    if (!med || med <= 0) continue;
    for (const p of pts) {
      const dev = (p.revenue - med) / med;
      if (Math.abs(dev) >= 0.4 && Math.abs(p.revenue - med) >= 300) {
        anomalies.push({
          date: p.date, store_name: s.store_name,
          revenue: p.revenue, expected: round2(med),
          dev_pct: Math.round(dev * 1000) / 10,
          dir: dev > 0 ? 'up' : 'down'
        });
      }
    }
  }
  anomalies.sort((a, b) => Math.abs(b.dev_pct) - Math.abs(a.dev_pct));

  // 4. 归因：按对大盘的百分点贡献排序，正负都列，说明谁拉动、谁拖累
  const attribution = storeRows
    .filter(s => s.contrib.pp != null && Math.abs(s.contrib.pp) >= 0.05)
    .map(s => ({ store_name: s.store_name, diff: s.contrib.diff, pp: s.contrib.pp, share: s.contrib.share }))
    .sort((a, b) => b.pp - a.pp);

  // 5. 渠道份额变化里最值得说的一句
  const mover = chRows.filter(r => r.share_pp != null).sort((a, b) => Math.abs(b.share_pp) - Math.abs(a.share_pp))[0];
  const channelText = mover
    ? `${mover.name}份额 ${mover.share_prev}% → ${mover.share}%（${mover.share_pp > 0 ? '+' : ''}${mover.share_pp}pp）`
    : '渠道份额暂不可比';

  res.json({
    date, window,
    current, prev, yoy,
    delta: { prev: deltaFor(prev), yoy: deltaFor(yoy) },
    series: { current: totalCur, prev: totalPrev, yoy: totalYoy },
    stores: storeRows,
    channels: { current: chCur, prev: chPrev, rows: chRows, text: channelText },
    analysis: {
      notes,
      forecast: {
        month, days_in_month: daysInMonth, day_of_month: dayOfMonth, days_left: daysLeft,
        month_cum: monthCum, month_orders: monthOrders, target: round2(targetSum),
        need_daily: needDaily, recent_daily: recentDaily, predicted,
        gap: predicted == null || targetSum <= 0 ? null : round2(targetSum - predicted),
        ratio: ratio == null ? null : Math.round(ratio * 100) / 100,
        verdict, verdict_text: verdictText
      },
      health,
      anomalies: anomalies.slice(0, 8),
      attribution: { total_diff: totalDiff, total_pct: deltaFor(prev).revenue.pct, stores: attribution },
      channels: { text: channelText, rows: chRows }
    }
  });
});

// ---------- 汇总排名（仅项目负责人） ----------
app.get('/api/ranking', requireAuth, requireSuper, (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: '需要 date' });
  const rows = db.prepare(`
    SELECT r.store_id, s.name AS store_name,
           SUM(r.turnover) AS turnover, SUM(r.orders) AS orders,
           COALESCE(SUM(t.target_amount), 0) AS target_amount
    FROM records r
    JOIN stores s ON s.id = r.store_id AND s.active = 1
    LEFT JOIN targets t ON t.store_id = r.store_id AND t.platform = r.platform AND t.date = r.date
    WHERE r.date = ?
    GROUP BY r.store_id
    ORDER BY turnover DESC
  `).all(date);
  const ranked = rows.map((r, i) => ({
    ...r,
    rank: i + 1,
    rate: r.target_amount > 0 ? Math.round((r.turnover / r.target_amount) * 1000) / 10 : null,
  }));
  res.json(ranked);
});

// ---------- Excel 上传解析（支持单文件与批量：一次最多 60 个日期） ----------
// 批量是为了回填历史：把去年同期的日报表一次性导入后，「同比」才有真实基准。
app.post('/api/upload', requireAuth, upload.any(), (req, res) => {
  const files = (req.files || []).filter(f => f && (f.fieldname === 'file' || f.fieldname === 'files'));
  if (!files.length) return res.status(400).json({ error: '未收到文件' });

  const upsert = db.prepare(`
    INSERT INTO records (store_id, platform, date, turnover, income, discount, orders, avg_pre, avg_post,
                         dine_in_turnover, dine_in_income, dine_in_orders, groupon_income, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(store_id, platform, date) DO UPDATE SET
      turnover=excluded.turnover, income=excluded.income, discount=excluded.discount,
      orders=excluded.orders, avg_pre=excluded.avg_pre, avg_post=excluded.avg_post,
      dine_in_turnover=excluded.dine_in_turnover, dine_in_income=excluded.dine_in_income,
      dine_in_orders=excluded.dine_in_orders, groupon_income=excluded.groupon_income,
      raw_json=excluded.raw_json, uploaded_at=datetime('now','localtime')
  `);

  const storeIdByCode = Object.fromEntries(db.prepare('SELECT code, id FROM stores').all().map(r => [r.code, r.id]));
  const done = [], failed = [];
  let totalInserted = 0;

  for (const file of files) {
    const parsed = parseGuandian(file.path);
    if (!parsed.ok) {
      failed.push({ file: file.originalname, error: parsed.error });
      continue;
    }
    const { date, stores } = parsed;
    const imported = [], warnings = [];
    let inserted = 0;
    let forbidden = null;

    for (const st of stores) {
      if (!st.store_code) { warnings.push('未匹配门店: ' + st.store_name); continue; }
      if (!storeIdByCode[st.store_code]) { warnings.push('未知门店编码: ' + st.store_code); continue; }
      const sid = storeIdByCode[st.store_code];
      // 权限：manager/employee 仅本店，整份文件拒绝，不留半份数据
      if (req.user.role !== 'super_admin' && req.user.store_id !== sid) {
        forbidden = `报表包含非本店数据（${st.store_name}），禁止上传`;
        break;
      }
      const di = st.channels.dine_in || {};
      const gp = (st.pay && st.pay.groupon) || 0;
      for (const pf of ['meituan', 'taobao_flash', 'jd']) {
        const ch = st.channels[pf];
        // 堂食/团购仅存于 meituan 行（避免三行重复统计）
        const diT = pf === 'meituan' ? di.turnover : 0;
        const diI = pf === 'meituan' ? di.income : 0;
        const diO = pf === 'meituan' ? di.orders : 0;
        const gpV = pf === 'meituan' ? gp : 0;
        upsert.run(sid, pf, date, ch.turnover, ch.income, ch.discount, ch.orders, ch.avg_pre, ch.avg_post,
                   diT, diI, diO, gpV, JSON.stringify(st));
        inserted++;
      }
      imported.push({ store_code: st.store_code, store_name: st.store_name, dine_in_orders: st.channels.dine_in.orders });
    }

    if (forbidden) { failed.push({ file: file.originalname, error: forbidden }); continue; }
    totalInserted += inserted;
    done.push({ file: file.originalname, date, inserted, imported, warnings });
  }

  if (!done.length) {
    return res.status(422).json({ error: failed[0] ? failed[0].error : '文件解析失败', failed });
  }

  // 单文件时保留旧字段（date/inserted/imported/warnings），老调用方不用改
  const first = done[0];
  const payload = {
    ok: true,
    total_inserted: totalInserted,
    files: done.sort((a, b) => (a.date < b.date ? -1 : 1)),
    failed
  };
  if (done.length === 1) {
    Object.assign(payload, { date: first.date, inserted: first.inserted, imported: first.imported, warnings: first.warnings });
  }
  res.json(payload);
});

// ---------- 独立登录 / 登出 ----------
app.post('/api/login', rateLimit, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });
  try {
    const r = await httpJson('POST', '/api/auth/login', { username, password }, null, clientIpOf(req));
    if (r.status !== 200 || !r.json || !r.json.ok) {
      if (r.status === 429) return res.status(429).json({ error: (r.json && r.json.error) || '尝试过于频繁' });
      return res.status(401).json({ error: '账号或密码错误（使用于百万统一账号）' });
    }
    const sid = crypto.randomBytes(24).toString('hex');
    // SSO 返回跨工具门店编码（rt/jz/wj...），映射到本工具本地门店 id
    let storeId = null;
    if (r.json.store_code) {
      const st = db.prepare('SELECT id FROM stores WHERE code = ?').get(r.json.store_code);
      if (st) storeId = st.id;
    }
    const user = {
      username: r.json.username,
      role: r.json.role,
      real_name: r.json.real_name || r.json.username,
      store_id: storeId,
    };
    const expire = Date.now() + SESSION_MS;
    db.prepare(`
      INSERT INTO sessions (sid, username, role, real_name, store_id, expire, sso_token, sso_checked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET username=excluded.username, role=excluded.role,
        real_name=excluded.real_name, store_id=excluded.store_id, expire=excluded.expire,
        sso_token=excluded.sso_token, sso_checked_at=excluded.sso_checked_at
    `).run(sid, user.username, user.role, user.real_name, user.store_id, expire,
           r.json.token || null, Date.now());
    const cookies = [];
    if (r.setCookie) (Array.isArray(r.setCookie) ? r.setCookie : [r.setCookie]).forEach((c) => { if (c) cookies.push(c); });
    cookies.push(`sp_sid=${sid}; Path=/; HttpOnly; SameSite=Lax${COOKIE_SECURE}; Max-Age=${SESSION_MS / 1000}`);
    res.setHeader('Set-Cookie', cookies);
    res.json({ ok: true, user });
  } catch (e) {
    res.status(502).json({ error: '账号服务暂不可用，请稍后再试' });
  }
});

app.post('/api/logout', async (req, res) => {
  const sid = getSid(req);
  if (sid) db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
  const cookies = ['sp_sid=; Path=/; HttpOnly; Max-Age=0'];
  const shared = getSharedToken(req);
  if (shared) {
    try {
      const r = await httpJson('POST', '/api/auth/logout', null, shared);
      if (r.setCookie) (Array.isArray(r.setCookie) ? r.setCookie : [r.setCookie]).forEach((c) => { if (c) cookies.push(c); });
    } catch (e) {}
  }
  res.setHeader('Set-Cookie', cookies);
  res.json({ ok: true });
});

// 健康检查（无需登录）
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'shop-performance' }));
// 当前登录用户（前端用）
app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

// 过期会话清理：启动清一次，之后每小时清一次。
// 统一认证那边是「登录时顺手清」，本工具没有登录入口的场景（全靠共享登录态）就不会触发，
// 于是过期的 sp_sid 会永久躺在库里。这里独立清理，留 24 小时宽限期避开正在处理的请求。
function purgeExpiredSessions() {
  try {
    const r = db.prepare('DELETE FROM sessions WHERE expire < ?').run(Date.now() - 24 * 60 * 60 * 1000);
    if (r.changes) console.log(`[shop-performance] 清理过期会话 ${r.changes} 条`);
  } catch (e) {
    console.error('[shop-performance] 清理过期会话失败:', e.message);
  }
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[shop-performance] 服务已启动: http://127.0.0.1:${PORT} (身份源: ${core.ssoOrigin()})`);
});
