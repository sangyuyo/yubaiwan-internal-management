// 于百万 · 统一身份认证服务（SSO）
// 唯一账号源：业务工具（QSC / 数据追踪 / 门户）登录时转发本服务校验账号密码
// 本服务同时签发一个挂在 .sangyu.work 上的共享登录凭证（cookie），
// 使 sangyu.work / qsc.sangyu.work / data.sangyu.work 三个站点登录一次即可互通。
// 本服务不存任何业务数据。
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');
// 公共运行时核心（shared/ybw-core.js，部署时自动注入本目录）
const core = require('./ybw-core');

const app = express();
const PORT = process.env.PORT || 3200;
// server-to-server 管理密钥：QSC 等工具的账号管理接口转发用
// 2026-11 起改为强制环境变量（/etc/ybw/env），不再内置默认值，避免源码泄露即等于密钥泄露
const SSO_KEY = core.requireEnv('SSO_KEY', 24);

// 共享登录态配置
const COOKIE_NAME = core.SHARED_COOKIE_NAME;
const COOKIE_DOMAIN = core.env('SSO_COOKIE_DOMAIN', '.sangyu.work');
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000; // 30 天

app.use(express.json({ limit: '2mb' }));

// ---------- 登录限流（防暴力破解） ----------
// 实现下沉到 core，四个应用共用同一套逻辑与参数（别人改不可能只改一处）
const rateLimit = core.createRateLimiter({
  windowMs: 60 * 1000,
  maxHits: 10,
  message: '尝试过于频繁，请 1 分钟后再试'
});

// ---------- 工具函数（均来自公共核心） ----------
const parseCookies = core.parseCookies;
function cookieAttrs(maxAgeSec) {
  return core.cookieAttrs(maxAgeSec, { domain: COOKIE_DOMAIN });
}

function issueSession(user, res) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  db.prepare('INSERT INTO sessions (token, username, real_name, role, store_code, expires_at) VALUES (?,?,?,?,?,?)')
    .run(token, user.username, user.real_name || user.username, user.role, user.store_code || null, expiresAt);
  res.setHeader('Set-Cookie', COOKIE_NAME + '=' + token + '; ' + cookieAttrs(Math.floor(SESSION_TTL_MS / 1000)));
  try { db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()); } catch (e) { /* 清理失败不影响登录 */ }
  return token;
}

// 校验当前请求携带的共享登录态，返回 { token, user } 或 null
function currentSession(req) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME] || req.headers['x-sso-token'];
  if (!token) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  // 账号被停用或删除后，已有会话立即失效
  const u = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(row.username);
  if (!u) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  return { token: token, user: u };
}

// ---------- 公共接口 ----------
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'sso-auth', ts: Date.now() }));

// 登录校验：业务工具登录页提交账号密码 → 转发本接口
// 校验通过后除返回身份信息外，同时种下 .sangyu.work 共享登录 cookie
app.post('/api/auth/login', rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '账号或密码错误' });
  }
  const token = issueSession(user, res);
  res.json({
    ok: true,
    username: user.username,
    real_name: user.real_name || user.username,
    role: user.role,
    store_code: user.store_code || null,
    token: token,
  });
});

// 校验共享登录态（门户/各工具用来自动免登）
app.get('/api/auth/session', (req, res) => {
  const s = currentSession(req);
  if (!s) return res.status(401).json({ ok: false, error: '未登录或登录已失效' });
  const u = s.user;
  res.json({
    ok: true,
    username: u.username,
    real_name: u.real_name || u.username,
    role: u.role,
    store_code: u.store_code || null,
  });
});

// 退出登录：删除会话并清除共享 cookie
app.post('/api/auth/logout', (req, res) => {
  const s = currentSession(req);
  if (s) db.prepare('DELETE FROM sessions WHERE token = ?').run(s.token);
  res.setHeader('Set-Cookie', COOKIE_NAME + '=; ' + cookieAttrs(0));
  res.json({ ok: true });
});

// 按用户名查身份（业务工具同步用户信息用）
// 2026-11 起收紧：该接口会返回真实姓名/角色/门店，改为需管理密钥或超管会话，
// 避免匿名枚举账号拿到人事信息（requireKey 为函数声明，已提升）
app.get('/api/auth/userinfo', requireKey, (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: '缺少 username' });
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  res.json({ ok: true, username: u.username, real_name: u.real_name, role: u.role, store_code: u.store_code, active: u.active });
});

// ---------- 管理接口（服务间调用，需 X-SSO-Key 或超管共享会话） ----------
function requireKey(req, res, next) {
  const s = currentSession(req);
  if (s && s.user.role === 'super_admin') return next();
  if (req.headers['x-sso-key'] === SSO_KEY) return next();
  return res.status(403).json({ error: '无权访问' });
}

// 用户列表
app.get('/api/admin/users', requireKey, (req, res) => {
  const rows = db.prepare('SELECT id, username, real_name, role, store_code, active, created_at FROM users ORDER BY id').all();
  res.json({ ok: true, users: rows });
});

// 新增账号
app.post('/api/admin/users', requireKey, (req, res) => {
  const { username, password, real_name, role, store_code, active } = req.body || {};
  if (!username || !password || !role) return res.status(400).json({ error: '缺少必填项（username/password/role）' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: '账号已存在' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (username, password_hash, real_name, role, store_code, active) VALUES (?,?,?,?,?,?)')
    .run(username, hash, real_name || '', role, store_code || null, active === 0 ? 0 : 1);
  res.json({ ok: true });
});

// 修改账号（角色/门店/姓名/启用/密码）
app.post('/api/admin/users/update', requireKey, (req, res) => {
  const { id, username, real_name, role, store_code, active, password } = req.body || {};
  if (!id) return res.status(400).json({ error: '缺少 id' });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  if (username && username !== u.username) {
    if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: '账号已存在' });
  }
  const sets = [], vals = [];
  if (username !== undefined) { sets.push('username = ?'); vals.push(username); }
  if (real_name !== undefined) { sets.push('real_name = ?'); vals.push(real_name); }
  if (role !== undefined) { sets.push('role = ?'); vals.push(role); }
  if (store_code !== undefined) { sets.push('store_code = ?'); vals.push(store_code || null); }
  if (active !== undefined) { sets.push('active = ?'); vals.push(active ? 1 : 0); }
  if (password) { sets.push('password_hash = ?'); vals.push(bcrypt.hashSync(password, 10)); }
  if (sets.length) {
    vals.push(id);
    db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?').run(...vals);
  }
  res.json({ ok: true });
});

// 删除账号
app.post('/api/admin/users/delete', requireKey, (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: '缺少 id' });
  const u = db.prepare('SELECT username FROM users WHERE id = ?').get(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  // 账号删除后，其残留会话一并清理，避免出现"已删除账号仍能通行"的漏洞
  if (u) db.prepare('DELETE FROM sessions WHERE username = ?').run(u.username);
  res.json({ ok: true });
});

// 过期会话清理：登录时顺手清一次（上面的 issueSession），这里再补一个定时清，
// 避免长期没人登录时过期会话一直堆在表里。
function purgeExpiredSessions() {
  try {
    const r = db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
    if (r.changes) console.log('[sso-auth] 清理过期会话 ' + r.changes + ' 条');
  } catch (e) {
    console.error('[sso-auth] 清理过期会话失败:', e.message);
  }
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

app.listen(PORT, '127.0.0.1', () => {
  console.log('[sso-auth] 统一身份认证服务已启动: http://127.0.0.1:' + PORT);
});
