// 于百万 · 工作台门户（portal）
// 职责：主域 sangyu.work 的工具总览入口 + 统一登录 + 账号管理控制台
// 登录态不在本服务保存，完全依赖 SSO 签发的 .sangyu.work 共享 cookie
const express = require('express');
const path = require('path');
// 公共运行时核心（shared/ybw-core.js，部署时自动注入本目录）
const core = require('./ybw-core');

const app = express();
const PORT = process.env.PORT || 3300;
// 启动即校验管理密钥：缺失或过短直接启动失败（不允许有默认值）。
// 实际发请求时由 core.ssoRequest 在 withKey 分支内部读取，本文件不再持有密钥变量。
core.requireEnv('SSO_KEY', 24);
const COOKIE_NAME = core.SHARED_COOKIE_NAME;

app.use(express.json({ limit: '2mb' }));

// ---------- 工具函数（均来自公共核心） ----------
const parseCookies = core.parseCookies;
const clientIp = core.clientIp;

function readToken(req) {
  return parseCookies(req)[COOKIE_NAME] || null;
}

// 调用 SSO（内部回环），返回 status/json/setCookie
// 实现在 core.ssoRequest，此处保留原签名以维持调用点
function callSSO(method, pathname, options) {
  options = options || {};
  return core.ssoRequest({
    method: method,
    path: pathname,
    body: options.body,
    token: options.token,
    withKey: options.withKey,
    // 透传真实客户端 IP：SSO 的登录限流按 IP 计数，若都记成 127.0.0.1 会误伤全部用户
    clientIp: options.clientIp,
    timeoutMs: 8000
  });
}

// 取得当前登录用户（无会话返回 null）
async function getSessionUser(req) {
  const token = readToken(req);
  if (!token) return null;
  try {
    const r = await callSSO('GET', '/api/auth/session', { token: token });
    if (r.status !== 200 || !r.json || !r.json.ok) return null;
    return r.json;
  } catch (e) {
    return null;
  }
}

function forwardSetCookie(res, setCookie) {
  if (setCookie) res.setHeader('Set-Cookie', setCookie);
}

// ---------- 接口 ----------
app.get('/api/me', async function (req, res) {
  const u = await getSessionUser(req);
  if (!u) return res.status(401).json({ ok: false });
  res.json({ ok: true, username: u.username, real_name: u.real_name, role: u.role, store_code: u.store_code });
});

app.post('/api/login', async function (req, res) {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: '请输入账号和密码' });
  try {
    const r = await callSSO('POST', '/api/auth/login', { body: { username: username, password: password }, clientIp: clientIp(req) });
    forwardSetCookie(res, r.setCookie);
    if (r.status !== 200 || !r.json || !r.json.ok) {
      return res.status(r.status === 200 ? 401 : r.status).json({ ok: false, error: (r.json && r.json.error) || '登录失败' });
    }
    res.json({ ok: true, username: r.json.username, real_name: r.json.real_name, role: r.json.role, store_code: r.json.store_code });
  } catch (e) {
    res.status(502).json({ ok: false, error: '身份服务暂不可用' });
  }
});

app.post('/api/logout', async function (req, res) {
  try {
    const r = await callSSO('POST', '/api/auth/logout', { token: readToken(req) });
    forwardSetCookie(res, r.setCookie);
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: true });
  }
});

// 账号管理：仅超管可用，且由门户校验身份后带服务密钥转发（密钥不下发前端）
async function requireSuperAdmin(req, res, next) {
  const u = await getSessionUser(req);
  if (!u) return res.status(401).json({ ok: false, error: '未登录' });
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: '仅管理员可访问' });
  req.ssoUser = u;
  next();
}

app.get('/api/admin/users', requireSuperAdmin, async function (req, res) {
  try {
    const r = await callSSO('GET', '/api/admin/users', { withKey: true });
    if (r.status !== 200) return res.status(502).json({ ok: false, error: (r.json && r.json.error) || '账号服务不可用' });
    res.json(r.json);
  } catch (e) {
    res.status(502).json({ ok: false, error: '账号服务不可用' });
  }
});

app.post('/api/admin/users', requireSuperAdmin, async function (req, res) {
  try {
    const r = await callSSO('POST', '/api/admin/users', { body: req.body, withKey: true });
    res.status(r.status).json(r.json || { ok: false });
  } catch (e) {
    res.status(502).json({ ok: false, error: '账号服务不可用' });
  }
});

app.post('/api/admin/users/update', requireSuperAdmin, async function (req, res) {
  try {
    const r = await callSSO('POST', '/api/admin/users/update', { body: req.body, withKey: true });
    res.status(r.status).json(r.json || { ok: false });
  } catch (e) {
    res.status(502).json({ ok: false, error: '账号服务不可用' });
  }
});

app.post('/api/admin/users/delete', requireSuperAdmin, async function (req, res) {
  try {
    const r = await callSSO('POST', '/api/admin/users/delete', { body: req.body, withKey: true });
    res.status(r.status).json(r.json || { ok: false });
  } catch (e) {
    res.status(502).json({ ok: false, error: '账号服务不可用' });
  }
});

// ---------- 页面 ----------
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/account', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

app.get('/api/health', function (req, res) {
  res.json({ ok: true, service: 'portal', ts: Date.now() });
});

app.listen(PORT, '127.0.0.1', function () {
  console.log('[portal] 工作台门户已启动: http://127.0.0.1:' + PORT);
});
