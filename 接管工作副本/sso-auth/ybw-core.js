'use strict';
/**
 * 于百万工作台 · 公共运行时核心
 * ---------------------------------------------------------------------------
 * 四个应用（portal / sso-auth / kitchen-clean / shop-performance）共享的唯一事实来源。
 *
 * 部署方式：deploy.sh 在打包前把本文件复制到各应用目录（app/ybw-core.js），
 * 应用用 require('./ybw-core') 引入。这样既保证单一来源，又不给运行时引入
 * 跨目录依赖（每个应用仍是可独立部署的目录）。
 *
 * 这里只放「四个应用都必须完全一致」的东西：
 *   环境变量与配置读取 / cookie 解析 / 真实客户端 IP / 登录限流 / SSO 客户端 / 会话 cookie 属性
 *
 * 为什么要有这个文件：2026-11 加固时，SSO 读 SSO_COOKIE_INSECURE、另两个应用读
 * COOKIE_INSECURE，名字不一致导致预发布登录态失效。同类事故只要存在多份拷贝就会复现。
 */

const http = require('http');
const https = require('https');

// ---------- 配置读取 ----------

/** 读环境变量，空字符串等同于未设置 */
function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? (fallback === undefined ? null : fallback) : v;
}

/**
 * 启动期强校验：缺失或过短直接抛错，由调用方 process.exit(1)。
 * 密钥类配置不允许有默认值 —— 有默认值就等于有硬编码密钥。
 */
function requireEnv(name, minLength) {
  const v = env(name);
  if (!v) throw new Error('缺少环境变量 ' + name);
  if (minLength && v.length < minLength) {
    throw new Error('环境变量 ' + name + ' 长度不足（需 >= ' + minLength + '，实际 ' + v.length + '）');
  }
  return v;
}

/**
 * 是否处于「非 HTTPS」部署（预发布走 http://127.0.0.1 隧道、本地调试）。
 * 同时接受 COOKIE_INSECURE 与旧名 SSO_COOKIE_INSECURE —— 统一在这里兼容，避免各应用各写一套。
 */
function isCookieInsecure() {
  return env('COOKIE_INSECURE') === '1' || env('SSO_COOKIE_INSECURE') === '1';
}

const DEFAULT_SSO_ORIGIN = 'http://127.0.0.1:3200';
const SHARED_COOKIE_NAME = 'ybw_sso';

/**
 * 统一身份认证服务的地址。
 * 两种写法都支持，避免各应用各用一套：
 *   SSO_ORIGIN=http://127.0.0.1:3200        （kitchen-clean / shop-performance 用）
 *   SSO_HOST=127.0.0.1 + SSO_PORT=3200      （portal 的历史写法，systemd 单元里就是这两项）
 * 注意：预发布必须指向 3420，否则预发布门户会连到生产的 SSO，
 * 用预发布库的临时账号去生产认证必然 401（2026-11 抽公共模块时踩过）。
 */
function ssoOrigin() {
  const explicit = env('SSO_ORIGIN');
  if (explicit) return explicit;
  return 'http://' + env('SSO_HOST', '127.0.0.1') + ':' + env('SSO_PORT', '3200');
}

/** server-to-server 管理密钥；无默认值，缺失即抛错 */
function ssoKey() {
  return requireEnv('SSO_KEY', 16);
}

// ---------- 请求工具 ----------

/** 解析 Cookie 头，返回普通对象。同名 cookie 取第一个。 */
function parseCookies(req) {
  const out = {};
  const raw = (req && req.headers && req.headers.cookie) || '';
  raw.split(';').forEach(function (part) {
    const i = part.indexOf('=');
    if (i > 0) {
      const k = part.slice(0, i).trim();
      if (k && !(k in out)) out[k] = part.slice(i + 1).trim();
    }
  });
  return out;
}

/** 真实客户端 IP：Nginx 已写入 X-Forwarded-For，取第一段 */
function clientIp(req) {
  const fwd = ((req.headers && req.headers['x-forwarded-for']) || '').split(',')[0].trim();
  return fwd || (req.socket && req.socket.remoteAddress) || '';
}

/**
 * 会话 Cookie 属性串（供 Set-Cookie 使用）。
 * 生产：Domain=.sangyu.work + Secure，三个子域共享登录态。
 * 预发布/本地：去掉 Domain（host-only）与 Secure，避免覆盖生产登录态。
 */
function cookieAttrs(maxAgeSec, options) {
  options = options || {};
  const insecure = options.insecure !== undefined ? options.insecure : isCookieInsecure();
  const domain = options.domain !== undefined ? options.domain : env('SSO_COOKIE_DOMAIN', '.sangyu.work');
  const parts = ['Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (!insecure && domain) parts.push('Domain=' + domain);
  if (!insecure) parts.push('Secure');
  parts.push('Max-Age=' + maxAgeSec);
  return parts.join('; ');
}

// ---------- 登录限流 ----------

/**
 * 固定窗口计数器限流。单进程内存实现，量级小、够用。
 * 返回 Express 中间件；每个应用各自创建一个实例（各自的 Map）。
 *
 * 注意：必须按真实客户端 IP 计数。四个应用调用 SSO 都走 127.0.0.1 回环，
 * 若不透传 X-Forwarded-For，全部用户会被算成同一个 IP，一限流就全员误伤。
 */
function createRateLimiter(options) {
  options = options || {};
  const windowMs = options.windowMs || 60 * 1000;
  const maxHits = options.maxHits || 10;
  const message = options.message || '尝试过于频繁，请 1 分钟后再试';
  const hits = new Map();

  return function rateLimit(req, res, next) {
    const ip = clientIp(req) || 'unknown';
    const now = Date.now();
    let rec = hits.get(ip);
    if (!rec || now - rec.start > windowMs) {
      rec = { start: now, count: 0 };
      hits.set(ip, rec);
    }
    rec.count++;
    // 顺带清理过期记录，避免 Map 无限增长
    if (hits.size > 5000) {
      for (const [k, v] of hits) if (now - v.start > windowMs) hits.delete(k);
    }
    if (rec.count > maxHits) {
      return res.status(429).json({ error: message });
    }
    next();
  };
}

// ---------- SSO 客户端 ----------

/**
 * 调用统一身份认证服务（内部回环）。
 * @returns {Promise<{status:number, json:any, setCookie:string|string[]|null}>}
 *
 * 统一入口，四个应用只经由这里访问 sso-auth。三处历史实现（portal 的 callSSO、
 * kitchen-clean 的 ssoRequest、shop-performance 的 httpJson）在各自文件里保留同名
 * 薄包装以维持调用点不变，实现全部下沉到这里。
 */
function ssoRequest(options) {
  const method = (options.method || 'GET').toUpperCase();
  const pathname = options.path;
  const data = options.body ? JSON.stringify(options.body) : null;
  const timeoutMs = options.timeoutMs || 8000;

  return new Promise(function (resolve, reject) {
    let url;
    try {
      url = new URL(ssoOrigin() + pathname);
    } catch (e) {
      return reject(e);
    }
    const headers = {};
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (options.token) headers['X-SSO-Token'] = options.token;
    if (options.withKey) headers['X-SSO-Key'] = ssoKey();
    if (options.clientIp) headers['X-Forwarded-For'] = options.clientIp;

    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request({
      method: method,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + (url.search || ''),
      headers: headers,
      timeout: timeoutMs,
    }, function (res) {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', function (c) { buf += c; });
      res.on('end', function () {
        let json = null;
        try { json = JSON.parse(buf); } catch (e) { /* 非 JSON 响应（如 302）忽略 */ }
        resolve({ status: res.statusCode, json: json, setCookie: res.headers['set-cookie'] || null });
      });
    });
    req.on('timeout', function () { req.destroy(new Error('SSO 响应超时（' + timeoutMs + 'ms）')); });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

module.exports = {
  env: env,
  requireEnv: requireEnv,
  isCookieInsecure: isCookieInsecure,
  ssoOrigin: ssoOrigin,
  ssoKey: ssoKey,
  DEFAULT_SSO_ORIGIN: DEFAULT_SSO_ORIGIN,
  SHARED_COOKIE_NAME: SHARED_COOKIE_NAME,
  parseCookies: parseCookies,
  clientIp: clientIp,
  cookieAttrs: cookieAttrs,
  createRateLimiter: createRateLimiter,
  ssoRequest: ssoRequest,
};
