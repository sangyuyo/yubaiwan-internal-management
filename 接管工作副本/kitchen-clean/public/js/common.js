// Shared helpers
const todayStr = () => {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

function shiftDate(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00');
  d.setDate(d.getDate() + days);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function fmtTime(s) {
  if (!s) return '';
  // SQLite datetime "YYYY-MM-DD HH:MM:SS"
  return s.replace('T', ' ').slice(5, 16);
}

// 轻提示：进入/退出都有过渡，避免「啪一下出现又消失」的廉价感
let toastTimer = null;
function toast(msg, ms = 2000) {
  let el = document.querySelector('.toast');
  if (!el) {
    el = document.createElement('div');
    el.className = 'toast';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  el.textContent = msg;
  // 下一帧再加 data-show，保证过渡动画能触发
  requestAnimationFrame(() => el.setAttribute('data-show', 'true'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.setAttribute('data-show', 'false');
  }, ms);
}

// 按钮加载态：自动禁用、结束后恢复，避免重复提交
async function withLoading(btn, task) {
  if (!btn || btn.dataset.loading === 'true') return;
  btn.dataset.loading = 'true';
  btn.disabled = true;
  try {
    return await task();
  } finally {
    btn.dataset.loading = 'false';
    btn.disabled = false;
  }
}

// 骨架屏：数据到位前先占位，避免页面空白跳动
function skeletonCards(n = 3) {
  return Array.from({ length: n }).map(() => `
    <div style="display:flex;align-items:center;gap:12px;padding:14px 0;">
      <div class="ui-skeleton" style="flex:1;height:14px;max-width:56%;"></div>
      <div class="ui-skeleton" style="width:64px;height:30px;border-radius:8px;"></div>
    </div>`).join('');
}

async function api(url, options = {}) {
  const isFormData = options.body instanceof FormData;
  const fetchOptions = { ...options };
  // FormData 上传时不要手动设置 Content-Type，由浏览器自动生成 multipart 边界
  if (!isFormData) {
    fetchOptions.headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  }
  const res = await fetch(url, fetchOptions);
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const err = (data && data.error) || `请求失败 (${res.status})`;
    const e = new Error(err);
    e.status = res.status;
    throw e;
  }
  return data;
}

async function getMe() {
  try {
    return await api('/api/auth/me');
  } catch (e) {
    return null;
  }
}

async function isLoggedIn() {
  return !!(await getMe());
}

function getCodeFromPath() {
  // /s/:code or /s/:code/...
  const parts = location.pathname.split('/').filter(Boolean);
  return parts.length >= 2 ? parts[1] : null;
}

function qs(name) {
  return new URLSearchParams(location.search).get(name);
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtSize(bytes) {
  if (!bytes) return '0 KB';
  if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return Math.max(1, Math.round(bytes / 1024)) + ' KB';
}
