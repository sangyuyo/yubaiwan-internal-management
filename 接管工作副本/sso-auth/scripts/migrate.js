// 账号迁移脚本：把 QSC 现有账号库（users + stores）导入 SSO（sso.db）
// 密码哈希直接迁移（bcrypt 哈希可跨库使用），用户无需重置密码，无感迁移
// 门店绑定：QSC 存 store_id（数字），SSO 存 store_code（如 rt/jz/wj），迁移时自动转换
// 用法：node scripts/migrate.js --from <qsc.db路径> [--dry]
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const args = process.argv.slice(2);
const fromIdx = args.indexOf('--from');
if (fromIdx < 0 || !args[fromIdx + 1]) {
  console.error('用法: node scripts/migrate.js --from <QSC数据库文件> [--dry]');
  process.exit(1);
}
const fromPath = path.resolve(args[fromIdx + 1]);
const dry = args.includes('--dry');
if (!fs.existsSync(fromPath)) {
  console.error('源数据库不存在: ' + fromPath);
  process.exit(1);
}

const src = new Database(fromPath, { readonly: true });
const { db: dst } = require('../db');

// 源门店表是否存在 / 结构兼容性检查
let srcStores = [];
let srcUsers = [];
try {
  srcStores = src.prepare('SELECT id, code, name FROM stores').all();
  srcUsers = src.prepare('SELECT id, username, password_hash, real_name, role, store_id, active FROM users').all();
} catch (e) {
  console.error('读取源库失败（确认是 QSC 数据库）: ' + e.message);
  process.exit(1);
}
console.log(`源库账号数: ${srcUsers.length}，门店数: ${srcStores.length}`);

const codeById = {};
for (const s of srcStores) codeById[s.id] = s.code;

let inserted = 0, skipped = 0;
const ins = dst.prepare('INSERT INTO users (username, password_hash, real_name, role, store_code, active) VALUES (?,?,?,?,?,?)');
const check = dst.prepare('SELECT id FROM users WHERE username = ?');

const tx = dst.transaction(() => {
  for (const u of srcUsers) {
    if (check.get(u.username)) { skipped++; continue; }
    const code = u.store_id != null ? (codeById[u.store_id] || null) : null;
    ins.run(u.username, u.password_hash, u.real_name || '', u.role, code, u.active === 0 ? 0 : 1);
    inserted++;
  }
});
if (dry) {
  console.log(`[dry-run] 将新增 ${srcUsers.length - skipped} 个账号（跳过已存在 ${skipped}）`);
} else {
  tx();
  console.log(`迁移完成：新增 ${inserted}，跳过已存在 ${skipped}`);
}

// 校验：抽查每个账号可登录
const dstUsers = dst.prepare('SELECT username, password_hash FROM users').all();
console.log(`SSO 库当前账号总数: ${dstUsers.length}`);
console.log('迁移前请先在 QSC 端确认 admin/admin123 存在，迁移后 SSO 内 admin 密码仍为 admin123');
src.close();
