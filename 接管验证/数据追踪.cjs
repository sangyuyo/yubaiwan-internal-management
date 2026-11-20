const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { DatabaseSync } = require('node:sqlite');

const workspace = path.resolve(__dirname, '..');
const baselineRoot = path.join(workspace, '源码基线');
const baseline = path.join(baselineRoot, 'shop-performance');
const candidate = path.join(workspace, '接管工作副本', 'shop-performance');
const manifest = JSON.parse(fs.readFileSync(path.join(baselineRoot, 'manifest.json'), 'utf8'));
const sha256 = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function checkSourceFiles() {
  for (const { path: file, sha256: expected } of manifest) {
    assert.equal(sha256(path.join(baselineRoot, file)), expected, '归档基线文件发生变化');
  }
  const publicFiles = manifest.filter(entry => entry.path.startsWith('shop-performance/public/'));
  const actual = fs.readdirSync(path.join(candidate, 'public'), { recursive: true, withFileTypes: true })
    .filter(entry => entry.isFile())
    .map(entry => path.relative(candidate, path.join(entry.parentPath, entry.name)).replaceAll(path.sep, '/'))
    .sort();
  assert.deepEqual(actual, [...publicFiles.map(entry => entry.path.slice('shop-performance/'.length)), 'public/dashboard-tools.js'].sort());
  for (const { path: file, sha256: expected } of publicFiles) {
    if (['shop-performance/public/index.html','shop-performance/public/css/app.css'].includes(file)) continue;
    assert.equal(sha256(path.join(candidate, file.slice('shop-performance/'.length))), expected, file);
  }
}

function reportSheet(day, adjustment = 0) {
  const rows = Array.from({ length: 6 }, () => Array(70).fill(''));
  rows[1][0] = '营业日期【' + day.replaceAll('-', '/') + '】';
  rows[2][1] = '门店名称';
  rows[2][6] = '营业额(元)';
  rows[3][64] = '扫码支付';
  rows[3][69] = '小计';
  rows[4].splice(64, 5, '微信', '团购', '美团外卖', '淘宝闪购', '京东秒送');
  const row = rows[5];
  row[1] = '测试品牌（日坛店）';
  const channels = ['店内销售', '美团外卖', '淘宝闪购', '京东秒送'];
  channels.forEach((name, i) => {
    const start = 12 + i * 11;
    rows[3][start] = name;
    const income = (i + 1) * 20 + adjustment;
    row.splice(start, 11, income + 5, income, 5, 2, (income + 5) / 2, income / 2, '', '', '', '', '');
  });
  row[8] = 200 + adjustment * 4;
  row.splice(64, 6, 16 + adjustment, 4, 40 + adjustment, 60 + adjustment, 80 + adjustment, row[8]);
  return rows;
}

function loadWith(file, dependencies, env = {}) {
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    require: name => Object.hasOwn(dependencies, name) ? dependencies[name] : require(name),
    __dirname: path.dirname(file),
    module,
    process: { env },
    console: { log() {}, error() {} },
    setInterval: () => ({ unref() {} })
  }, { filename: file });
  return module.exports;
}

function makeHarness(appDir) {
  const sqlite = new DatabaseSync(':memory:');
  const database = {
    exec: sql => sqlite.exec(sql),
    prepare: sql => sqlite.prepare(sql),
    pragma: sql => sqlite.exec('PRAGMA ' + sql),
    transaction: handler => (...args) => {
      sqlite.exec('BEGIN');
      try {
        const result = handler(...args);
        sqlite.exec('COMMIT');
        return result;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
  };
  const db = loadWith(path.join(appDir, 'db.js'), {
    'better-sqlite3': function InMemoryDatabase() { return database; }
  }, { DB_PATH: ':memory:' });
  const storeId = db.prepare("SELECT id FROM stores WHERE code = 'rt'").get().id;
  db.prepare('INSERT INTO monthly_targets(store_id, month, target_amount) VALUES (?, ?, ?)').run(storeId, '2026-11', 9000);

  const sheets = {
    normal: reportSheet('2026-11-17'),
    replacement: reportSheet('2026-11-17', 1),
    fault: reportSheet('2026-11-18'),
    following: reportSheet('2026-11-19'),
  };
  const parser = loadWith(path.join(appDir, 'parsers/meituan_guandian.js'), {
    xlsx: {
      readFile(name) {
        if (!Object.hasOwn(sheets, name)) throw new Error('测试报表读取失败');
        return { SheetNames: ['sheet'], Sheets: { sheet: sheets[name] } };
      },
      utils: { sheet_to_json: sheet => sheet },
    },
  });
  const handlers = new Map();
  const noop = () => {};
  const app = {
    use: noop, listen: noop, delete: noop,
    get: (route, ...chain) => handlers.set('GET ' + route, chain.at(-1)),
    post: (route, ...chain) => handlers.set('POST ' + route, chain.at(-1)),
  };
  const express = Object.assign(() => app, { json: () => noop, urlencoded: () => noop, static: () => noop });
  const multer = Object.assign(() => ({ any: () => noop }), { diskStorage: () => ({}) });
  loadWith(path.join(appDir, 'server.js'), {
    express, multer,
    fs: { existsSync: () => true },
    './db': db,
    './parsers/meituan_guandian': parser,
    './ybw-core': { isCookieInsecure: () => true, createRateLimiter: () => noop },
  });

  function invoke(route, extra) {
    const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(result) { this.body = result; } };
    handlers.get(route)({ user: { role: 'manager', store_id: storeId }, ...extra }, response);
    return JSON.parse(JSON.stringify(response));
  }

  return {
    sqlite, invoke,
    upload: (...names) => invoke('POST /api/upload', {
      files: names.map(name => ({ fieldname: 'files', path: name, originalname: name + '.xlsx' })),
    }),
    dashboard: date => invoke('GET /api/dashboard', { query: { date } }),
    monthView: date => invoke('GET /api/month-view', { query: { month: date.slice(0, 7), asof: date } }),
    records: date => db.prepare('SELECT platform, income, dine_in_income, groupon_income FROM records WHERE date = ? ORDER BY platform').all(date),
  };
}

checkSourceFiles();
const original = makeHarness(baseline);
const revised = makeHarness(candidate);
const sampleDay = '2026-11-17';
const comparison = [original, revised].map(system => {
  const upload = system.upload('normal');
  const dashboard = system.dashboard(sampleDay);
  const monthView = system.monthView(sampleDay);
  assert.equal(upload.statusCode, 200);
  assert.equal(upload.body.inserted, 3);
  assert.equal(dashboard.statusCode, 200);
  assert.equal(dashboard.body.ranking.length, 1);
  assert.equal(monthView.statusCode, 200);
  return { upload, dashboard, monthView };
});
assert.deepEqual(comparison[1].upload,comparison[0].upload);
assert.deepEqual(comparison[1].monthView,comparison[0].monthView);
for (const key of Object.keys(comparison[0].dashboard.body)) {
  if(key!=='stores') assert.deepEqual(comparison[1].dashboard.body[key],comparison[0].dashboard.body[key]);
}
for(const [key,value] of Object.entries(comparison[0].dashboard.body.stores[0])) {
  assert.deepEqual(comparison[1].dashboard.body.stores[0][key],value);
}
const report = revised.dashboard(sampleDay).body.daily;
assert.equal(report.reported,1);
assert.equal(report.income,200);
assert.equal(revised.dashboard('2026-11-18').body.stores[0].today_income,null);
assert.equal(revised.dashboard('2026-11-18').body.ranking.length,0);
const previewFile={fieldname:'files',path:'replacement',originalname:'update.xlsx'};
const preview = revised.invoke('POST /api/upload',{files:[previewFile],query:{mode:'preview'}});
assert.equal(preview.body.files[0].amounts[0].before,200);
assert.equal(revised.dashboard(sampleDay).body.daily.income,200);
const confirm={files:[previewFile],query:{mode:'confirm'},body:{confirmations:JSON.stringify([preview.body.files[0].token])}};
assert.equal(revised.invoke('POST /api/upload',confirm).statusCode,200);
assert.equal(revised.invoke('POST /api/upload',confirm).statusCode,422);
assert.equal(revised.invoke('GET /api/import-history',{query:{date:sampleDay}}).body.length,2);
assert.equal(revised.upload('replacement').statusCode, 200);
const records = revised.records(sampleDay);
assert.equal(records.length, 3);
assert.equal(records.reduce((sum, row) => sum + row.dine_in_income, 0), 21);
assert.equal(records.reduce((sum, row) => sum + row.groupon_income, 0), 4);

// 让第二个渠道写入时出现 SQLite 故障，以检查已写入的第一行会回滚。
revised.sqlite.exec(`
  CREATE TRIGGER test_write_failure BEFORE INSERT ON records
  WHEN NEW.date = '2026-11-18' AND NEW.platform = 'taobao_flash'
  BEGIN SELECT RAISE(ABORT, 'synthetic database failure'); END;
`);
const batch = revised.upload('fault', 'unreadable', 'following');
assert.equal(batch.statusCode, 200);
assert.equal(batch.body.failed.length, 2);
assert.equal(batch.body.total_inserted, 3);
assert.equal(revised.records('2026-11-18').length, 0);
assert.equal(revised.records('2026-11-19').length, 3);

assert.equal(revised.monthView(sampleDay).body.stores[0].month_cum,204);
const pair=makeHarness(candidate);
const add=pair.sqlite.prepare("INSERT INTO records(store_id,date,platform,income,orders) SELECT id,?,?,?,? FROM stores WHERE code=?");
for(const [store,date,income] of [['rt','2026-10-31',100],['rt','2026-11-01',120],['jz','2026-10-31',300],['jz','2026-11-01',240],['wj','2026-11-01',0]]) {
  for(const platform of ['meituan','taobao_flash','jd']) add.run(date,platform,platform==='meituan'?income:0,income?1:0,store);
}
const hq={role:'super_admin'};
const multi=pair.invoke('GET /api/dashboard',{query:{date:'2026-11-01'},user:hq}).body;
assert.equal(multi.daily.comparable_income-multi.daily.previous_income,-40);
assert.equal(multi.daily.drivers.reduce((n,r)=>n+r.income_diff,0),-40);
assert.equal(multi.daily.target_rate,40);
assert.equal(multi.stores.find(s=>s.store_name==='望京店').report_status,'zero');
for(const [code,before,after] of [['rt',100,120],['jz',300,240]]) {
  for(const [day,value] of [['2026-09-03',before],['2026-09-10',after]]) {
    for(const p of ['meituan','taobao_flash','jd']) add.run(day,p,p==='meituan'?value:0,1,code);
  }
}
const compare=pair.invoke('GET /api/compare',{query:{date:'2026-09-10',window:7},user:hq}).body;
assert.equal(compare.stores.find(s=>s.store_name==='日坛店').delta.prev.revenue.diff,20);
assert.equal(compare.stores.find(s=>s.store_name==='金盏店').delta.prev.revenue.diff,-60);
// 门店客单拆解应能从两天源字段还原，包括分位取整。
const setFacts=pair.sqlite.prepare("UPDATE records SET turnover=?,discount=?,income=?,orders=?,raw_json=? WHERE store_id=(SELECT id FROM stores WHERE code='rt') AND date=? AND platform='meituan'");
for(const [date,gross,income,orders] of [['2026-09-03',3476.41,1145.71,64],['2026-09-10',5455.38,1649.44,95]]) {
  const discount=Math.round((gross-income)*100)/100;
  setFacts.run(gross,discount,income,orders,JSON.stringify({channels:{meituan:{turnover:gross,discount,income,orders}}}),date);
}
const weekday=pair.invoke('GET /api/dashboard',{query:{date:'2026-09-10',basis:'weekday'},user:hq}).body;
const row=weekday.daily.drivers.find(r=>r.store_name==='日坛店'&&r.channel==='美团');
assert.equal(row.ticket_effect,-51.22);
assert.deepEqual(row.components,{gross:295.08,discount:-346.31,residual:0.01});
assert.equal(row.week.length,7);
assert.equal(row.week[0].rate,null);
assert.equal(weekday.daily.platform_rates.find(p=>p.name==='美团').covered,1);
for(const day of ['2026-08-13','2026-08-20','2026-08-27']) {
  for(const p of ['meituan','taobao_flash','jd']) add.run(day,p,p==='meituan'?100:0,1,'rt');
}
const alerts=pair.invoke('GET /api/compare',{query:{date:'2026-09-10',window:7},user:hq}).body.analysis;
assert.equal(alerts.anomalies.find(s=>s.store_name==='日坛店').samples,4);
assert.equal(alerts.anomalies.find(s=>s.store_name==='日坛店').expected,100);
assert.equal(alerts.weekday_coverage.find(s=>s.name==='金盏店').assessed,false);
pair.sqlite.close();
original.sqlite.close();
revised.sqlite.close();
console.log('通过：基线校验、导入预览及版本冲突、缺报与零营业、历史截止、跨月和分店环比、业绩通晒取数与事务回滚。');
