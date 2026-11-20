const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const input = typeof fixtureInput === 'undefined' ? JSON.parse(fs.readFileSync(0, 'utf8')) : fixtureInput;
const runtime = {
  'portal': '/home/sangyu/apps/portal',
  'sso-auth': '/home/sangyu/apps/sso-auth',
  'kitchen-clean': '/home/sangyu/kitchen-clean',
  'shop-performance': '/home/sangyu/apps/shop-performance',
};
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ybw-e2e-'));
const children = [];
const occupied = new Set();
const testKey = randomBytes(32).toString('hex');

function copySources() {
  for (const { name, content } of input.files) {
    assert.match(name, /^(portal|sso-auth|kitchen-clean|shop-performance|shop-candidate)\/[a-z0-9_.\/-]+$/);
    assert(!name.split('/').includes('..'));
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Buffer.from(content, 'base64'), { flag: 'wx' });
  }
}

async function pickPort() {
  while (true) {
    const probe = net.createServer();
    const port = await new Promise((resolve, reject) => {
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => resolve(probe.address().port));
    });
    await new Promise(resolve => probe.close(resolve));
    if (!occupied.has(port)) {
      occupied.add(port);
      return port;
    }
  }
}

async function start(app, sso) {
  const port = await pickPort();
  const origin = 'http://127.0.0.1:' + port;
  const cwd = path.join(root, app);
  const child = spawn(process.execPath, ['server.js'], {
    cwd, stdio: ['ignore', 'ignore', 'pipe'],
    env: {
      PORT: String(port), NODE_ENV: 'test',
      DB_PATH: path.join(cwd, 'isolated-shop.db'),
      NODE_PATH: path.join(runtime[app === 'shop-candidate' ? 'shop-performance' : app], 'node_modules'),
      SSO_ORIGIN: sso || origin, SSO_KEY: testKey,
      SESSION_SECRET: randomBytes(32).toString('hex'), COOKIE_INSECURE: '1',
    },
  });
  const exited = new Promise(resolve => child.once('exit', resolve));
  children.push({ child, exited });
  let errorText = '';
  child.stderr.on('data', chunk => { errorText = (errorText + chunk).slice(-1600); });
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(app + ' 启动失败 ' + errorText);
    try {
      if ((await fetch(origin + '/api/health', { signal: AbortSignal.timeout(1000) })).ok) return origin;
    } catch {}
    await delay(100);
  }
  throw new Error(app + ' 健康检查超时');
}

async function request(origin, endpoint, options = {}) {
  const { cookie, data, form, expected = 200, headers = {}, method = data || form ? 'POST' : 'GET' } = options;
  const response = await fetch(origin + endpoint, {
    method,
    headers: { ...headers, ...(cookie ? { cookie } : {}), ...(data ? { 'content-type': 'application/json' } : {}) },
    body: data ? JSON.stringify(data) : form,
    signal: AbortSignal.timeout(10000),
  });
  assert.equal(response.status, expected, endpoint);
  return { body: await response.json(), cookies: response.headers.getSetCookie() };
}

function reportBytes(day, adjustment = 0) {
  const XLSX = require(path.join(runtime['shop-performance'], 'node_modules', 'xlsx'));
  const rows = Array.from({ length: 6 }, () => Array(70).fill(''));
  rows[1][0] = '营业日期【' + day.replaceAll('-', '/') + '】';
  rows[2][1] = '门店名称';
  rows[2][6] = '营业额(元)';
  rows[3][64] = '扫码支付';
  rows[3][69] = '小计';
  rows[4].splice(64, 5, '微信', '团购', '美团外卖', '淘宝闪购', '京东秒送');
  const row = rows[5];
  row[1] = '测试品牌（日坛店）';
  ['店内销售', '美团外卖', '淘宝闪购', '京东秒送'].forEach((name, i) => {
    const start = 12 + i * 11;
    const income = 20 * (i + 1) + adjustment;
    rows[3][start] = name;
    row.splice(start, 11, income + 5, income, 5, 2, (income + 5) / 2, income / 2, '', '', '', '', '');
  });
  row[8] = 200 + adjustment * 4;
  row.splice(64, 6, 16 + adjustment, 4, 40 + adjustment, 60 + adjustment, 80 + adjustment, row[8]);
  const book = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(book, XLSX.utils.aoa_to_sheet(rows), '测试日报');
  return XLSX.write(book, { type: 'buffer', bookType: 'xlsx' });
}

function uploadForm(name, bytes) {
  const form = new FormData();
  form.append('files', new Blob([bytes]), name + '.xlsx');
  return form;
}

async function run() {
  copySources();
  const sso = await start('sso-auth');
  const portal = await start('portal', sso);
  const qsc = await start('kitchen-clean', sso);
  const original = await start('shop-performance', sso);
  const candidate = await start('shop-candidate', sso);
  const day = '2026-11-17';
  const account = { username: 'takeover_fixture', password: randomBytes(24).toString('hex') };
  const testName = '接管测试负责人';

  await request(sso, '/api/admin/users', {
    data: { ...account, real_name: testName, role: 'manager', store_code: 'rt' },
    headers: { 'X-SSO-Key': testKey },
  });
  const login = await request(portal, '/api/login', { data: account });
  const shared = login.cookies.find(value => value.startsWith('ybw_sso=')).split(';')[0];
  const me = (await request(portal, '/api/me', { cookie: shared })).body;
  assert.equal(me.store_code, 'rt');
  const qscLogin = await request(qsc, '/api/auth/me', { cookie: shared });
  const qscUser = qscLogin.body;
  const stores = (await request(qsc, '/api/public/stores')).body;
  assert.equal(qscUser.store_id, stores.find(store => store.code === 'rt').id);
  if (input.qscCandidate) {
    const local = qscLogin.cookies.find(value => value.startsWith('connect.sid=')).split(';')[0];
    await request(qsc, '/api/auth/me', { cookie: local, expected: 401 });
  }
  const formPath = '/api/public/stores/rt/records?form=daily&date=' + day;
  const form = (await request(qsc, formPath)).body;
  assert(form.items.length > 0);
  let inspectionPhoto = '';
  let uploadPhoto;
  if (input.qscCandidate) {
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/XWQAAAAASUVORK5CYII=', 'base64');
    uploadPhoto = async () => {
      const photo = new FormData();
      photo.append('photo', new Blob([png], { type: 'image/png' }), 'fixture.png');
      return (await request(qsc, '/api/admin/upload', { cookie: shared, form: photo })).body;
    };
    inspectionPhoto = (await uploadPhoto()).filename;
    assert.match(inspectionPhoto, /^record-/);
  }
  await request(qsc, '/api/admin/records', { cookie: shared, data: {
    store_id: qscUser.store_id, form_code: 'daily', record_date: day,
    inspector_name: testName, notes: '合成内部备注',
    items: [{ item_id: form.items[0].item_id, is_done: 1, cleaner_name: '合成责任人', photo_path: inspectionPhoto }],
  } });
  const record = (await request(qsc, formPath)).body;
  assert.equal(record.inspector_name, testName);
  assert.equal(record.notes, '');
  assert.equal(Number(record.items[0].is_done), 1);
  const visible = stores.find(store => store.code === 'jz');
  await request(qsc, '/api/admin/records?store_id=' + visible.id + '&form=daily&date=' + day, { cookie: shared, expected: 403 });
  if (input.qscCandidate) {
    const deletePhoto = filename => request(qsc, '/api/admin/photo', { method: 'DELETE', cookie: shared, data: { filename } });
    await deletePhoto(inspectionPhoto);
    assert.equal((await fetch(qsc + '/uploads/' + inspectionPhoto)).status, 200, '编辑中原记录保留照片');
    const draft = await uploadPhoto();
    const second = { username: 'takeover_second', password: randomBytes(24).toString('hex') };
    await request(sso, '/api/admin/users', {
      data: { ...second, role: 'manager', store_code: 'jz' },
      headers: { 'X-SSO-Key': testKey },
    });
    const other = (await request(portal, '/api/login', { data: second })).cookies
      .find(value => value.startsWith('ybw_sso=')).split(';')[0];
    await request(qsc, '/api/admin/photo', {
      method: 'DELETE', cookie: other, data: { filename: draft.filename }, expected: 403,
    });
    await deletePhoto(draft.filename);
    assert.equal((await fetch(qsc + draft.url)).status, 404, '本人未提交草稿应能删除');
  }

  const bytes = reportBytes(day);
  const cases = [];
  for (const app of [original, candidate]) {
    const accountData = (await request(app, '/api/me', { cookie: shared })).body;
    assert.equal(accountData.role, 'manager');
    const scopedStores = (await request(app, '/api/stores', { cookie: shared })).body;
    assert.equal(scopedStores.length, 1);
    assert.equal(scopedStores[0].code, 'rt');
    const upload = (await request(app, '/api/upload', { cookie: shared, form: uploadForm('synthetic', bytes) })).body;
    assert.equal(upload.inserted, 3);
    const dashboard = (await request(app, '/api/dashboard?date=' + day, { cookie: shared })).body;
    const monthView = (await request(app, '/api/month-view?month=2026-11&asof=' + day, { cookie: shared })).body;
    const comparisons = {};
    for (const window of [7, 30]) {
      comparisons[window] = (await request(app, '/api/compare?date=' + day + '&window=' + window, { cookie: shared })).body;
    }
    assert.equal(dashboard.ranking.length, app===candidate?0:1,'无目标门店在新版退出达成率榜');
    assert.equal(monthView.stores.length, 1);
    cases.push({ upload, dashboard, monthView, accountData, comparisons });
  }
  assert.deepEqual(cases[1].upload,cases[0].upload);
  assert.deepEqual(cases[1].monthView,cases[0].monthView);
  assert.equal(cases[1].dashboard.daily.income,cases[0].dashboard.stores[0].today_income);
  assert.deepEqual(cases[1].comparisons[7].current,cases[0].comparisons[7].current);
  const preview = (await request(candidate,'/api/upload?mode=preview',{cookie:shared,form:uploadForm('review',reportBytes(day,1))})).body;
  assert.equal(preview.files[0].amounts[0].before,200);
  const confirmed = () => {
    const form=uploadForm('review',reportBytes(day,1));
    form.append('confirmations',JSON.stringify([preview.files[0].token]));
    return form;
  };
  await request(candidate,'/api/upload?mode=confirm',{cookie:shared,form:confirmed()});
  await request(candidate,'/api/upload?mode=confirm',{cookie:shared,form:confirmed(),expected:422});
  const home=await fetch(candidate+'/');
  const html=await home.text();
  assert(html.includes('门店渠道收入变化') && !html.includes('经营晨报'));
  for(const url of ['/dashboard-tools.js','/details.html','/daily.html']) assert.equal((await fetch(candidate+url)).status,200);
  assert.equal((await fetch(candidate+'/api/shared-reports',{headers:{cookie:shared}})).status,404);

  const correction = uploadForm('corrected', reportBytes(day, 1));
  correction.append('files', new Blob(['synthetic unreadable workbook']), 'unreadable.xlsx');
  const corrected = (await request(candidate, '/api/upload', { cookie: shared, form: correction })).body;
  assert.equal(corrected.total_inserted, 3);
  assert.equal(corrected.failed.length, 1);
  await request(candidate,'/api/upload',{cookie:shared,form:uploadForm('baseline-day',reportBytes('2026-11-16',2))});
  cases[1].dashboard=(await request(candidate,'/api/dashboard?date='+day,{cookie:shared})).body;
  const example=cases[1].dashboard.daily.drivers.find(r=>r.channel==='美团');
  assert(example.components && example.week.length===7);
  assert.equal(cases[1].dashboard.daily.dining[0].current.groupon,4);
  const checks = ['四应用真实依赖及健康接口', '工作台登录与单店权限', 'QSC 填报和匿名卫生公示', '真实 XLSX 上传、同日覆盖、失败批次续跑及通晒取数一致'];
  if (input.qscCandidate) checks.push('QSC 草稿照片归属、已提交照片保留、退出共享登录后的本地会话拒绝均通过');
  return { checks, fixture: { ...cases[1], day } };
}

(async () => {
  try {
    const result = await run();
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    for (const { child } of children) child.kill('SIGTERM');
    await Promise.all(children.map(({ exited }) => exited));
    fs.rmSync(root, { recursive: true, force: true });
  }
})();
