const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const fixture = JSON.parse(fs.readFileSync(0, 'utf8'));
const edge = path.join(process.env['ProgramFiles(x86)'], 'Microsoft', 'Edge', 'Application', 'msedge.exe');
const publicDir = path.resolve(__dirname, '..', '接管工作副本', 'shop-performance', 'public');
const assets = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/dashboard-tools.js': ['dashboard-tools.js','text/javascript; charset=utf-8'],
  '/css/base.css': ['css/base.css', 'text/css'],
  '/css/app.css': ['css/app.css', 'text/css'],
  '/vendor/html2canvas.min.js': ['vendor/html2canvas.min.js', 'text/javascript'],
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (Object.hasOwn(assets, url.pathname)) {
    const [file, type] = assets[url.pathname];
    res.writeHead(200, { 'content-type': type }).end(fs.readFileSync(path.join(publicDir, file)));
    return;
  }
  const responses = {
    '/api/me': fixture.accountData, '/api/latest-date': { latest: fixture.day },
    '/api/dashboard': fixture.dashboard, '/api/month-view': fixture.monthView,
    '/api/compare': fixture.comparisons?.[url.searchParams.get('window')],
  };
  if (Object.hasOwn(responses, url.pathname) && responses[url.pathname]) {
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(responses[url.pathname]));
    return;
  }
  res.writeHead(404).end();
});

async function waitFor(get, label, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await get();
    if (result) return result;
    await delay(120);
  }
  throw new Error(label + '超时');
}

async function run() {
  assert(fs.existsSync(edge), '未找到 Edge 浏览器');
  const temp = path.resolve(os.tmpdir());
  const work = fs.mkdtempSync(path.join(temp, 'ybw-poster-'));
  const downloads = path.join(work, 'downloads');
  const profile = path.join(work, 'profile');
  fs.mkdirSync(downloads);
  let browser;
  let socket;
  let stopped;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const origin = 'http://127.0.0.1:' + server.address().port;
    browser = spawn(edge, ['--headless=new', '--disable-gpu', '--disable-background-networking',
      '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0',
      '--user-data-dir=' + profile, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
    let startupError;
    browser.once('error', error => { startupError = error; });
    stopped = new Promise(resolve => browser.once('close', resolve));
    const debugFile = path.join(profile, 'DevToolsActivePort');
    const port = await waitFor(() => {
      if (startupError) throw startupError;
      if (browser.exitCode !== null) throw new Error('隔离浏览器退出：' + browser.exitCode);
      return fs.existsSync(debugFile) && Number(fs.readFileSync(debugFile, 'utf8').split('\n')[0]);
    }, '浏览器调试端口');
    const tabs = await (await fetch('http://127.0.0.1:' + port + '/json/list', { signal: AbortSignal.timeout(3000) })).json();
    socket = new WebSocket(tabs.find(tab => tab.type === 'page').webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
    let nextId = 0;
    const pending = new Map();
    socket.addEventListener('message', event => {
      const reply = JSON.parse(event.data);
      const callbacks = pending.get(reply.id);
      if (!callbacks) return;
      pending.delete(reply.id);
      if (reply.error) callbacks.reject(new Error(reply.error.message));
      else callbacks.resolve(reply.result);
    });
    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timeout = setTimeout(() => { pending.delete(id); reject(new Error(method + ' 超时')); }, 5000);
        pending.set(id, {
          resolve: result => { clearTimeout(timeout); resolve(result); },
          reject: error => { clearTimeout(timeout); reject(error); },
        });
        socket.send(JSON.stringify({ id, method, params }));
      });
    }
    async function evaluate(expression) {
      const response = await send('Runtime.evaluate', { expression, returnByValue: true });
      if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
      return response.result.value;
    }
    await send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:960,deviceScaleFactor:1,mobile:false});
    await send('Page.navigate', { url: origin + '/' });
    await waitFor(() => evaluate('typeof dash !== "undefined" && !!dash?.stores?.length && typeof html2canvas === "function"'), '通晒页面加载');
    await waitFor(()=>evaluate('document.querySelector("#contrib").textContent.trim().length > 0'),'门店贡献度');
    const rightCard='document.querySelector("#contrib").closest(".panel")';
    const cardHeight=await evaluate(rightCard+'.offsetHeight');
    const top=await evaluate('document.querySelector(".channel-analysis").offsetTop');
    await evaluate('document.querySelector("#channelChanges").open=true');
    await waitFor(()=>evaluate('!!document.querySelector("#allDriverRows")'),'桌面结论卡');
    assert(await evaluate('document.querySelector("#allDriverRows").open'),'桌面默认展示明细表');
    assert.equal(await evaluate(rightCard+'.offsetHeight'),cardHeight,'展开分析不拉高右侧概览');
    assert.equal(await evaluate('document.querySelector(".channel-analysis").offsetTop'),top,'分析区在两张概览下方独立展开');
    assert(await evaluate(`(() => {
      const analysis=document.querySelector('.channel-analysis').getBoundingClientRect();
      const overview=document.querySelector('.split').getBoundingClientRect();
      return Math.abs(analysis.left-overview.left)<1 && Math.abs(analysis.right-overview.right)<1;
    })()`),'渠道分析外框与上方概览左右对齐');
    assert(await evaluate(`(() => {
      const summary = document.querySelector('.driver-highlights').getBoundingClientRect();
      const ticket = document.querySelector('#ticketPanel').getBoundingClientRect();
      const table = document.querySelector('.ticket-compare table').getBoundingClientRect();
      const rate = document.querySelector('.rate-week').getBoundingClientRect();
      const all = document.querySelector('#allDriverRows').getBoundingClientRect();
      const platform = document.querySelector('#platformRates').closest('details');
      platform.open = true;
      const platformTable = platform.querySelector('table').getBoundingClientRect();
      const content = document.querySelector('#ticketDetail').getBoundingClientRect();
      const heading = document.querySelector('#ticketTitle').getBoundingClientRect();
      const panel = document.querySelector('#ticketPanel');
      const inset = parseFloat(getComputedStyle(panel).paddingLeft)+panel.clientLeft;
      const aligned = Math.abs(content.left-ticket.left-inset) < 2 &&
        Math.abs(heading.left-content.left) < 2 && Math.abs(table.left-content.left) < 2;
      return aligned && ticket.left >= all.right && Math.abs(ticket.top-all.top) <= 1 &&
        ticket.height > 0 && all.top >= summary.bottom &&
        table.width > 0 && Math.abs(table.width-content.width) < 2 && Math.abs(rate.width-table.width) < 2 &&
        platformTable.width > 0 && platformTable.width < 640;
    })()`),'桌面结论在上，完整表与拆解并排');
    const selectedBackground='getComputedStyle(document.querySelector("#allDriverRows tr.is-current")).backgroundColor';
    const activeColor=await evaluate(selectedBackground);
    assert.equal(activeColor,'rgb(247, 234, 234)','奇数行整行高亮');
    await evaluate('document.querySelectorAll("#allDriverRows .pick-driver")[1].click()');
    assert.equal(await evaluate(selectedBackground),activeColor,'偶数行高亮优先于交替底色');
    assert.equal(await evaluate('document.querySelectorAll("#allDriverRows tr.is-current").length'),1);
    assert(await evaluate('document.querySelector("#ticketTitle").textContent.includes(document.querySelectorAll("#allDriverRows .pick-driver")[1].textContent)'));
    await evaluate('document.querySelector("button.driver-highlight").focus()');
    await send('Input.dispatchKeyEvent',{type:'rawKeyDown',key:' ',code:'Space',windowsVirtualKeyCode:32,nativeVirtualKeyCode:32});
    await send('Input.dispatchKeyEvent',{type:'keyUp',key:' ',code:'Space',windowsVirtualKeyCode:32,nativeVirtualKeyCode:32});
    await waitFor(()=>evaluate('document.activeElement.matches("button.driver-highlight[aria-pressed=true]") && document.querySelector("#allDriverRows tr.is-current button").dataset.driver === document.activeElement.dataset.driver'),'空格选中整张结论卡');
    if(process.env.YBW_LAYOUT_SCREENSHOT) {
      await evaluate('document.querySelector(".channel-analysis").scrollIntoView({block:"start"}); window.scrollBy(0,-62);');
      const shot=await send('Page.captureScreenshot',{format:'png'});
      fs.writeFileSync(process.env.YBW_LAYOUT_SCREENSHOT,Buffer.from(shot.data,'base64'));
    }
    await evaluate('document.querySelector("#posterBtn").click()');
    const file = path.join(downloads, '于百万_业绩通晒_' + fixture.day + '.png');
    await waitFor(async () => {
      const banner = await evaluate('document.querySelector("#banner")?.textContent');
      if (banner?.includes('海报生成失败')) throw new Error(banner);
      return fs.existsSync(file) && banner?.includes('已生成并下载');
    }, 'PNG 下载', 25000);
    const png = fs.readFileSync(file);
    assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    const width = png.readUInt32BE(16);
    const height = png.readUInt32BE(20);
    assert(width > 500 && height > 500 && png.length > 10000);
    console.log('浏览器下载通过：' + path.basename(file) + '，' + width + '×' + height + '，' + png.length + ' 字节。');
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await send('Page.navigate',{url:origin+'/?date='+fixture.day});
    await waitFor(()=>evaluate('document.querySelector("#coverage")?.textContent.includes("已报")'),'手机上报状态');
    await evaluate('document.querySelector("#channelChanges").open=true');
    await waitFor(()=>evaluate('document.querySelector("#driverRows").textContent.includes("对比")'),'同页渠道分析');
    assert(await evaluate('!!document.querySelector(".driver-highlight") && !document.querySelector("#allDriverRows").open'));
    assert(await evaluate('getComputedStyle(document.querySelector("#ticketPanel")).display === "none"'));
    await evaluate('document.querySelector(".driver-highlight .highlight-metrics").click()');
    await waitFor(()=>evaluate('document.querySelectorAll(".rate-week div").length === 7 && getComputedStyle(document.querySelector("#ticketPanel")).display !== "none"'),'七日到手率');
    assert(await evaluate('document.querySelector(".ticket-compare").getBoundingClientRect().top >= document.querySelector(".ticket-effects").getBoundingClientRect().bottom'),'手机按阅读顺序堆叠');
    await evaluate('document.querySelector("#allDriverRows").open=true');
    await evaluate('document.querySelector("#allDriverRows .pick-driver").click()');
    assert(await evaluate('document.querySelector("#ticketTitle").textContent.includes(document.querySelector("#allDriverRows .pick-driver").textContent)'));
    assert(await evaluate('document.querySelector("#platformRates").textContent.includes("到手率")'));
    await evaluate('document.querySelector("#uploadBtn").click()');
    assert(await evaluate('document.querySelector("#drop").classList.contains("show")'),'同页导入');
    assert(await evaluate('!document.body.textContent.includes("经营晨报")'),'独立晨报已撤下');
    console.log('通过：390 像素手机数据追踪、上报状态、渠道分析和原位导入。');
    await send('Browser.close').catch(() => browser.kill());
  } finally {
    socket?.close();
    if (browser && browser.exitCode === null) browser.kill();
    if (stopped) await Promise.race([stopped, delay(3000)]);
    server.closeAllConnections();
    if (server.listening) server.close();
    assert.equal(path.dirname(path.resolve(work)), temp);
    assert(path.basename(work).startsWith('ybw-poster-'));
    try {
      fs.rmSync(work, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
    } catch (error) {
      if (!['EPERM', 'EBUSY'].includes(error.code)) throw error;
      console.warn('Edge 临时目录仍被占用：' + work);
    }
  }
}

run().catch(error => {
  console.error(error.message + (error.cause?.code ? '（' + error.cause.code + '）' : ''));
  process.exitCode = 1;
});
