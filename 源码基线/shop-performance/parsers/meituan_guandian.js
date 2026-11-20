// 美团管家「综合营业统计」报表解析器 v1
// 模板识别：表头第3行含"门店名称"，第4行含"美团外卖/淘宝闪购/京东秒送"渠道分组
// 产出：按门店×渠道的结构化数据（全字段保留，通晒口径后续按需取用）
const XLSX = require('xlsx');

// 门店名称 → 系统门店编码 映射表（含变体/历史名）
// 规则：优先精确匹配括号内门店名；可扩展别名
const STORE_NAME_MAP = [
  { names: ['大悦城店'], code: 'dyz' },
  { names: ['日坛店', '朝阳门店'], code: 'rt' },   // 美团管家后台名=朝阳门店，实际=日坛店
  { names: ['金盏店'], code: 'jz' },
  { names: ['望京店'], code: 'wj' },               // 历史名"麻辣香锅"，已改后台名
];

// 渠道定义：渠道名 → { startCol(0基索引), metrics[11项] }
const CHANNEL_DEFS = [
  { key: 'dine_in',     name: '店内销售' },
  { key: 'meituan',     name: '美团外卖' },
  { key: 'taobao_flash', name: '淘宝闪购' },
  { key: 'jd',          name: '京东秒送' },
];
const CHANNEL_METRICS = [
  'turnover',    // 营业额(元)
  'income',      // 营业收入(元)
  'discount',    // 优惠金额(元)
  'orders',      // 订单量
  'avg_pre',     // 折前单均(元)
  'avg_post',    // 折后单均(元)
  'discount_rate', // 优惠占比
  'arrival_rate',  // 到手率
  'order_share',   // 占总订单量
  'ppp_pre',     // 折前人均(元)
  'ppp_post',    // 折后人均(元)
];

// 营业收入构成（结账方式维度）：微信扫码=堂食扫码；团购=美团/大众点评团购核销；外卖三平台
// 验证关系：全店营业收入(C9) = 微信 + 团购 + 美团 + 淘闪 + 京东（营业收入构成小计 C70）
//          店内销售 income = 微信扫码 + 团购核销

// 数字清洗："6,593.86"→6593.86；"29.27%"→0.2927；"--"/空→0
function num(v) {
  if (v == null || v === '') return 0;
  const s = String(v).replace(/,/g, '').replace(/[￥¥\s]/g, '');
  if (s === '--' || s === '-' || s === '合计') return 0;
  if (s.endsWith('%')) return Math.round(parseFloat(s.slice(0, -1)) * 1000) / 100000; // 百分比→小数
  const n = parseFloat(s);
  return isNaN(n) ? 0 : n;
}

function matchStore(storeName) {
  const m = storeName.match(/（([^）]+)）/);
  const short = m ? m[1].trim() : storeName;
  for (const item of STORE_NAME_MAP) {
    if (item.names.some(n => short.includes(n) || storeName.includes(n))) return item.code;
  }
  return null;
}

// 从标题行提取营业日期："营业日期【2026/10/27-2026/10/27】" → "2026-10-27"
function extractDate(titleRow) {
  const s = String(titleRow[0] || '');
  const m = s.match(/营业日期【\s*(\d{4})\/(\d{1,2})\/(\d{1,2})/);
  if (m) {
    const d = `${m[1]}-${String(m[2]).padStart(2, '0')}-${String(m[3]).padStart(2, '0')}`;
    return d;
  }
  return null;
}

// 主入口：解析文件 → { template, date, stores: [...] }
function parseGuandian(filePath) {
  const wb = XLSX.readFile(filePath);
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: false, defval: '' });

  // 模板识别：第3行(索引2)需含"门店名称"与"营业额(元)"；第4行(索引3)需含渠道
  const h3 = rows[2] || [], h4 = rows[3] || [];
  if (!h3.includes('门店名称') || !h3.includes('营业额(元)')) {
    return { ok: false, error: '不是美团管家综合营业统计模板（缺少表头特征）' };
  }
  const channelOk = CHANNEL_DEFS.every(c => h4.includes(c.name));
  if (!channelOk) {
    return { ok: false, error: '渠道表头缺失（需要 店内销售/美团外卖/淘宝闪购/京东秒送）' };
  }

  // 定位每个渠道的起始列（在 h4 中找渠道名）
  const channelStart = {};
  for (const c of CHANNEL_DEFS) {
    const idx = h4.indexOf(c.name);
    if (idx === -1) return { ok: false, error: `找不到渠道列: ${c.name}` };
    channelStart[c.key] = idx;
  }

  const date = extractDate(rows[1] || []);
  if (!date) return { ok: false, error: '无法从标题行解析营业日期' };

  const stores = [];
  for (let i = 5; i < rows.length; i++) {
    const r = rows[i];
    const storeName = String(r[1] || '').trim();
    if (!storeName || storeName === '合计' || r[0] === '合计') continue;

    const storeCode = matchStore(storeName);
    if (!storeCode) {
      stores.push({ store_name: storeName, store_code: null, unmatched: true });
      continue;
    }

    const channels = {};
    for (const c of CHANNEL_DEFS) {
      const base = channelStart[c.key];
      const ch = {};
      CHANNEL_METRICS.forEach((m, j) => { ch[m] = num(r[base + j]); });
      channels[c.key] = ch;
    }
    // 门店总计（主列）：营业额C7 优惠金额C8 营业收入C9 到手率C10 订单量C11 用餐人数C12（1基）→ 索引6..11
    const total = {
      turnover: num(r[6]), income: num(r[8]), discount: num(r[7]),
      arrival_rate: num(r[9]), orders: num(r[10]), diners: num(r[11]),
    };
    // 营业收入构成（结账方式）：微信扫码 / 团购 / 外卖三平台 / 小计
    // 列定位：以"扫码支付"（h4=R3 分组头）为起点，在指标行 r4=rows[4] 内扫描列头，
    // 兼容新旧两种模板（旧模板无"美团/大众点评支付"列）：
    //   旧模板：64微信 65团购 66美团外卖 67淘闪 68京东 69小计
    //   新模板：64微信 65团购 66美团支付 67美团外卖 68淘闪 69京东 70小计
    const r4 = rows[4] || [];
    const payBase = h4.indexOf('扫码支付');            // 分组起点（R3:64，新旧模板一致）
    const subCol = h4.indexOf('小计', payBase);        // 分组内小计列（旧69/新70）
    let wechatCol = -1, meituanCol = -1, taobaoCol = -1, jdCol = -1;
    for (let j = payBase; j < subCol && j < r4.length; j++) {   // 仅在分组内扫描（64..小计前）
      const hh = String(r4[j]);
      if (hh === '微信') wechatCol = j;
      else if (hh === '美团外卖') meituanCol = j;
      else if (hh === '淘宝闪购') taobaoCol = j;
      else if (hh === '京东秒送') jdCol = j;
    }
    const pay = (payBase >= 0 && subCol > payBase && wechatCol >= 0 && meituanCol >= 0 && taobaoCol >= 0 && jdCol >= 0) ? {
      wechat: num(r[wechatCol]),          // 微信扫码（堂食扫码支付）
      groupon: num(r[payBase + 1]),       // 美团/大众点评团购核销营收（固定为扫码支付+1）
      meituan: num(r[meituanCol]),
      taobao_flash: num(r[taobaoCol]),
      jd: num(r[jdCol]),
      subtotal: num(r[subCol]),           // 营业收入构成小计（旧69/新70）
    } : null;
    // 校验：渠道求和 = 全店营业收入（防止模板变化导致静默错数）
    const chSum = Object.values(channels).reduce((a, c) => a + c.income, 0);
    const incomeDelta = Math.abs(total.income - chSum);
    const payDelta = pay ? Math.abs(total.income - pay.subtotal) : -1;
    stores.push({
      store_code: storeCode, store_name: storeName, total, channels, pay,
      check: { channels_income_sum: chSum, income_delta: incomeDelta, pay_delta: payDelta },
    });
  }

  return { ok: true, template: 'meituan_guandian_v1', date, stores };
}

module.exports = { parseGuandian, matchStore };
