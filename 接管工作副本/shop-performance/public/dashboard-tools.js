'use strict';

const labels = {missing:'待报',partial:'部分到数',zero:'零营业',reported:'已报',closed:'休业',unknown:'历史范围待确认'};
function reportState(status) { return labels[status] || '待核对'; }

function storeNote(store) {
  const note = store.note ? '<p class="store-note">'+esc(store.note)+'</p>' : '';
  const button = me.role === 'employee' ? '' : '<button class="note-link" data-note="'+store.store_id+'">营业状态与备注</button>';
  const zero = store.report_status === 'zero' ? '<small>已报 · 零营业</small>' : '';
  return zero + note + button;
}

const analysisLink=new URLSearchParams(location.search);
let jumpToDrivers=analysisLink.get('analysis')==='drivers';
if(analysisLink.get('basis')==='weekday')$('#changeBasis').value='weekday';

function renderCoverage(d) {
  const names = d.stores.filter(s => s.today_income == null).map(s => s.store_name+'（'+reportState(s.report_status)+'）');
  $('#coverage').textContent = ['已报 '+d.daily.reported+'/'+d.daily.expected+' 家',...names,d.daily.updated_at?'更新于 '+d.daily.updated_at:''].filter(Boolean).join(' · ');
  renderDining(d);
  if(jumpToDrivers && !$('#channelChanges').open) $('#channelChanges').open=true;
  else if ($('#channelChanges').open) loadDrivers();
}

function renderDining(d) {
  $('#platformRates').innerHTML='<div class="tbl-wrap"><table class="driver-table"><thead><tr><th>平台</th><th>折前营业额</th><th>优惠金额 / 占比</th><th>营业收入 / 到手率</th></tr></thead><tbody>'+
    d.daily.platform_rates.map(r=>'<tr><th>'+esc(r.name)+'<br><small>'+r.covered+'/'+d.daily.expected+' 店</small></th><td>'+fmt(r.covered?r.gross:null)+'</td><td>'+fmt(r.covered?r.discount:null)+'<br>'+(r.discount_rate==null?'—':fmt(r.discount_rate)+'%')+'</td><td>'+fmt(r.covered?r.income:null)+'<br>'+(r.income_rate==null?'—':fmt(r.income_rate)+'%')+'</td></tr>').join('')+
    '</tbody></table></div><small>按已对账门店合计金额计算，口径为营业报表收入。</small>';
  $('#diningMix').innerHTML=d.daily.dining.map(row=>{
    const a=row.current,b=row.previous;
    if(!a)return '<p>'+esc(row.name)+' · 支付明细待对账</p>';
    const share=a.total>0?fmt(100*a.groupon/a.total)+'%':'—';
    return '<p><b>'+esc(row.name)+'</b>　堂食 ¥'+fmt(a.total)+'<br>团购 ¥'+fmt(a.groupon)+'（占 '+share+'） · 微信 ¥'+fmt(a.wechat)+' · 其余支付 ¥'+fmt(a.other)+
      (b?' <small>团购较 '+d.daily.previous_date+' '+(a.groupon>=b.groupon?'+':'')+fmt(a.groupon-b.groupon)+' 元</small>':'')+'</p>';
  }).join('')||'暂无已报门店';
}

function ticketPanel(row,base,date) {
  const c=row.components, a=row.after, b=row.before;
  if(!a || !b)return '<p>折前金额、优惠与收入缺少可核对的明细。</p>';
  const signed=v=>(v>0?'+':'')+fmt(v);
  const width=c?Math.max(Math.abs(c.gross),Math.abs(c.discount),1):1;
  const bar=(name,value)=>'<div class="effect"><span>'+name+'</span><i><em style="width:'+Math.min(100,Math.abs(value)*100/width)+'%;background:'+(value<0?'#a84136':'#23765a')+'"></em></i><b>'+signed(value)+' 元</b></div>';
  const lines=[['单量',b.orders,a.orders,'单'],['折前单均',b.gross_ticket,a.gross_ticket,'元'],['每单优惠',b.discount_ticket,a.discount_ticket,'元'],['优惠率',b.discount_rate,a.discount_rate,'%'],['到手率',b.income_rate,a.income_rate,'%']];
  return '<div class="ticket-layout"><div class="ticket-effects">'+(c?'<p><b>客单贡献 '+signed(row.ticket_effect)+' 元</b> · 按当日 '+a.orders+' 单折算</p>'+bar('折前单均变化',c.gross)+bar('每单优惠变化',c.discount)+
    (c.residual?'<small>对账及取整差额 '+signed(c.residual)+' 元</small>':''):'<p>有一日为零单，无法拆解客单贡献。</p>')+
    '</div><div class="ticket-compare"><table class="driver-table"><thead><tr><th>指标</th><th>'+base+'</th><th>'+date+'</th></tr></thead><tbody>'+lines.map(([k,v,w,u])=>{
      const display=value=>value==null?'—':(u==='单'?fmtInt(value):fmt(value))+u;
      return '<tr><th scope="row">'+k+'</th><td>'+display(v)+'</td><td>'+display(w)+'</td></tr>';
    }).join('')+'</tbody></table></div>'+
    '<div class="ticket-trend"><p><b>近 7 天到手率</b></p><div class="rate-week">'+row.week.map(p=>'<div><span>'+p.day.slice(5)+'</span><i><em style="height:'+Math.max(0,Math.min(100,p.rate||0))+'%"></em></i><b>'+(p.rate==null?'—':Number(p.rate.toFixed(1))+'%')+'</b></div>').join('')+'</div>'+
    '<small>优惠率＝优惠 ÷ 折前营业额。到手率＝收入 ÷ 折前营业额。</small></div></div>';
}
function driverHighlights(rows) {
  const best=rows.findIndex(r=>r.income_diff>0);
  const worst=rows.findIndex(r=>r.income_diff<0);
  const hiddenDrop=rows.findIndex(r=>r.orders_diff>0 && r.income_diff<0 && r.ticket_effect<0);
  const highlights=new Map();
  if(best!==-1)highlights.set(best,'最大拉动');
  if(worst!==-1)highlights.set(worst,'最大降幅');
  if(hiddenDrop!==-1)highlights.set(hiddenDrop,hiddenDrop===worst?'最大降幅 · 单量涨、收入跌':'单量涨、收入跌');
  if(!highlights.size && rows.length)highlights.set(0,'量价变化');
  const signed=v=>(v>0?'+':'')+fmt(v);
  return [...highlights].map(([index,label])=>{
    const r=rows[index], c=r.comparison;
    const movement=r.income_diff>0?'收入多了':r.income_diff<0?'收入少了':'收入变化';
    const orders='订单 '+fmtInt(c.previous_orders)+' → '+fmtInt(c.current_orders)+' 单';
    const ticket='客单 '+fmt(c.previous_ticket)+' → '+fmt(c.current_ticket)+' 元';
    const contributions=r.order_effect==null || r.ticket_effect==null
      ? '零单，暂无法拆分' : '单量 '+signed(r.order_effect)+' 元 · 客单 '+signed(r.ticket_effect)+' 元';
    return '<button class="driver-highlight" type="button" data-driver="'+index+'" aria-controls="ticketPanel">'+
      '<small class="highlight-label">'+label+'</small>'+
      '<span class="highlight-result"><strong>'+esc(r.store_name)+' / '+esc(r.channel)+'</strong>'+
      '<b class="'+(r.income_diff<0?'driver-loss':'driver-gain')+'">'+movement+' '+fmt(Math.abs(r.income_diff))+' 元</b></span>'+
      '<span class="highlight-metrics"><span>'+orders+'</span><span>'+ticket+'</span></span>'+
      '<span class="highlight-contributions">'+contributions+'</span></button>';
  }).join('');
}

let driverRequest = 0;
async function loadDrivers() {
  const request = ++driverRequest;
  const basis = $('#changeBasis').value;
  const box = $('#driverRows');
  box.textContent='正在读取…';
  try {
    const d = basis==='previous' && dash?.date===curDate ? dash :
      await api('api/dashboard?'+new URLSearchParams({date:curDate,basis}));
    if(request!==driverRequest)return;
    renderDining(d);
    const a=d.daily;
    const signed=v=>v==null?'—':(v>0?'+':'')+fmt(v);
    const summary='对比 '+a.previous_date+' · 同范围 '+a.comparable_stores+' 家';
    if(jumpToDrivers){jumpToDrivers=false;$('#channelChanges').scrollIntoView({block:'start'});}
    if(!a.drivers.length){box.textContent=summary+' · '+(a.comparable_stores?'渠道收入持平':'暂无可比数据');return;}
    const net=Number((a.comparable_income-a.previous_income).toFixed(2));
    const formatNet=net>0?'多收 '+fmt(net)+' 元':net<0?'少收 '+fmt(-net)+' 元':'收入持平';
    const desktop=matchMedia('(min-width:901px)').matches;
    box.innerHTML='<div class="driver-headline"><strong>'+formatNet+'</strong><small>'+esc(summary)+'</small></div>'+
      '<div class="driver-highlights">'+driverHighlights(a.drivers)+'</div><div class="driver-workspace">'+
      '<details id="allDriverRows" class="driver-more"'+(desktop?' open':'')+'><summary>全部 '+a.drivers.length+' 项明细</summary>'+
      '<div class="tbl-wrap"><table class="driver-table"><thead><tr><th>门店 / 渠道</th><th>收入变化</th><th>单量贡献</th><th>客单贡献</th></tr></thead><tbody>'+
      a.drivers.map((r,i)=>'<tr><th><button type="button" class="pick-driver" data-driver="'+i+'">'+esc(r.store_name)+' / '+esc(r.channel)+'</button></th><td>'+signed(r.income_diff)+'</td><td>'+signed(r.order_effect)+'</td><td>'+signed(r.ticket_effect)+'</td></tr>').join('')+
      '</tbody></table></div><small>单位为元。单量贡献按对比日客单价计算。</small></details>'+
      '<section class="ticket-panel" id="ticketPanel" aria-labelledby="ticketTitle"><h4 tabindex="-1" id="ticketTitle"></h4><div id="ticketDetail"></div></section></div>';
    const select=index=>{
      const r=a.drivers[index];
      $('#ticketTitle').textContent=r.store_name+' / '+r.channel+' · 客单贡献拆解';
      $('#ticketDetail').innerHTML=ticketPanel(r,a.previous_date,d.date);
      for(const btn of box.querySelectorAll('[data-driver]')) {
        const selected=Number(btn.dataset.driver)===index;
        btn.setAttribute('aria-pressed',String(selected));
        (btn.closest('tr') || btn.closest('.driver-highlight'))?.classList.toggle('is-current',selected);
      }
    };
    const firstIncrease=a.drivers.findIndex(row=>row.income_diff>0);
    select(firstIncrease<0?0:firstIncrease);
    for(const btn of box.querySelectorAll('[data-driver]'))btn.onclick=()=>{
      select(Number(btn.dataset.driver));
      $('#ticketPanel').classList.add('is-picked');
      if(!desktop)$('#ticketTitle').focus();
    };
  } catch(e){if(request===driverRequest)box.textContent=e.message;}
}
$('#channelChanges').ontoggle=()=>{if($('#channelChanges').open)loadDrivers();};
$('#changeBasis').onchange=loadDrivers;

let editingStore;
$('#cards').addEventListener('click',e=>{
  const button=e.target.closest('button[data-note]');
  if(!button)return;
  editingStore=dash.stores.find(s=>s.store_id===Number(button.dataset.note));
  if(!editingStore)return;
  $('#noteHeading').textContent=editingStore.store_name+' · '+curDate;
  $('#dayNote').value=editingStore.note||'';
  $('#closureOption').hidden=me.role!=='super_admin';
  $('#isClosed').checked=editingStore.report_status==='closed';
  $('#noteFeedback').textContent='';
  $('#storeDialog').showModal();
});
$('#cancelNote').onclick=()=>$('#storeDialog').close();
$('#storeForm').onsubmit=async e=>{
  e.preventDefault();
  const button=e.submitter;
  if(button)button.disabled=true;
  try {
    await api('api/report-day',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({date:curDate,store_id:editingStore.store_id,note:$('#dayNote').value,closed:$('#isClosed').checked})});
    $('#storeDialog').close();await loadDash();
  } catch(error){$('#noteFeedback').textContent=error.message;}
  finally{if(button)button.disabled=false;}
};

$('#uploadBtn').onclick=()=>$('#drop').classList.toggle('show');
if(new URLSearchParams(location.search).get('upload')==='1')$('#drop').classList.add('show');
async function importHistory(){
  const box=$('#importRows');
  try {
    const rows=await api('api/import-history?date='+curDate);
    box.textContent=rows.map(r=>r.store_name+' · '+r.filename+' · '+fmt(r.before_income)+' → '+fmt(r.after_income)+' 元 · '+r.created_at).join('\n')||'当日暂无导入记录。';
  }catch(e){box.textContent=e.message;}
}
$('#importHistory').ontoggle=()=>{if($('#importHistory').open)importHistory();};

async function sendReports(mode,files,confirmations){
  const body=new FormData();
  for(const file of files)body.append('files',file);
  if(confirmations)body.append('confirmations',JSON.stringify(confirmations));
  const response=await fetch('/api/upload?mode='+mode,{method:'POST',body});
  const result=await response.json();
  if(!response.ok)throw Error(result.failed?.map(r=>r.file+' · '+r.error).join('；')||result.error||'导入失败');
  return result;
}
let previewRequest=0;
$('#fileInput').onchange=async e=>{
  const field=e.target, files=Array.from(field.files), box=$('#importResult'), key=++previewRequest;
  box.textContent=files.length?'正在预览…':'';
  if(!files.length)return;
  try{
    const preview=await sendReports('preview',files);
    if(key!==previewRequest)return;
    box.innerHTML=preview.files.map(f=>'<p><b>'+esc(f.file)+' · '+esc(f.date)+'</b><br>'+
      f.amounts.map(a=>esc(a.name)+'　'+(a.before==null?'新增':fmt(a.before)+' →')+' '+fmt(a.after)+' 元').join('<br>')+
      f.warnings.map(w=>'<br>'+esc(w)).join('')+'</p>').join('')+
      preview.failed.map(f=>'<p>'+esc(f.file)+' · '+esc(f.error)+'</p>').join('')+
      '<button class="btn brand" id="confirmImport">确认导入 '+preview.files.length+' 个文件</button>';
    $('#confirmImport').onclick=async event=>{
      const button=event.currentTarget;button.disabled=true;field.disabled=true;
      try{
        const r=await sendReports('confirm',preview.files.map(f=>files[f.index]),preview.files.map(f=>f.token));
        box.textContent='已导入 '+r.files.length+' 个文件。'+r.failed.map(f=>f.file+' · '+f.error).join('；');
        field.value='';curDate=r.files[0].date;
        history.replaceState(null,'','/?date='+curDate);
        await load();if($('#importHistory').open)await importHistory();
      }catch(error){box.textContent=error.message+'。请重新选择文件。';field.value='';}
      finally{field.disabled=false;}
    };
  }catch(error){if(key===previewRequest){box.textContent=error.message;field.value='';}}
};
