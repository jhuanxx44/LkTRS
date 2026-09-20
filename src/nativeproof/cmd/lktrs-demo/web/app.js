'use strict';
const $ = id => document.getElementById(id);
let state, selected = 0, auto = false, inFlight = false, lastJSON = '', connectionError = '', actionError = '';
let requestGeneration = 0;
const seconds = ms => ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
const text = (id, value) => { $(id).textContent = value; };
function node(tag, className, content) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (content !== undefined) el.textContent = content;
  return el;
}
function notice(message) {
  text('error', message); $('error').hidden = !message;
}
function render(s) {
  const reports = s.reports || [], checks = s.checks || [], complete = s.next === s.steps.length;
  const step = s.steps[Math.min(s.next, s.steps.length - 1)];
  $('controls').classList.toggle('busy', s.busy);
  $('controls').setAttribute('aria-busy', String(s.busy));
  $('stage-index').replaceChildren(document.createTextNode(String(Math.min(s.next + 1, 8)).padStart(2, '0')), node('span', '', '/ 08'));
  text('stage-label', complete ? '完整流程已完成' : s.busy ? '真实后端正在执行' : '下一步');
  text('stage-title', complete ? '证据已准备好，欢迎独立复核。' : step.title);
  text('stage-description', complete ? '六份真实证明；公开导出含独立验签脚本和拒绝用例。授权材料自创建起 24 小时有效。' : step.detail);
  text('next', complete ? '全部完成' : s.busy ? '执行中…' : `${s.next === 0 ? '建立协作组' : '运行下一步'} →`);
  $('next').disabled = inFlight || s.busy || complete || !!s.error || auto || !!connectionError;
  $('auto').disabled = complete || !!s.error || !!connectionError;
  text('auto', complete ? '连续运行已完成' : auto ? '在本步骤后暂停' : '连续运行全部步骤');
  $('reset').disabled = inFlight || s.busy || (!s.run && !s.error) || !!connectionError;
  $('download').disabled = !s.export;
  $('progress').style.width = `${s.next / s.steps.length * 100}%`;
  text('session-label', s.issue ? `本期 ${s.issue.slice(0, 10)} · 配额 k = 3` : '尚未建立本期协作组');
  text('epoch', s.epoch ? `成员版本 ${s.epoch} / ${s.revoked ? 2 : 4} 个活跃账号` : '尚未初始化');
  text('member-count', s.epoch ? `${s.revoked ? 2 : 3} 人` : '—');
  text('alice-count', `${s.alice_used} / 3`); text('bob-count', `${s.bob_used} / 3`);
  text('alice-status', s.revoked ? '已撤销' : s.epoch ? '已注册' : '待注册');
  text('bob-status', s.epoch ? '已注册' : '待注册'); text('carol-status', s.epoch ? '已注册' : '待注册');
  $('alice').classList.toggle('revoked', s.revoked);
  [...$('alice-slots').children].forEach((el, i) => el.classList.toggle('used', i < s.alice_used));
  $('alice-slots').setAttribute('aria-label', `Alice 已用 ${s.alice_used} 个额度`);
  text('report-count', `${reports.length} 份`); text('check-count', checks.length ? `${checks.length} 条` : '等待运行');
  if (reports.length) {
    const previousLength = (state?.reports || []).length;
    if (reports.length > previousLength || !reports.some(r => r.id === selected)) selected = reports[reports.length - 1].id;
    const children = reports.map(r => {
      const payload = JSON.parse(r.message), rejected = r.decision === 'rejected_reuse';
      const el = node('button', `report${r.id === selected ? ' selected' : ''}`);
      el.dataset.report = r.id; el.setAttribute('aria-pressed', String(r.id === selected));
      el.setAttribute('aria-label', `报告 ${String(r.id).padStart(2, '0')}，${rejected ? '违规重用，追责到 Alice' : '验签通过'}，查看公开字段`);
      const top = node('div', 'report-top'); top.append(node('span', '', `REPORT ${String(r.id).padStart(2, '0')}`), node('span', `badge${rejected ? ' warn' : ''}`, rejected ? '重用拒收 · Alice' : r.decision === 'pending_trace' ? '证明有效 · 待追责' : '验签通过'));
      const reading = node('div', 'report-reading'), temp = node('span', 'temperature', payload.water_temperature_c.toFixed(1));
      temp.append(node('small', '', '°C')); reading.append(temp, node('small', '', `模拟水温 / 成员 v${r.epoch}`));
      const bottom = node('div', 'report-bottom'); bottom.append(node('span', `nym-tag${r.nym !== reports[0].nym ? ' other' : ''}`, `nym ${r.nym.slice(0, 12)}…`), node('span', '', `证明 ${seconds(r.prove_ms)}`));
      el.append(top, reading, bottom); el.addEventListener('click', () => { selected = r.id; selectReport(); }); return el;
    });
    const focused = document.activeElement?.dataset?.report;
    $('reports').replaceChildren(...children);
    if (focused) $('reports').querySelector(`[data-report="${Number(focused)}"]`)?.focus({preventScroll:true});
    if (reports.length > previousLength) $('reports').scrollTop = $('reports').scrollHeight;
  } else {
    const empty = node('div', 'empty'), waves = node('div', 'empty-waves', '≈');
    waves.setAttribute('aria-hidden', 'true');
    empty.append(waves, node('h3', '', '第一份报告，从这里开始'), node('p', '', '建立协作组后，提交一份报告。这里会显示真实验签结果和本期化名。'));
    $('reports').replaceChildren(empty);
    selected = 0;
  }
  if (checks.length) {
    $('checks').replaceChildren(...[...checks].reverse().map(c => {
      const el = node('li', ['rejected', 'traced'].includes(c.result) ? 'warning' : '');
      el.append(node('h3', '', c.label), node('p', '', c.detail), node('span', 'check-meta', `${c.result.toUpperCase()} · ${seconds(c.ms)}`)); return el;
    }));
  } else $('checks').replaceChildren(node('li', 'waiting-check', '完成一个步骤后，验证结果会出现在这里。'));
  state = s;
  selectReport();
  notice(s.error ? `本次运行中止：${s.error}。可重新开始；已经生成的本地材料会保留。` : connectionError || actionError);
  updateStatus();
}
function selectReport() {
  const r = state?.reports?.find(r => r.id === selected);
  $('inspector-content').hidden = !r; $('inspector-empty').hidden = !!r;
  text('inspector-title', r ? `报告 ${String(r.id).padStart(2, '0')} · 公开字段` : '选择一份报告');
  text('inspector-status', r ? r.decision === 'rejected_reuse' ? '证明有效 / 业务拒收 / 追责到 Alice' : r.decision === 'pending_trace' ? '证明有效 / 等待追责检查' : '证明有效 / 本演示业务接收' : '');
  if (!r) return;
  text('prove-time', seconds(r.prove_ms)); text('verify-time', seconds(r.verify_ms)); text('proof-size', `${r.proof_bytes} B`); text('report-epoch', `v${r.epoch}`);
  text('message', JSON.stringify(JSON.parse(r.message), null, 2)); text('nym', r.nym); text('serial', r.serial);
  for (const el of $('reports').children) { const active = Number(el.dataset.report) === selected; el.classList.toggle('selected', active); el.setAttribute('aria-pressed', String(active)); }
}
function updateStatus() {
  if (!state) return;
  text('run-status', state.busy ? `${state.phase} · 已运行 ${Math.max(0, Math.floor((Date.now() - state.started) / 1000))} 秒。可在此等待，无需刷新。` : `${state.phase}${state.next ? ` · 已完成 ${state.next} / 8 步` : ' · 首次 setup 需要数分钟和数 GB 内存'}`);
}
async function action(path, body) {
  if (inFlight || !state) return;
  inFlight = true;
  requestGeneration++; // Invalidate any GET started before this mutation.
  actionError = '';
  render(state);
  try {
    const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json', 'X-Demo-Token':state.token}, body:JSON.stringify(body)});
    if (!response.ok) throw new Error(await response.text());
    lastJSON = ''; await poll();
  } catch (error) { auto = false; actionError = `请求失败：${error.message}。状态将自动刷新，确认后可重试。`; }
  finally { inFlight = false; render(state); }
}
async function poll() {
  const generation = ++requestGeneration;
  try {
    const response = await fetch('/api/state', {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const s = await response.json();
    if (generation !== requestGeneration) return; // Discard superseded responses.
    const raw = JSON.stringify(s), recovered = !!connectionError;
    connectionError = '';
    if (s.error || s.next === s.steps.length) auto = false;
    if (raw !== lastJSON || recovered) { render(s); lastJSON = raw; }
    if (auto && !s.busy && !s.error && s.next < s.steps.length && !inFlight) await action('/api/advance', {step:s.next});
  } catch (error) {
    if (generation !== requestGeneration) return;
    auto = false; connectionError = `无法连接本地服务：${error.message}。请确认启动终端仍在运行；连接恢复后此页会自动更新。`;
    if (state) render(state); else notice(connectionError);
  }
}
$('next').addEventListener('click', () => action('/api/advance', {step:state.next}));
$('auto').addEventListener('click', () => { auto = !auto; render(state); if (auto && !state.busy) action('/api/advance', {step:state.next}); });
$('reset').addEventListener('click', () => {
  if (state.run && !window.confirm('重新开始会结束本期协作并丢弃内存中的密钥，当前会话无法恢复。已生成的本地材料会保留。继续？')) return;
  auto = false; selected = 0; action('/api/reset', {});
});
$('download').addEventListener('click', () => { window.location.href = '/api/export'; });
async function tick() { await poll(); updateStatus(); setTimeout(tick, 1000); }
tick();
