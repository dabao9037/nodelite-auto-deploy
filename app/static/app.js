'use strict';
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const base = (document.querySelector('meta[name="base-path"]') || {}).content || '';
  const form = document.getElementById('deploy-form');
  const submit = document.getElementById('submit');
  const formError = document.getElementById('form-error');
  const progress = document.getElementById('progress');
  const pill = document.getElementById('status-pill');
  const statusMessage = document.getElementById('status-message');
  const log = document.getElementById('log');
  const result = document.getElementById('result');
  const pwHint = document.getElementById('pw-hint');
  const redeployNote = document.getElementById('redeploy-note');
  const labels = { queued: '排队中', running: '部署中', success: '已完成', failed: '失败' };
  const stepLabels = { pending: '等待', running: '进行中', done: '完成', failed: '失败', skipped: '已跳过', warn: '有警告' };
  const recordStatus = { success: '成功', warn: '成功（有警告）', failed: '失败', '': '未部署' };
  let taskId = null;
  let since = 0;
  let timer = null;
  let servers = [];
  // 重新部署时使用已保存密码的目标（host/port/user 与此一致时允许密码留空）
  let savedTarget = null;

  const text = (id, value) => { document.getElementById(id).textContent = value; };
  const api = async (path, options = {}) => {
    const headers = Object.assign({ 'x-csrf-token': csrf }, options.headers || {});
    const response = await fetch(`${base}${path}`, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, options, { headers }));
    if (response.status === 401) { location.href = `${base}/login`; throw new Error('请先登录'); }
    let body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) { const error = new Error(body.detail || `请求失败（${response.status}）`); error.body = body; throw error; }
    return body;
  };
  const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '—');
  const hostPort = (r) => `${r.host.includes(':') ? `[${r.host}]` : r.host}:${r.ssh_port}`;

  // ---- 标签页 -----------------------------------------------------------------
  const tabs = [document.getElementById('tab-deploy'), document.getElementById('tab-servers')];
  function selectTab(tab, focus = false) {
    tabs.forEach((t) => {
      const selected = t === tab;
      t.setAttribute('aria-selected', String(selected));
      t.tabIndex = selected ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
    });
    if (focus) tab.focus();
    if (tab.id === 'tab-servers') loadServers();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      selectTab(tabs[(index + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length], true);
    });
  });

  // ---- 部署 -------------------------------------------------------------------
  function setSteps(steps) {
    document.querySelectorAll('#steps li').forEach((li) => {
      const state = steps[li.dataset.step] || 'pending';
      li.className = state;
      li.setAttribute('aria-label', `${li.textContent.replace(/（.*）$/, '')}：${stepLabels[state] || state}`);
      if (state === 'running') li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
    });
  }

  function appendLogs(lines) {
    if (!lines.length) return;
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    log.textContent += lines.join('\n') + '\n';
    if (nearBottom) log.scrollTop = log.scrollHeight;
  }

  function clearPassword() { document.getElementById('ssh_password').value = ''; }

  function finish() {
    clearInterval(timer);
    timer = null;
    submit.disabled = false;
    submit.textContent = '开始部署';
  }

  function currentTarget() {
    return { host: form.host.value.trim().toLowerCase(), port: Number(form.ssh_port.value.trim() || 22), user: form.ssh_user.value.trim() || 'root' };
  }
  function usesSavedPassword() {
    if (!savedTarget) return false;
    const t = currentTarget();
    return t.host === savedTarget.host.toLowerCase() && t.port === savedTarget.port && t.user === savedTarget.user;
  }
  function updatePasswordHint() {
    const saved = usesSavedPassword();
    pwHint.textContent = saved ? '留空则使用该服务器已保存的 SSH 密码' : '';
    document.getElementById('pw-star').hidden = saved;
  }
  ['host', 'ssh_port', 'ssh_user'].forEach((name) => form[name].addEventListener('input', updatePasswordHint));

  function showResult(r) {
    const url = document.getElementById('r-url');
    url.href = r.panel_url; url.textContent = r.panel_url;
    const altShown = Boolean(r.alt_panel_url);
    document.getElementById('r-alt-label').hidden = !altShown;
    document.getElementById('r-alt-row').hidden = !altShown;
    if (altShown) { const alt = document.getElementById('r-alt'); alt.href = r.alt_panel_url; alt.textContent = r.alt_panel_url; }
    text('r-user', r.username);
    text('r-pass', r.password);
    text('r-version', `${r.version}（${r.mode === 'update' ? '已更新，保留原账号密码' : '全新安装'}）`);
    text('r-ipv6', r.ipv6.message);
    const reach = r.reachability;
    const pub = reach.public === true ? '公网访问正常' : reach.public === false ? `公网访问失败：${reach.public_note}` : reach.public_note;
    text('r-reach', `服务器本机：${reach.local ? '正常' : '异常'}；${pub}`);
    text('r-fp', `${r.key_type} ${r.fingerprint}`);
    result.hidden = false;
    result.focus();
  }

  async function poll() {
    if (!taskId) return;
    try {
      const response = await fetch(`${base}/api/tasks/${encodeURIComponent(taskId)}?since=${since}`, { cache: 'no-store', credentials: 'same-origin' });
      if (response.status === 401) { location.href = `${base}/login`; return; }
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || '任务不可用');
      since = body.log_next;
      appendLogs(body.logs);
      setSteps(body.steps);
      pill.className = `pill ${body.status}`;
      pill.textContent = labels[body.status] || body.status;
      statusMessage.textContent = body.error || body.message;
      if (body.status === 'success') { finish(); showResult(body.result); savedTarget = null; updatePasswordHint(); loadServers(); }
      else if (body.status === 'failed') { finish(); loadServers(); }
    } catch (error) {
      finish();
      statusMessage.textContent = error.message;
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    formError.textContent = '';
    const host = form.host.value.trim();
    if (!host) { formError.textContent = '请填写服务器 IP 或域名'; form.host.focus(); return; }
    if (!form.ssh_password.value && !usesSavedPassword()) { formError.textContent = '请填写 SSH 密码'; form.ssh_password.focus(); return; }
    if (!form.authorized.checked) { formError.textContent = '请先勾选授权确认'; form.authorized.focus(); return; }
    const port = form.ssh_port.value.trim();
    if (port && !(Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535)) {
      formError.textContent = 'SSH 端口必须在 1-65535 之间'; form.ssh_port.focus(); return;
    }
    const payload = {
      host,
      ssh_port: port || null,
      ssh_user: form.ssh_user.value.trim() || null,
      ssh_password: form.ssh_password.value || null,
      save_password: form.save_password.checked,
      disable_ipv6: form.disable_ipv6.checked,
      authorized: form.authorized.checked,
    };
    submit.disabled = true;
    submit.textContent = '部署中…';
    result.hidden = true;
    try {
      const response = await fetch(`${base}/api/tasks`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify(payload),
      });
      payload.ssh_password = '';
      clearPassword();
      const body = await response.json();
      if (response.status === 401) { location.href = `${base}/login`; return; }
      if (!response.ok) throw new Error(body.detail || '创建任务失败');
      taskId = body.task_id; since = 0; log.textContent = '';
      progress.hidden = false;
      redeployNote.hidden = true;
      setSteps({});
      statusMessage.textContent = '任务已创建';
      progress.scrollIntoView({ behavior: 'smooth', block: 'start' });
      await poll();
      if (!timer && taskId) timer = setInterval(poll, 1500);
    } catch (error) {
      payload.ssh_password = '';
      finish();
      formError.textContent = error.message;
    }
  });

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('button.copy[data-copy]');
    if (!button) return;
    const value = document.getElementById(button.dataset.copy).textContent;
    try {
      await navigator.clipboard.writeText(value);
      text('copy-status', '已复制到剪贴板');
    } catch (e) {
      text('copy-status', '复制失败，请手动选择文本复制');
    }
  });

  document.getElementById('forget').addEventListener('click', async () => {
    if (!taskId) return;
    await fetch(`${base}/api/tasks/${encodeURIComponent(taskId)}`, { method: 'DELETE', credentials: 'same-origin', headers: { 'x-csrf-token': csrf } });
    ['r-user', 'r-pass', 'r-fp'].forEach((id) => text(id, ''));
    result.hidden = true;
    taskId = null;
    statusMessage.textContent = '结果已从本页和内存清除（服务器记录不受影响）';
  });
  document.getElementById('goto-servers').addEventListener('click', () => selectTab(tabs[1], true));
  document.getElementById('server-search').addEventListener('input', () => renderServers());

  // ---- 服务器记录 ---------------------------------------------------------------
  const list = document.getElementById('servers');
  const listStatus = document.getElementById('servers-status');
  const template = document.getElementById('server-card');
  const searchInput = document.getElementById('server-search');

  // 按 IP 过滤：忽略大小写和首尾空格，匹配主机名/IP 或 "IP:端口" 中的任意片段
  function matchesSearch(r, query) {
    if (!query) return true;
    const host = String(r.host || '').toLowerCase();
    return host.includes(query) || hostPort(r).toLowerCase().includes(query);
  }

  async function loadServers() {
    try {
      const body = await api('/api/servers');
      servers = body.servers;
      renderServers();
    } catch (error) {
      listStatus.textContent = error.message;
    }
  }

  function renderServers() {
    const count = document.getElementById('server-count');
    count.textContent = servers.length ? String(servers.length) : '';
    list.replaceChildren();
    const query = searchInput.value.trim().toLowerCase();
    const shown = servers.filter((r) => matchesSearch(r, query));
    if (!servers.length) listStatus.textContent = '还没有服务器记录。部署成功后会自动保存到这里。';
    else if (!query) listStatus.textContent = '';
    else if (!shown.length) listStatus.textContent = `没有找到 IP 包含「${searchInput.value.trim()}」的服务器。`;
    else listStatus.textContent = `找到 ${shown.length} / ${servers.length} 台服务器。`;
    shown.forEach((r) => {
      const card = template.content.firstElementChild.cloneNode(true);
      const f = (name) => card.querySelector(`[data-f="${name}"]`);
      card.dataset.id = r.id;
      card.setAttribute('aria-label', `服务器 ${hostPort(r)}`);
      f('title').textContent = `${r.ssh_user}@${hostPort(r)}`;
      const status = f('status');
      status.textContent = recordStatus[r.last_status] || r.last_status;
      status.classList.add(r.last_status === 'failed' ? 'failed' : r.last_status ? 'success' : 'queued');
      f('when').textContent = `首次部署 ${fmtTime(r.first_deploy_at)} · 最近部署 ${fmtTime(r.last_deploy_at)}`;
      const url = f('url');
      if (r.panel_url) { url.href = r.panel_url; url.textContent = r.panel_url; } else { url.replaceWith(document.createTextNode('—')); }
      f('puser').textContent = r.panel_user || '—';
      f('version').textContent = r.version || '—';
      f('ipv6').textContent = r.ipv6_status || '—';
      f('fp').textContent = r.fingerprint ? `${r.key_type} ${r.fingerprint}` : '—';
      f('sshpw').textContent = r.has_ssh_password ? '已加密保存（可一键连接）' : '未保存（连接时需输入）';
      if (!r.has_panel_password) card.querySelectorAll('[data-act="reveal"],[data-act="copy-pass"]').forEach((b) => { b.disabled = true; });
      if (!r.has_ssh_password) card.querySelector('[data-act="forget-pw"]').hidden = true;
      if (r.pending_fingerprint) {
        const warn = f('keywarn');
        warn.hidden = false;
        warn.textContent = `⚠ 最近一次连接时服务器出示了不同的 SSH 主机密钥：${r.pending_key_type} ${r.pending_fingerprint}（记录中为 ${r.fingerprint}）。可能是服务器重装了系统，也可能是中间人攻击，已拒绝连接。`;
        const trust = document.createElement('button');
        trust.type = 'button'; trust.className = 'danger'; trust.dataset.act = 'trust-key'; trust.textContent = '信任新密钥';
        warn.append(' ', trust);
      }
      list.append(card);
    });
  }

  async function copyText(value, msg) {
    try { await navigator.clipboard.writeText(value); msg.textContent = '已复制到剪贴板'; } catch (e) { msg.textContent = '复制失败，请手动选择文本复制'; }
  }

  async function revealPassword(id) {
    const body = await api(`/api/servers/${id}/reveal`, { method: 'POST' });
    return body.password;
  }

  list.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-act]');
    if (!button) return;
    const card = button.closest('article.server');
    const id = Number(card.dataset.id);
    const record = servers.find((r) => r.id === id);
    const msg = card.querySelector('[data-f="msg"]');
    const pass = card.querySelector('[data-f="ppass"]');
    msg.textContent = '';
    try {
      switch (button.dataset.act) {
        case 'copy-user':
          await copyText(record.panel_user, msg); break;
        case 'reveal':
          if (button.getAttribute('aria-pressed') === 'true') {
            pass.textContent = '••••••••'; button.textContent = '显示'; button.setAttribute('aria-pressed', 'false');
          } else {
            pass.textContent = await revealPassword(id); button.textContent = '隐藏'; button.setAttribute('aria-pressed', 'true');
          }
          break;
        case 'copy-pass':
          await copyText(await revealPassword(id), msg); break;
        case 'connect':
          window.open(`${base}/terminal/${id}`, '_blank', 'noopener');
          break;
        case 'redeploy':
          form.host.value = record.host;
          form.ssh_port.value = record.ssh_port === 22 ? '' : String(record.ssh_port);
          form.ssh_user.value = record.ssh_user === 'root' ? '' : record.ssh_user;
          clearPassword();
          form.authorized.checked = false;
          savedTarget = record.has_ssh_password ? { host: record.host, port: record.ssh_port, user: record.ssh_user } : null;
          redeployNote.hidden = false;
          redeployNote.textContent = `重新部署 ${record.ssh_user}@${hostPort(record)}：${record.has_ssh_password ? '已保存 SSH 密码，密码框可留空。' : '没有保存的 SSH 密码，请填写。'}会校验已记录的主机密钥。`;
          updatePasswordHint();
          selectTab(tabs[0]);
          form.authorized.focus();
          break;
        case 'history': {
          const box = card.querySelector('[data-f="history"]');
          const open = button.getAttribute('aria-expanded') === 'true';
          if (open) { box.hidden = true; button.setAttribute('aria-expanded', 'false'); button.textContent = '查看历史'; break; }
          const body = await api(`/api/servers/${id}/history`);
          const table = document.createElement('table');
          table.innerHTML = '<caption>部署历史（最近 50 次）</caption><thead><tr><th scope="col">时间</th><th scope="col">结果</th><th scope="col">版本</th><th scope="col">错误</th></tr></thead>';
          const tbody = document.createElement('tbody');
          body.history.forEach((h) => {
            const tr = document.createElement('tr');
            [fmtTime(h.at), recordStatus[h.status] || h.status, h.version || '—', h.error || ''].forEach((v) => {
              const td = document.createElement('td'); td.textContent = v; tr.append(td);
            });
            tbody.append(tr);
          });
          if (!body.history.length) { const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan = 4; td.textContent = '暂无历史'; tr.append(td); tbody.append(tr); }
          table.append(tbody);
          box.replaceChildren(table);
          box.hidden = false;
          button.setAttribute('aria-expanded', 'true'); button.textContent = '收起历史';
          break;
        }
        case 'forget-pw':
          if (!confirm(`删除 ${hostPort(record)} 保存的 SSH 密码？以后连接时需要重新输入。`)) break;
          await api(`/api/servers/${id}/ssh-password`, { method: 'DELETE' });
          await loadServers();
          listStatus.textContent = '已删除保存的 SSH 密码';
          break;
        case 'delete':
          if (!confirm(`删除 ${hostPort(record)} 的整条记录（含面板密码、SSH 密码和历史）？此操作不可恢复，不影响远程服务器本身。`)) break;
          await api(`/api/servers/${id}`, { method: 'DELETE' });
          await loadServers();
          listStatus.textContent = '记录已删除';
          break;
        case 'trust-key':
          if (!confirm(`确认信任新的主机密钥？\n${record.pending_key_type} ${record.pending_fingerprint}\n\n请先在服务商控制台核对该指纹。`)) break;
          await api(`/api/servers/${id}/trust-key`, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fingerprint: record.pending_fingerprint }),
          });
          await loadServers();
          listStatus.textContent = '已更新主机密钥';
          break;
        default:
      }
    } catch (error) {
      msg.textContent = error.message;
    }
  });

  loadServers();
})();
