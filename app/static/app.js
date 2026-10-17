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
  const labels = { queued: '排队中', running: '部署中', success: '已完成', failed: '失败' };
  const stepLabels = { pending: '等待', running: '进行中', done: '完成', failed: '失败', skipped: '已跳过', warn: '有警告' };
  let taskId = null;
  let since = 0;
  let timer = null;

  const text = (id, value) => { document.getElementById(id).textContent = value; };

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
      if (body.status === 'success') { finish(); showResult(body.result); }
      else if (body.status === 'failed') { finish(); }
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
    if (!form.ssh_password.value) { formError.textContent = '请填写 SSH 密码'; form.ssh_password.focus(); return; }
    if (!form.authorized.checked) { formError.textContent = '请先勾选授权确认'; form.authorized.focus(); return; }
    const port = form.ssh_port.value.trim();
    if (port && !(Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535)) {
      formError.textContent = 'SSH 端口必须在 1-65535 之间'; form.ssh_port.focus(); return;
    }
    const payload = {
      host,
      ssh_port: port || null,
      ssh_user: form.ssh_user.value.trim() || null,
      ssh_password: form.ssh_password.value,
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
    const button = event.target.closest('button.copy');
    if (!button) return;
    const value = document.getElementById(button.dataset.copy).textContent;
    try {
      await navigator.clipboard.writeText(value);
      text('copy-status', '已复制到剪贴板');
    } catch {
      text('copy-status', '复制失败，请手动选择文本复制');
    }
  });

  document.getElementById('forget').addEventListener('click', async () => {
    if (!taskId) return;
    await fetch(`${base}/api/tasks/${encodeURIComponent(taskId)}`, { method: 'DELETE', credentials: 'same-origin', headers: { 'x-csrf-token': csrf } });
    ['r-user', 'r-pass', 'r-fp'].forEach((id) => text(id, ''));
    result.hidden = true;
    taskId = null;
    statusMessage.textContent = '结果已从内存清除';
  });
})();
