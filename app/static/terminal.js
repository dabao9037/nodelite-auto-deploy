'use strict';
(() => {
  const meta = (name) => (document.querySelector(`meta[name="${name}"]`) || {}).content || '';
  const csrf = meta('csrf-token');
  const base = meta('base-path');
  const serverId = meta('server-id');
  const nonce = meta('style-nonce');

  // CSP 不允许 unsafe-inline：xterm 动态创建的 <style> 带上本页 nonce，
  // style="..." 属性改走 CSSOM（element.style 不受 CSP 限制）。只在本页生效。
  const createElement = Document.prototype.createElement;
  Document.prototype.createElement = function patchedCreateElement(tag, options) {
    const element = createElement.call(this, tag, options);
    if (String(tag).toLowerCase() === 'style' && nonce) element.setAttribute('nonce', nonce);
    return element;
  };
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function patchedSetAttribute(name, value) {
    if (String(name).toLowerCase() === 'style' && this.style) { this.style.cssText = String(value); return; }
    setAttribute.call(this, name, value);
  };

  const status = document.getElementById('term-status');
  const pwBox = document.getElementById('pw-box');
  const pwForm = document.getElementById('pw-form');
  const pwInput = document.getElementById('term-password');
  const pwError = document.getElementById('pw-error');
  const keyBox = document.getElementById('key-box');
  const disconnectButton = document.getElementById('disconnect');
  const reconnectButton = document.getElementById('reconnect');
  const container = document.getElementById('terminal');

  const term = new window.Terminal({
    cursorBlink: true,
    convertEol: false,
    scrollback: 5000,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
    fontSize: 14,
    theme: { background: '#0f172a', foreground: '#dbe4f3' },
  });
  const fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(container);
  fit.fit();

  let ws = null;
  let pendingKey = null;
  const setStatus = (message) => { status.textContent = message; };
  const send = (obj) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); };

  term.onData((data) => send({ t: 'i', d: data }));
  term.onResize(({ cols, rows }) => send({ t: 'r', c: cols, r: rows }));
  let resizeTimer = null;
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => fit.fit(), 120); });

  function connected(isOpen) {
    disconnectButton.hidden = !isOpen;
    reconnectButton.hidden = isOpen;
  }

  function askPassword(reason) {
    pwBox.hidden = false;
    document.getElementById('pw-reason').textContent = reason;
    pwInput.value = '';
    pwInput.focus();
  }

  async function connect(password, save) {
    pwBox.hidden = true;
    keyBox.hidden = true;
    pwError.textContent = '';
    setStatus('正在申请连接…');
    let body = {};
    try {
      const response = await fetch(`${base}/api/servers/${encodeURIComponent(serverId)}/terminal`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ ssh_password: password || null, save_password: Boolean(save), cols: term.cols, rows: term.rows }),
      });
      if (response.status === 401) { location.href = `${base}/login`; return; }
      body = await response.json();
      if (!response.ok) {
        if (body.need_password) { askPassword(body.detail); setStatus('需要 SSH 密码'); connected(false); return; }
        throw new Error(body.detail || '连接失败');
      }
    } catch (error) {
      setStatus(error.message);
      connected(false);
      return;
    }
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${scheme}://${location.host}${body.ws_path}?ticket=${encodeURIComponent(body.ticket)}`);
    ws.binaryType = 'arraybuffer';
    connected(true);
    ws.onmessage = (event) => {
      if (typeof event.data !== 'string') { term.write(new Uint8Array(event.data)); return; }
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.t === 'status') setStatus(message.m);
      else if (message.t === 'ready') { setStatus(message.saved ? '已连接（SSH 密码已加密保存）' : '已连接'); fit.fit(); send({ t: 'r', c: term.cols, r: term.rows }); term.focus(); }
      else if (message.t === 'closed') setStatus(message.m);
      else if (message.t === 'hostkey') {
        pendingKey = message.actual;
        document.getElementById('key-expected').textContent = message.expected;
        document.getElementById('key-actual').textContent = `${message.key_type} ${message.actual}`;
        keyBox.hidden = false;
        setStatus('主机密钥不一致，已拒绝连接');
      } else if (message.t === 'error') {
        setStatus(message.m);
        if (message.need_password) askPassword(message.m);
      }
    };
    ws.onclose = (event) => {
      connected(false);
      if (event.code === 1008) setStatus('连接被拒绝（登录已过期或连接凭证无效），请刷新页面');
      else if (event.code === 1013) setStatus('终端数量已达上限，请稍后再试');
      else if (!/已结束|断开|拒绝|失败|密码/.test(status.textContent)) setStatus('连接已断开');
      ws = null;
    };
    ws.onerror = () => setStatus('WebSocket 连接出错');
  }

  pwForm.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!pwInput.value) { pwError.textContent = '请输入 SSH 密码'; pwInput.focus(); return; }
    const password = pwInput.value;
    pwInput.value = '';
    connect(password, document.getElementById('term-save').checked);
  });

  disconnectButton.addEventListener('click', () => {
    if (!ws) return;
    send({ t: 'bye' });
    ws.close();
    setStatus('已断开连接');
  });
  reconnectButton.addEventListener('click', () => { term.reset(); connect(null, false); });

  document.getElementById('trust-key').addEventListener('click', async () => {
    if (!pendingKey) return;
    if (!confirm(`确认信任新的主机密钥？\n${pendingKey}`)) return;
    try {
      const response = await fetch(`${base}/api/servers/${encodeURIComponent(serverId)}/trust-key`, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({ fingerprint: pendingKey }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || '操作失败');
      pendingKey = null;
      connect(null, false);
    } catch (error) {
      setStatus(error.message);
    }
  });

  window.addEventListener('beforeunload', () => { if (ws) { send({ t: 'bye' }); ws.close(); } });
  connect(null, false);
})();
