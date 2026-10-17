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

  if (typeof window.Terminal !== 'function' || !window.FitAddon) {
    status.textContent = '终端组件没有加载成功（网络中断或浏览器版本过旧），请刷新页面，或换用 Chrome / Edge 新版浏览器';
    return;
  }
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

  // ---- 连接状态 ------------------------------------------------------------------
  // 断线（切后台、锁屏、换网络、NAT 超时）不会结束服务器上的 SSH 会话：它在后台保留一段时间，
  // 本页带上续接令牌重连后回到同一个 shell，并补上断线期间的输出。
  const stateBadge = document.getElementById('term-state');
  const tokenKey = `nlad-term-resume:${serverId}`;
  const HEARTBEAT_MS = 20000;
  const DEAD_MS = 45000;
  const MAX_DELAY_MS = 15000;
  let ws = null;
  let pendingKey = null;
  let received = 0; // 本会话已收到的输出字节数（续接时服务器从这里补发）
  let stopped = false; // 主动断开 / 认证失败 / 主机密钥不一致等：不自动重连
  let live = false; // 已收到 ready
  let connecting = false;
  let retryDelay = 1000;
  let retryTimer = null;
  let lastMessageAt = 0;
  let expiredNotice = false;
  let resuming = false; // 当前这条 WebSocket 是续接尝试

  const loadToken = () => { try { return window.sessionStorage.getItem(tokenKey) || ''; } catch (e) { return ''; } };
  const saveToken = (value) => { try { window.sessionStorage.setItem(tokenKey, value); } catch (e) { /* 隐私模式 */ } };
  const clearToken = () => { try { window.sessionStorage.removeItem(tokenKey); } catch (e) { /* 隐私模式 */ } };

  const setStatus = (message) => { status.textContent = message; };
  function setState(kind) {
    const labels = { ok: '已连接', retry: '重连中', off: '已断开', wait: '连接中' };
    stateBadge.textContent = labels[kind] || '';
    stateBadge.className = `term-state ${kind}`;
  }
  const send = (obj) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); };

  term.onData((data) => send({ t: 'i', d: data }));
  term.onResize((size) => send({ t: 'r', c: size.cols, r: size.rows }));
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

  // 丢弃当前 WebSocket（不触发它的 onclose 逻辑）
  function dropSocket() {
    if (!ws) return;
    const old = ws;
    ws = null;
    old.onopen = null; old.onmessage = null; old.onclose = null; old.onerror = null;
    try { old.close(); } catch (e) { /* 已关闭 */ }
  }

  // 不再自动重连：显示原因，留下“重新连接”按钮
  function stop(message, keepToken) {
    stopped = true;
    live = false;
    clearTimeout(retryTimer);
    if (!keepToken) clearToken();
    dropSocket();
    if (message) setStatus(message);
    setState('off');
    connected(false);
  }

  // 意外断线：有续接令牌就按 1s、2s、4s… 最长 15s 退避重连（令牌有效期内不限次数）
  function scheduleReconnect(immediate) {
    if (stopped) return;
    dropSocket();
    live = false;
    if (!loadToken()) { setStatus('连接已断开'); setState('off'); connected(false); return; }
    setStatus('连接中断，正在重连…');
    setState('retry');
    connected(true);
    clearTimeout(retryTimer);
    const delay = immediate ? 0 : retryDelay;
    retryDelay = Math.min(retryDelay * 2, MAX_DELAY_MS);
    retryTimer = setTimeout(() => { connect(null, false); }, delay);
  }

  function reconnectNow() {
    if (stopped || connecting) return;
    retryDelay = 1000;
    scheduleReconnect(true);
  }

  // 心跳：每 20 秒互发 ping；45 秒什么都没收到就认为连接已死，立即重连
  setInterval(() => {
    if (!ws || !(live || resuming)) return;
    if (Date.now() - lastMessageAt > DEAD_MS) { scheduleReconnect(true); return; }
    send({ t: 'ping' });
  }, HEARTBEAT_MS);

  // 从后台切回 / 网络恢复：连着的就探测一下（5 秒没回应就重连），断着的就马上重连
  function probe() {
    if (stopped) return;
    if (!ws || !live) { reconnectNow(); return; }
    const sentAt = Date.now();
    send({ t: 'ping' });
    setTimeout(() => { if (ws && live && lastMessageAt < sentAt) reconnectNow(); }, 5000);
  }
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') probe(); });
  window.addEventListener('online', probe);
  window.addEventListener('pageshow', (event) => { if (event.persisted) probe(); });

  async function connect(password, save) {
    if (connecting) return;
    connecting = true;
    clearTimeout(retryTimer);
    pwBox.hidden = true;
    keyBox.hidden = true;
    pwError.textContent = '';
    const resume = password ? '' : loadToken();
    if (!resume) setStatus('正在申请连接…');
    if (!live && !resume) setState('wait');
    let body = {};
    let response = null;
    try {
      response = await fetch(`${base}/api/servers/${encodeURIComponent(serverId)}/terminal`, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify({
          ssh_password: password || null, save_password: Boolean(save), cols: term.cols, rows: term.rows,
          resume: resume || null,
        }),
      });
      try { body = await response.json(); } catch (e) { body = {}; }
    } catch (error) {
      // 网络还没恢复：续接中就继续退避重试
      connecting = false;
      if (resume && !stopped) { scheduleReconnect(false); return; }
      stop('网络错误，连接失败', true);
      return;
    }
    connecting = false;
    if (response.status === 401) { clearToken(); location.href = `${base}/login`; return; }
    if (response.status === 410 && resume) {
      // 后台会话已过期：用保存的密码重新登录一个新会话
      clearToken();
      expiredNotice = true;
      connect(null, false);
      return;
    }
    if (!response.ok) {
      if (body.need_password) { stop('需要 SSH 密码', false); askPassword(body.detail); return; }
      if (resume && response.status >= 500) { scheduleReconnect(false); return; }
      stop(body.detail || '连接失败', Boolean(resume));
      return;
    }
    if (stopped && resume) return;
    openSocket(body, resume);
  }

  function openSocket(body, resume) {
    dropSocket();
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${location.host}${body.ws_path}`);
    ws = socket;
    resuming = Boolean(resume);
    socket.binaryType = 'arraybuffer';
    lastMessageAt = Date.now();
    // 一次性票据作为第一条消息发送（不放在 URL 里，避免进入访问日志）；offset = 已收到多少输出
    socket.onopen = () => socket.send(JSON.stringify({ t: 'auth', ticket: body.ticket, offset: resume ? received : 0 }));
    connected(true);
    socket.onmessage = (event) => {
      lastMessageAt = Date.now();
      if (typeof event.data !== 'string') {
        const bytes = new Uint8Array(event.data);
        received += bytes.length;
        term.write(bytes);
        return;
      }
      let message;
      try { message = JSON.parse(event.data); } catch (e) { return; }
      handleControl(message);
    };
    socket.onclose = (event) => {
      if (ws !== socket) return;
      ws = null;
      const wasLive = live;
      live = false;
      if (stopped) return;
      if (event.code === 1008) { stop('连接被拒绝（登录已过期或连接凭证无效），请刷新页面', false); return; }
      if (event.code === 1013) { stop('终端数量已达上限，请稍后再试', false); return; }
      if (event.code === 4001) { stop(status.textContent, true); return; }
      if (wasLive || resume) { scheduleReconnect(false); return; }
      stop(/已结束|断开|拒绝|失败|密码/.test(status.textContent) ? status.textContent : '连接已断开', false);
    };
  }

  function handleControl(message) {
    if (message.t === 'ping') { send({ t: 'pong' }); return; }
    if (message.t === 'pong') return;
    if (message.t === 'status') { setStatus(message.m); return; }
    if (message.t === 'ready') {
      live = true;
      retryDelay = 1000;
      if (message.token) saveToken(message.token);
      if (!message.resumed) {
        received = 0;
        if (expiredNotice) term.write('\r\n[会话已过期，已重新登录]\r\n');
      }
      expiredNotice = false;
      setStatus(message.resumed ? '已重新连接（同一个会话）' : (message.saved ? '已连接（SSH 密码已加密保存）' : '已连接'));
      setState('ok');
      fit.fit();
      send({ t: 'r', c: term.cols, r: term.rows });
      term.focus();
      return;
    }
    if (message.t === 'expired') { clearToken(); expiredNotice = true; dropSocket(); connect(null, false); return; }
    if (message.t === 'kicked') { stop(message.m, true); return; }
    if (message.t === 'closed') { stop(message.m, false); return; }
    if (message.t === 'hostkey') {
      pendingKey = message.actual;
      document.getElementById('key-expected').textContent = message.expected;
      document.getElementById('key-actual').textContent = `${message.key_type} ${message.actual}`;
      keyBox.hidden = false;
      stop('主机密钥不一致，已拒绝连接', false);
      return;
    }
    if (message.t === 'error') {
      stop(message.m, false);
      if (message.need_password) askPassword(message.m);
    }
  }

  pwForm.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!pwInput.value) { pwError.textContent = '请输入 SSH 密码'; pwInput.focus(); return; }
    const password = pwInput.value;
    pwInput.value = '';
    stopped = false;
    connect(password, document.getElementById('term-save').checked);
  });

  disconnectButton.addEventListener('click', () => {
    send({ t: 'bye' }); // 主动断开：服务器上的 SSH 会话立即真正关闭
    stop('已断开连接', false);
  });
  reconnectButton.addEventListener('click', () => {
    stopped = false;
    retryDelay = 1000;
    if (!loadToken()) { term.reset(); received = 0; }
    connect(null, false);
  });

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
      stopped = false;
      connect(null, false);
    } catch (error) {
      setStatus(error.message);
    }
  });

  // 关闭 / 刷新页面：告诉服务器只保留很短时间（刷新后能续接，真关掉页面很快就会关闭 SSH 会话）
  window.addEventListener('beforeunload', () => { send({ t: 'unload' }); });
  connect(null, false);
})();
