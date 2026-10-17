'use strict';
// 终端页兼容层：部分手机浏览器（如内核较老的厂商浏览器、微信内置浏览器）缺少新 API。
// 必须在 xterm.js 之前加载。
(() => {
  const define = (proto, name, fn) => {
    if (proto && !proto[name]) Object.defineProperty(proto, name, { value: fn, writable: true, configurable: true });
  };
  function at(index) {
    const n = Math.trunc(index) || 0;
    const i = n < 0 ? this.length + n : n;
    return i < 0 || i >= this.length ? undefined : this[i];
  }
  define(Array.prototype, 'at', at);
  define(String.prototype, 'at', function stringAt(index) { const v = at.call(String(this), index); return v; });
  if (typeof Int8Array !== 'undefined') define(Object.getPrototypeOf(Int8Array.prototype), 'at', at);
  if (!Object.hasOwn) Object.hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

  // 脚本出错时把原因显示在页面上，而不是一直停在“准备连接…”
  window.addEventListener('error', (event) => {
    const status = document.getElementById('term-status');
    if (status) status.textContent = `终端加载失败：${event.message || '脚本错误'}。请换用 Chrome / Edge 等新版浏览器后重试`;
  });
})();
