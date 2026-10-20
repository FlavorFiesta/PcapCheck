/* eslint-disable */
// 冒烟测试启动器:先准备 jsdom 环境 + 开启前端 mock,再加载打包后的应用,逐路由真实渲染。
// 用法:npm run smoke
'use strict';
const { JSDOM } = require('jsdom');

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'http://127.0.0.1:5173/',
  pretendToBeVisual: true,
});

// ---- 全局 DOM 环境 ----
global.window = dom.window;
global.document = dom.window.document;
try {
  Object.defineProperty(global, 'navigator', { value: dom.window.navigator, configurable: true });
} catch {
  /* node 自带 navigator 时保持原样即可 */
}
global.HTMLElement = dom.window.HTMLElement;
global.Element = dom.window.Element;
global.Node = dom.window.Node;
global.localStorage = dom.window.localStorage;
global.sessionStorage = dom.window.sessionStorage;
global.location = dom.window.location;
global.getComputedStyle = dom.window.getComputedStyle;
global.requestAnimationFrame = dom.window.requestAnimationFrame
  ? dom.window.requestAnimationFrame.bind(dom.window)
  : (cb) => setTimeout(() => cb(Date.now()), 0);
global.cancelAnimationFrame = dom.window.cancelAnimationFrame
  ? dom.window.cancelAnimationFrame.bind(dom.window)
  : clearTimeout;

// 开启前端 mock(必须在加载应用代码之前,client/mock 模块求值时读取)
global.localStorage.setItem('pd_mock', '1');

// jsdom 没有布局引擎:给所有元素一个固定视口尺寸,让虚拟列表能算出行
// (virtual-core 的 getRect 读 offsetWidth/offsetHeight)
Object.defineProperty(dom.window.HTMLElement.prototype, 'offsetHeight', {
  get() {
    return 720;
  },
  configurable: true,
});
Object.defineProperty(dom.window.HTMLElement.prototype, 'offsetWidth', {
  get() {
    return 1280;
  },
  configurable: true,
});
dom.window.Element.prototype.getBoundingClientRect = function () {
  return { width: 1280, height: 720, top: 0, left: 0, right: 1280, bottom: 720, x: 0, y: 0, toJSON() {} };
};
Object.defineProperty(dom.window.HTMLElement.prototype, 'clientHeight', {
  get() {
    return 720;
  },
  configurable: true,
});
Object.defineProperty(dom.window.HTMLElement.prototype, 'clientWidth', {
  get() {
    return 1280;
  },
  configurable: true,
});

// 虚拟列表依赖
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// LivePage 会连 WebSocket:jsdom 没有,给个立刻失败的桩
global.WebSocket = class WebSocket {
  constructor() {
    setTimeout(() => {
      if (typeof this.onerror === 'function') this.onerror(new dom.window.Event('error'));
      if (typeof this.onclose === 'function') this.onclose({ code: 1006 });
    }, 0);
  }
  send() {}
  close() {}
};

// ---- 加载并运行应用冒烟 ----
require('./smoke.cjs')
  .run()
  .then((ok) => {
    console.log(ok ? 'SMOKE RESULT: ALL PASS' : 'SMOKE RESULT: FAILED');
    process.exit(ok ? 0 : 1);
  })
  .catch((e) => {
    console.error('SMOKE ERROR:', e);
    process.exit(2);
  });
