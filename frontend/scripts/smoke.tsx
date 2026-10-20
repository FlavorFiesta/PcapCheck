// 全路由渲染冒烟测试(数据走 src/api/mock.ts 的 mock 路径)。
// 由 scripts/smoke-run.cjs 准备好 jsdom 环境后加载本模块,逐路由 createRoot 真实渲染,
// 断言关键 UI 出现且 root 不为空。任何渲染期异常都会导致对应路由 root 为空而被捕获。
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import ErrorBoundary from '../src/components/ErrorBoundary';
import { TreeNode, isTreeEnvelope, normTreeNode } from '../src/components/ProtocolTree';
import { absTime } from '../src/lib/format';
import { useApp } from '../src/store/appStore';
import { useFrames } from '../src/store/framesStore';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function Thrower() {
  throw new Error('boom-测试渲染异常');
}

/** 验证顶层 ErrorBoundary:渲染期异常必须显示中文错误卡片,绝不允许黑屏 */
async function testBoundary(): Promise<boolean> {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  root.render(
    <ErrorBoundary>
      <Thrower />
    </ErrorBoundary>,
  );
  await sleep(300);
  const html = container.innerHTML;
  const ok = html.includes('界面出现未捕获的渲染异常') && html.includes('boom-测试渲染异常') && html.includes('重试');
  console.log(ok ? '[PASS] ErrorBoundary 兜底(中文错误卡片 + 异常消息 + 重试按钮)' : `[FAIL] ErrorBoundary 未生效: ${html.slice(0, 300)}`);
  return ok;
}

/** 验证协议树新形状({"no":N,"tree":[...]})与时间 UTC 口径 */
async function testTreeShapeAndTime(): Promise<boolean> {
  // 1) 时间语义:epoch 0 必须渲染为 UTC 且带标注
  const t0 = absTime(0);
  const timeOk = t0 === '1970-01-01 00:00:00.000 UTC';
  console.log(timeOk ? `[PASS] 帧绝对时间 UTC 口径: absTime(0) = ${t0}` : `[FAIL] absTime(0) = ${t0}`);

  // 2) 新形状检测与降级
  const envelope = {
    no: 10,
    tree: [
      {
        label: 'Frame 10: 114 bytes on wire',
        children: [
          { label: 'eth', children: [{ label: 'eth.src', value: 'aa:bb:cc:dd:ee:ff' }] },
          { label: 'empty-children', children: [] },
        ],
      },
    ],
  };
  const shapeOk = isTreeEnvelope(envelope) && !isTreeEnvelope([{ _source: { layers: {} } }]);
  console.log(shapeOk ? '[PASS] 协议树形状检测:新 tree 信封识别 / 旧 tshark 信封降级' : '[FAIL] 协议树形状检测失败');

  // 3) 新形状节点归一 + 真实渲染(层级、label 全文、value)
  const rootNode = normTreeNode((envelope as { tree: unknown[] }).tree[0]);
  let renderOk = false;
  if (rootNode) {
    const container = document.createElement('div');
    document.body.appendChild(container);
    const r = createRoot(container);
    r.render(<TreeNode node={rootNode} depth={0} />);
    await sleep(200);
    const html = container.innerHTML;
    renderOk =
      html.includes('Frame 10: 114 bytes on wire') &&
      html.includes('eth.src') &&
      html.includes('aa:bb:cc:dd:ee:ff') &&
      html.includes('ptree-children');
    console.log(
      renderOk
        ? '[PASS] 协议树新形状渲染:label 全文 + value + 层级缩进线(ptree-children)'
        : `[FAIL] 协议树新形状渲染异常: ${html.slice(0, 300)}`,
    );
  } else {
    console.log('[FAIL] normTreeNode 返回空');
  }
  return timeOk && shapeOk && renderOk;
}

interface Case {
  name: string;
  path: string;
  expect: string[];
}

const CASES: Case[] = [
  {
    name: '浏览页(报文列表)',
    path: '/browse?capture=mock-0001',
    expect: ['192.168.1.100', '协议树', '帧信息', '重传'],
  },
  {
    name: '诊断报告页(三档卡片)',
    path: '/report?report=mock-rpt-001',
    expect: ['简报', '更多详情请导出报告查看', '确诊故障', '疑似问题', '潜在风险', 'R01_RETRANS_STORM', '处置建议', '未配置 LLM'],
  },
  {
    name: '历史页',
    path: '/history',
    expect: ['mock-office.pcapng', '查看'],
  },
  {
    name: '实时抓包页',
    path: '/live',
    expect: ['自动滚底', '开始', 'Loopback'],
  },
  {
    name: '知识库页',
    path: '/kb',
    expect: ['TCP 重传与重传风暴'],
  },
  {
    name: '设置页',
    path: '/settings',
    expect: ['tshark 路径', '保存设置'],
  },
];

export async function run(): Promise<boolean> {
  // 预灌数据:等价于"后端正常返回 JSON 之后"的全局状态
  await useApp.getState().loadCaptures();
  useApp.getState().setCurrent('mock-0001');
  await sleep(300); // 等 refreshMeta(mock 120ms)完成
  useFrames.getState().open('mock-0001', '');
  await sleep(400); // 等第一页 2000 帧加载完成

  let ok = true;
  for (const c of CASES) {
    const container = document.createElement('div');
    document.body.appendChild(container);
    try {
      const root = createRoot(container);
      root.render(
        <MemoryRouter initialEntries={[c.path]}>
          <App />
        </MemoryRouter>,
      );
      for (let i = 0; i < 8; i++) await sleep(150); // 等 effects + mock 响应 + 重渲染全部落定
      const html = container.innerHTML;
      if (html.length === 0) {
        console.log(`[FAIL] ${c.name}(${c.path}) root 为空 —— 渲染期异常导致整树卸载`);
        ok = false;
      } else {
        const missing = c.expect.filter((e) => !html.includes(e));
        if (missing.length > 0) {
          console.log(`[FAIL] ${c.name}(${c.path}) 渲染了但缺少内容: ${missing.join(' | ')}`);
          ok = false;
        } else {
          console.log(`[PASS] ${c.name}(${c.path}) innerHTML=${html.length}`);
        }
      }
      } catch (e) {
      console.log(`[FAIL] ${c.name}(${c.path}) 异常:`, e);
      ok = false;
    }
  }
  const boundaryOk = await testBoundary();
  const treeTimeOk = await testTreeShapeAndTime();
  return ok && boundaryOk && treeTimeOk;
}
