// 开发期 mock(极少量,默认关闭)。
// 开启方式:浏览器控制台 localStorage.setItem('pd_mock','1') 后刷新;
// 或在 frontend/.env.local 写 VITE_MOCK=1。
// 所有数据由少量模板程序化生成,仅覆盖主要接口形态,用于后端未就绪时联调 UI。
import type {
  AppSettings,
  CaptureMeta,
  Conversation,
  ExpertItem,
  FollowResp,
  FrameRow,
  IoPoint,
  KbArticle,
  LiveInterface,
  PhsNode,
  Report,
} from './types';

export const mockEnabled = (() => {
  try {
    if (import.meta.env?.VITE_MOCK === '1') return true;
    return localStorage.getItem('pd_mock') === '1';
  } catch {
    return false;
  }
})();

const CAPTURE_ID = 'mock-0001';

function mockCapture(): CaptureMeta {
  return {
    id: CAPTURE_ID,
    name: 'mock-office.pcapng',
    path: 'D:/mock/mock-office.pcapng',
    size: 18_632_000,
    frame_count: MOCK_FRAMES.length,
    first_ts: MOCK_FRAMES[0]?.ts,
    last_ts: MOCK_FRAMES[MOCK_FRAMES.length - 1]?.ts,
    created_at: Date.now() / 1000 - 3600,
    status: 'ready',
    error: null,
  };
}

function genFrames(n: number): FrameRow[] {
  const rows: FrameRow[] = [];
  const t0 = Date.now() / 1000 - 180;
  for (let i = 1; i <= n; i++) {
    const m = i % 200;
    let src = '192.168.1.100';
    let dst = '203.0.113.10';
    let sport: number | null = 51000 + (i % 40);
    let dport: number | null = 443;
    let proto = 'TCP';
    let stream: number | null = i % 40;
    let info = `${sport} → ${dport} [ACK] Seq=${i} Ack=${i} Win=64240 Len=0`;
    const analysis: string[] = [];

    if (i % 23 === 0) {
      proto = 'TLSv1.2';
      info = 'Application Data';
    }
    if (m === 5) {
      analysis.push('retransmission');
      info = 'TCP Retransmission 1436 → 443 Seq=1001 Win=64240 Len=1396';
    }
    if (m === 9) {
      analysis.push('out_of_order');
      info = 'TCP Out-Of-Order 1436 → 443 Seq=2001 Win=64240 Len=1396';
    }
    if (m === 13) {
      analysis.push('zero_window');
      info = `443 → ${sport} [TCP ZeroWindow]`;
    }
    if (m === 17) {
      analysis.push('rst');
      info = `${sport} → ${dport} [RST] Seq=1 Win=0 Len=0`;
    }
    if (m === 21) {
      proto = 'DNS';
      src = '192.168.1.100';
      dst = '192.168.1.1';
      sport = 53000 + (i % 10);
      dport = 53;
      stream = null;
      info = 'Standard query 0x1a2b A www.example.com';
      if (i % 42 === 21) {
        analysis.push('dns_fail');
        info = 'Standard query response 0x1a2b A www.example.com SERVFAIL';
      }
    }
    if (m === 29) {
      proto = 'HTTP';
      dport = 80;
      info = 'GET /api/index HTTP/1.1';
      if (i % 58 === 29) {
        analysis.push('http_5xx');
        info = 'HTTP/1.1 500 Internal Server Error';
      }
    }
    if (m === 33) {
      proto = 'TLSv1.2';
      info = 'Alert (Level: Fatal, Description: Certificate Expired)';
      analysis.push('tls_alert');
    }
    if (m === 41) {
      proto = 'ARP';
      src = '192.168.1.100';
      dst = 'Broadcast';
      sport = null;
      dport = null;
      stream = null;
      info = 'Who has 192.168.1.1? Tell 192.168.1.100';
    }

    const expert: ExpertItem[] | null =
      analysis.length > 0 ? [{ severity: 'Error', group: 'Sequence', message: `检测到:${analysis.join(',')}` }] : null;

    rows.push({
      no: i,
      ts: t0 + i * 0.013,
      src,
      dst,
      sport,
      dport,
      proto,
      length: 54 + ((i * 37) % 1400),
      info,
      stream,
      analysis,
      expert,
    });
  }
  return rows;
}

const MOCK_FRAMES: FrameRow[] = genFrames(2400);

function matchSingle(f: FrameRow, c: string): boolean {
  const m = c.match(/^(\w+)\s*==\s*(.+)$/);
  if (!m) return true;
  const key = m[1];
  const val = m[2].replace(/^"|"$/g, '');
  const a = Array.isArray(f.analysis) ? f.analysis : [];
  switch (key) {
    case 'ip':
      return f.src === val || f.dst === val;
    case 'port':
      return f.sport === Number(val) || f.dport === Number(val);
    case 'proto':
      return f.proto.toLowerCase() === val.toLowerCase();
    case 'stream':
      return f.stream === Number(val);
    case 'analysis':
      return a.some((x) => x === val);
    case 'flag':
      return val === 'rst' && a.includes('rst');
    case 'dns':
      return val === 'fail' && a.includes('dns_fail');
    case 'tls':
      return val === 'alert' && a.includes('tls_alert');
    case 'http':
      return val === '5xx' && a.includes('http_5xx');
    case 'contains':
      return f.info.includes(val);
    default:
      return true;
  }
}

function matchMock(f: FrameRow, expr: string): boolean {
  const e = expr.trim();
  if (!e) return true;
  const conds = e.split('&&').map((s) => s.trim()).filter(Boolean);
  return conds.every((c) => (c.startsWith('!') ? !matchSingle(f, c.slice(1).trim()) : matchSingle(f, c)));
}

function mockReport(): Report {
  return {
    id: 'mock-rpt-001',
    capture_id: CAPTURE_ID,
    created_at: Date.now() / 1000 - 1200,
    engine: 'rules-v1',
    findings: [
      {
        rule_id: 'R01_RETRANS_STORM',
        tier: 'confirmed',
        title: 'TCP 重传风暴',
        evidence_frames: [5, 205, 405, 605, 805],
        stats: { 重传帧数: 12, 涉及流数: 3, 重传比例: '0.5%' },
        suggestion: '检查链路质量与对端主机网卡丢包,优先排查 Wi-Fi 漫游与交换机端口错包。',
        kb_ids: ['kb-tcp-retransmission'],
      },
      {
        rule_id: 'R04_DNS_FAIL',
        tier: 'confirmed',
        title: 'DNS 解析失败(SERVFAIL/NXDOMAIN)',
        evidence_frames: [63, 105, 147],
        stats: { 失败响应数: 3, 失败率: '25%' },
        suggestion: '核查内网 DNS 服务器上游转发配置与域名是否存在。',
        kb_ids: ['kb-dns-failure'],
      },
      {
        rule_id: 'R11_OOO_HIGH',
        tier: 'suspect',
        title: '乱序比例异常',
        evidence_frames: [9, 209, 409],
        stats: { 乱序帧数: 12, 乱序比例: '0.5%' },
        suggestion: '多路径负载均衡或无线重传可能导致,检查等价路由与 AP 漫游。',
        kb_ids: [],
      },
      {
        rule_id: 'R15_BW_TREND',
        tier: 'potential',
        title: '带宽趋于饱和',
        evidence_frames: [1200, 1500, 1800],
        stats: { 峰值Mbps: 88.4 },
        suggestion: '关注出口链路利用率趋势,必要时做限速或扩容。',
        kb_ids: [],
      },
    ],
    summary: '检出 2 项确诊故障、1 项疑似问题、1 项潜在风险。主要问题为 TCP 重传风暴与 DNS 解析失败。',
    narrative: null,
    masked: 0,
  };
}

const KB_LIST: KbArticle[] = [
  {
    id: 'kb-tcp-retransmission',
    title: 'TCP 重传与重传风暴',
    rule_ids: ['R01_RETRANS_STORM'],
    protocols: ['TCP'],
    symptoms: '应用卡顿、传输慢、连接超时',
    severity: 'high',
    content:
      '# TCP 重传与重传风暴\n\n## 机理\n\nTCP 依靠 ACK 确认,超时未确认即重传……\n\n## 判断标准\n\n- 重传比例 > 1% 需关注\n- 同一流连续多次重传视为风暴\n\n## 处置建议\n\n1. 检查物理链路\n2. 检查对端主机负载\n',
  },
  {
    id: 'kb-dns-failure',
    title: 'DNS 解析失败(SERVFAIL / NXDOMAIN)',
    rule_ids: ['R04_DNS_FAIL'],
    protocols: ['DNS'],
    symptoms: '打开网页慢、域名无法解析',
    severity: 'high',
    content:
      '# DNS 解析失败\n\n## 机理\n\nSERVFAIL 表示递归服务器解析失败;NXDOMAIN 表示域名不存在……\n\n## 排查步骤\n\n1. 确认 DNS 服务器地址\n2. 抓包看查询与响应的 rcode\n',
  },
];

const PHS: PhsNode[] = [
  {
    label: 'eth',
    frames: MOCK_FRAMES.length,
    bytes: MOCK_FRAMES.reduce((s, f) => s + f.length, 0),
    percent_frames: 100,
    percent_bytes: 100,
    children: [
      { label: 'ip', frames: 2280, bytes: 2_900_000, percent_frames: 95, percent_bytes: 96 },
      { label: 'arp', frames: 120, bytes: 9_600, percent_frames: 5, percent_bytes: 4 },
    ],
  },
];

const IO: IoPoint[] = Array.from({ length: 120 }, (_, i) => ({
  t: Date.now() / 1000 - 120 + i,
  frames: 15 + Math.round(10 * Math.sin(i / 7) + (i % 11)),
  bytes: 9000 + Math.round(6000 * Math.abs(Math.sin(i / 9))),
}));

const CONVS: Conversation[] = [
  { src: '192.168.1.100', sport: 51000, dst: '203.0.113.10', dport: 443, frames: 900, bytes: 1_200_000, frames_ab: 500, bytes_ab: 800_000, frames_ba: 400, bytes_ba: 400_000 },
  { src: '192.168.1.100', sport: 51001, dst: '203.0.113.11', dport: 443, frames: 420, bytes: 560_000, frames_ab: 220, bytes_ab: 300_000, frames_ba: 200, bytes_ba: 260_000 },
  { src: '192.168.1.100', sport: 53000, dst: '192.168.1.1', dport: 53, frames: 84, bytes: 9_000, frames_ab: 42, bytes_ab: 5_000, frames_ba: 42, bytes_ba: 4_000 },
  { src: '192.168.1.100', sport: null, dst: '192.168.1.1', dport: null, frames: 120, bytes: 9_600, frames_ab: 60, bytes_ab: 4_800, frames_ba: 60, bytes_ba: 4_800 },
];

const FOLLOW: FollowResp = {
  client: '192.168.1.100:51000',
  server: '203.0.113.10:443',
  messages: Array.from({ length: 12 }, (_, i) => ({
    no: 100 + i * 2,
    ts: Date.now() / 1000 - 100 + i,
    dir: i % 2 === 0 ? 'c2s' : 's2c',
    data: i % 2 === 0 ? `GET /api/item/${i} HTTP/1.1\r\nHost: example.com\r\n\r\n` : `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok`,
    len: 64 + i,
  })),
};

const SETTINGS: AppSettings = {
  tshark_path: 'C:\\Program Files\\Wireshark\\tshark.exe',
  llm: { base_url: 'https://api.example.com/v1', api_key: 'sk-mock', model: 'gpt-4o-mini', enabled: false },
  masking: { enabled: true },
  kb_dir: 'D:\\code2026\\PcapCheck\\docs\\kb',
};

const IFACES: LiveInterface[] = [
  { idx: 1, name: '\\Device\\NpcapLoopback_1', desc: 'Adapter for loopback traffic capture (mock)' },
  { idx: 2, name: '\\Device\\NPF_{01234567-89AB-CDEF-0123-456789ABCDEF}', desc: '以太网 Realtek PCIe GbE Family Controller (mock)' },
];

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface MockOpts {
  method?: string;
  body?: unknown;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function mockRequest<T>(path: string, opts: MockOpts): Promise<T> {
  await sleep(120);
  const u = new URL(path, 'http://mock.local');
  const p = u.pathname;
  const m = (opts.method ?? 'GET').toUpperCase();
  const body = (opts.body ?? {}) as Record<string, unknown>;

  const R = (v: unknown): T => v as T;

  if (p === '/api/captures' && m === 'GET') return R([mockCapture()]);
  if (p === '/api/captures' && m === 'POST') return R({ capture_id: CAPTURE_ID });
  if (p === '/api/captures/upload' && m === 'POST') return R({ capture_id: CAPTURE_ID });
  if (/^\/api\/captures\/[^/]+$/.test(p)) return R(mockCapture());
  if (/^\/api\/captures\/[^/]+\/frames$/.test(p)) {
    const offset = Number(u.searchParams.get('offset') ?? 0);
    const limit = Number(u.searchParams.get('limit') ?? 1000);
    const filter = u.searchParams.get('filter') ?? '';
    const matched = MOCK_FRAMES.filter((f) => matchMock(f, filter));
    return R({ total: matched.length, frames: matched.slice(offset, offset + limit) });
  }
  if (/^\/api\/captures\/[^/]+\/frames\/\d+\/detail$/.test(p)) {
    const no = Number(p.match(/frames\/(\d+)\/detail/)?.[1] ?? 1);
    const f = MOCK_FRAMES[no - 1] ?? MOCK_FRAMES[0];
    return R([
      {
        _source: {
          layers: {
            frame: { 'frame.number': String(f.no), 'frame.time_epoch': String(f.ts), 'frame.len': String(f.length) },
            ip: { 'ip.src': f.src, 'ip.dst': f.dst, 'ip.ttl': '64', 'ip.version': '4' },
            tcp: { 'tcp.srcport': String(f.sport ?? ''), 'tcp.dstport': String(f.dport ?? ''), 'tcp.flags.syn': '0', 'tcp.window_size_value': '64240' },
          },
        },
      },
    ]);
  }
  if (/\/stats\/phs$/.test(p)) return R(PHS);
  if (/\/stats\/io$/.test(p)) return R(IO);
  if (/\/stats\/conversations$/.test(p)) {
    const proto = u.searchParams.get('proto') ?? 'tcp';
    return R(proto === 'ip' ? CONVS : CONVS.filter((c) => c.sport != null));
  }
  if (/\/follow\/\d+$/.test(p)) return R(FOLLOW);
  if (p === '/api/filter/compile') return R({ tshark_filter: String(body['expr'] ?? '') });
  if (p === '/api/reports' && m === 'GET') return R([mockReport()]);
  if (/^\/api\/reports\/[^/]+$/.test(p)) return R(mockReport());
  if (/^\/api\/reports\/[^/]+\/export$/.test(p)) return R({ ok: true } as Record<string, unknown>);
  if (p === '/api/settings' && m === 'GET') return R(SETTINGS);
  if (p === '/api/settings' && m === 'PUT') return R(body as unknown as AppSettings);
  if (p === '/api/kb/articles' && m === 'GET') {
    const rid = u.searchParams.get('rule_id');
    return R(rid ? KB_LIST.filter((a) => a.rule_ids?.includes(rid)) : KB_LIST);
  }
  if (p.startsWith('/api/kb/articles/')) return R(KB_LIST[0]);
  if (p === '/api/live/interfaces') return R(IFACES);
  if (p === '/api/live/start' || p === '/api/live/stop') return R(undefined);
  if (p === '/api/live/status') return R({ running: false, frame_count: 0, ifaces: IFACES.length });
  if (p === '/api/live/analyze') return R({ capture_id: CAPTURE_ID });
  if (p === '/api/captures/import' && m === 'POST') return R({ capture_id: CAPTURE_ID });

  throw Object.assign(new Error(`mock 未实现:${m} ${p}`), { status: 404 });
}
