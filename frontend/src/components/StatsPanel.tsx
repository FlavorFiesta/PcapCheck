// 统计面板:协议分级(phs)/ 会话列表(可排序)/ IO 时间线(ECharts 面积图)
import { useEffect, useMemo, useState } from 'react';
import ReactECharts from 'echarts-for-react';
import type { EChartsOption } from 'echarts';
import { api } from '../api/endpoints';
import type { Conversation, IoPoint, PhsNode } from '../api/types';
import { fmtBytes, fmtNum, pad2 } from '../lib/format';
import { useFrames } from '../store/framesStore';

type StatsTab = 'phs' | 'conv' | 'io';

const IO_INTERVALS = [0.1, 0.5, 1, 5, 10, 30, 60];

function asRec(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function num(v: unknown): number | undefined {
  if (v === null || v === undefined || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
function str(v: unknown): string {
  return v === null || v === undefined ? '' : String(v);
}

function clock(ts: number): string {
  const d = new Date(ts * 1000);
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

// ---- 协议分级 ----

function normPhsList(arr: unknown[]): PhsNode[] {
  return arr.map((item) => {
    const r = asRec(item) ?? {};
    const label =
      str(r['protocol'] ?? r['name'] ?? r['label'] ?? r['layer'] ?? r['title']) || '协议';
    const childRaw = r['children'] ?? r['sub'] ?? r['items'] ?? r['subtrees'];
    const children = Array.isArray(childRaw) ? normPhsList(childRaw) : undefined;
    return {
      label,
      frames: num(r['frames'] ?? r['frame_count'] ?? r['count']),
      bytes: num(r['bytes'] ?? r['total_bytes'] ?? r['len']),
      percent_frames: num(r['percent_frames'] ?? r['frames_percent'] ?? r['percent']),
      percent_bytes: num(r['percent_bytes'] ?? r['bytes_percent']),
      children,
    };
  });
}

function normPhs(data: unknown): PhsNode[] {
  if (Array.isArray(data)) return normPhsList(data);
  const r = asRec(data);
  if (!r) return [];
  for (const k of ['protocols', 'tree', 'items', 'nodes', 'protocol_hierarchy', 'phs']) {
    if (Array.isArray(r[k])) return normPhsList(r[k] as unknown[]);
  }
  return [];
}

/** 占比可能是 0-1 分数,也可能 0-100;整树归一 */
function rescalePercents(nodes: PhsNode[]): void {
  let max = 0;
  const walk = (list: PhsNode[]) => {
    for (const n of list) {
      max = Math.max(max, n.percent_frames ?? 0, n.percent_bytes ?? 0);
      if (n.children) walk(n.children);
    }
  };
  walk(nodes);
  const k = max > 0 && max <= 1.0001 ? 100 : 1;
  const fix = (list: PhsNode[]) => {
    for (const n of list) {
      if (n.percent_frames !== undefined) n.percent_frames *= k;
      if (n.percent_bytes !== undefined) n.percent_bytes *= k;
      if (n.children) fix(n.children);
    }
  };
  if (k !== 1) fix(nodes);
}

function PhsRow({ node, depth }: { node: PhsNode; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const hasKids = !!node.children?.length;
  return (
    <>
      <tr className={depth === 0 ? 'phs-root' : ''}>
        <td>
          <span style={{ paddingLeft: depth * 16 }}>
            {hasKids ? (
              <button className="tw-btn" onClick={() => setOpen(!open)}>
                {open ? '−' : '+'}
              </button>
            ) : (
              <span className="tw-space" />
            )}
            {node.label}
          </span>
        </td>
        <td className="num">{node.frames !== undefined ? fmtNum(node.frames) : '-'}</td>
        <td className="num">{node.bytes !== undefined ? fmtBytes(node.bytes) : '-'}</td>
        <td className="num">{node.percent_frames !== undefined ? `${node.percent_frames.toFixed(1)}%` : '-'}</td>
        <td className="num">{node.percent_bytes !== undefined ? `${node.percent_bytes.toFixed(1)}%` : '-'}</td>
      </tr>
      {open && node.children?.map((c, i) => <PhsRow key={i} node={c} depth={depth + 1} />)}
    </>
  );
}

function PhsView({ captureId }: { captureId: string }) {
  const [nodes, setNodes] = useState<PhsNode[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setError(null);
    api
      .statsPhs(captureId, ctrl.signal)
      .then((d) => {
        const t = normPhs(d);
        rescalePercents(t);
        setNodes(t);
      })
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => ctrl.abort();
  }, [captureId]);

  if (error) return <div className="err-text" style={{ padding: 10 }}>加载失败:{error}</div>;
  if (!nodes) return <div className="dim" style={{ padding: 10 }}>加载中…</div>;
  if (nodes.length === 0) return <div className="dim" style={{ padding: 10 }}>暂无协议分层数据</div>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>协议层级</th>
          <th>帧数</th>
          <th>字节数</th>
          <th>帧占比</th>
          <th>字节占比</th>
        </tr>
      </thead>
      <tbody>
        {nodes.map((n, i) => (
          <PhsRow key={i} node={n} depth={0} />
        ))}
      </tbody>
    </table>
  );
}

// ---- 会话列表 ----

type ConvKey = 'src' | 'dst' | 'frames' | 'bytes' | 'frames_ab' | 'bytes_ab' | 'frames_ba' | 'bytes_ba';

function ConvView({ captureId }: { captureId: string }) {
  const applyFilter = useFrames((s) => s.applyFilter);
  const [convs, setConvs] = useState<Conversation[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [proto, setProto] = useState<'tcp' | 'udp' | 'ip'>('tcp');
  const [sortKey, setSortKey] = useState<ConvKey>('frames');
  const [sortDir, setSortDir] = useState<1 | -1>(-1);

  useEffect(() => {
    const ctrl = new AbortController();
    setError(null);
    api
      .statsConversations(captureId, proto, ctrl.signal)
      .then((c) => setConvs(c))
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => ctrl.abort();
  }, [captureId, proto]);

  const sorted = useMemo(() => {
    const list = [...(convs ?? [])];
    list.sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      const an = typeof av === 'number' ? av : String(av ?? '');
      const bn = typeof bv === 'number' ? bv : String(bv ?? '');
      if (typeof an === 'number' && typeof bn === 'number') return (an - bn) * sortDir;
      return String(an).localeCompare(String(bn)) * sortDir;
    });
    return list;
  }, [convs, sortKey, sortDir]);

  const head = (key: ConvKey, label: string) => (
    <th
      onClick={() => {
        if (sortKey === key) setSortDir((d) => (d === 1 ? -1 : 1));
        else {
          setSortKey(key);
          setSortDir(-1);
        }
      }}
      title="点击排序"
    >
      {label}
      {sortKey === key ? (sortDir === 1 ? ' ↑' : ' ↓') : ''}
    </th>
  );

  if (error) return <div className="err-text" style={{ padding: 10 }}>加载失败:{error}</div>;
  if (!convs) return <div className="dim" style={{ padding: 10 }}>加载中…</div>;

  return (
    <div>
      <div className="conv-toolbar">
        <span className="dim">协议:</span>
        {(['tcp', 'udp', 'ip'] as const).map((p) => (
          <button key={p} className={`preset${proto === p ? ' active' : ''}`} onClick={() => setProto(p)}>
            {p.toUpperCase()}
          </button>
        ))}
        <span className="dim"> 共 {convs.length} 个会话</span>
      </div>
      <table className="data-table">
        <thead>
          <tr>
            {head('src', '源地址')}
            {head('dst', '目的地址')}
            {head('frames', '帧数')}
            {head('bytes', '字节数')}
            {head('frames_ab', 'A→B 帧')}
            {head('bytes_ab', 'A→B 字节')}
            {head('frames_ba', 'B→A 帧')}
            {head('bytes_ba', 'B→A 字节')}
            <th>过滤</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((c, i) => (
            <tr key={i}>
              <td className="mono">
                {c.src}
                {c.sport != null ? `:${c.sport}` : ''}
              </td>
              <td className="mono">
                {c.dst}
                {c.dport != null ? `:${c.dport}` : ''}
              </td>
              <td className="num">{fmtNum(c.frames)}</td>
              <td className="num">{fmtBytes(c.bytes)}</td>
              <td className="num">{c.frames_ab ?? '-'}</td>
              <td className="num">{c.bytes_ab != null ? fmtBytes(c.bytes_ab) : '-'}</td>
              <td className="num">{c.frames_ba ?? '-'}</td>
              <td className="num">{c.bytes_ba != null ? fmtBytes(c.bytes_ba) : '-'}</td>
              <td>
                <button className="btn small" onClick={() => applyFilter(`ip==${c.src}`)} title="按源 IP 过滤">
                  过滤
                </button>
              </td>
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={9} className="dim">
                暂无会话数据
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ---- IO 时间线 ----

function IoView({ captureId }: { captureId: string }) {
  const [io, setIo] = useState<IoPoint[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [interval, setIntervalS] = useState(1);

  useEffect(() => {
    const ctrl = new AbortController();
    setError(null);
    api
      .statsIo(captureId, interval, ctrl.signal)
      .then((d) => setIo(Array.isArray(d) ? d : []))
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => ctrl.abort();
  }, [captureId, interval]);

  const option: EChartsOption = useMemo(
    () => ({
      backgroundColor: 'transparent',
      animation: false,
      tooltip: { trigger: 'axis' },
      legend: { data: ['帧数', '字节数'], textStyle: { color: '#8b93a7', fontSize: 11 }, top: 0 },
      grid: { left: 56, right: 64, top: 28, bottom: 42 },
      xAxis: {
        type: 'category',
        data: (io ?? []).map((p) => clock(p.t)),
        axisLabel: { color: '#8b93a7', fontSize: 10 },
        axisLine: { lineStyle: { color: '#2b3140' } },
      },
      yAxis: [
        {
          type: 'value',
          name: '帧',
          nameTextStyle: { color: '#8b93a7' },
          axisLabel: { color: '#8b93a7', fontSize: 10 },
          splitLine: { lineStyle: { color: '#242a35' } },
        },
        {
          type: 'value',
          name: '字节',
          nameTextStyle: { color: '#8b93a7' },
          axisLabel: { color: '#8b93a7', fontSize: 10, formatter: (v: number) => fmtBytes(v) },
          splitLine: { show: false },
        },
      ],
      dataZoom: [{ type: 'inside' }],
      series: [
        {
          name: '帧数',
          type: 'line',
          smooth: true,
          showSymbol: false,
          areaStyle: { opacity: 0.25 },
          lineStyle: { width: 1.5 },
          itemStyle: { color: '#4f8cff' },
          data: (io ?? []).map((p) => p.frames),
        },
        {
          name: '字节数',
          type: 'line',
          yAxisIndex: 1,
          smooth: true,
          showSymbol: false,
          areaStyle: { opacity: 0.15 },
          lineStyle: { width: 1.5 },
          itemStyle: { color: '#3fb27f' },
          data: (io ?? []).map((p) => p.bytes),
        },
      ],
    }),
    [io],
  );

  return (
    <div className="io-view">
      <div className="conv-toolbar">
        <span className="dim">时间粒度(秒):</span>
        {IO_INTERVALS.map((iv) => (
          <button key={iv} className={`preset${interval === iv ? ' active' : ''}`} onClick={() => setIntervalS(iv)}>
            {iv}
          </button>
        ))}
      </div>
      {error ? (
        <div className="err-text" style={{ padding: 10 }}>
          加载失败:{error}
        </div>
      ) : !io ? (
        <div className="dim" style={{ padding: 10 }}>
          加载中…
        </div>
      ) : (
        <div className="io-chart">
          <ReactECharts option={option} style={{ height: '100%', width: '100%' }} notMerge lazyUpdate />
        </div>
      )}
    </div>
  );
}

// ---- 面板外壳 ----

export default function StatsPanel({ captureId }: { captureId: string }) {
  const [tab, setTab] = useState<StatsTab>('phs');
  return (
    <div className="pane stats-pane">
      <div className="pane-title stats-title-row">
        <span>统计</span>
      </div>
      <div className="pane-tabs sub">
        <button className={tab === 'phs' ? 'active' : ''} onClick={() => setTab('phs')}>
          协议分级
        </button>
        <button className={tab === 'conv' ? 'active' : ''} onClick={() => setTab('conv')}>
          会话
        </button>
        <button className={tab === 'io' ? 'active' : ''} onClick={() => setTab('io')}>
          IO 时间线
        </button>
      </div>
      <div className="stats-body">
        {tab === 'phs' && <PhsView captureId={captureId} />}
        {tab === 'conv' && <ConvView captureId={captureId} />}
        {tab === 'io' && <IoView captureId={captureId} />}
      </div>
    </div>
  );
}
