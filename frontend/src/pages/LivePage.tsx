// 实时抓包页:接口选择 -> 开始/停止 -> WS 帧流入(虚拟滚动 + 自动滚底可暂停)
// "分析当前数据":优先 POST /api/live/analyze,未实现则用 GET /api/live/status
// 中的临时 pcap 路径走 POST /api/captures/import。
import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../api/endpoints';
import type { FrameRow, LiveInterface, LiveStatus } from '../api/types';
import { addrPort, fmtNum, relTime } from '../lib/format';
import { classifyFrame } from '../lib/frameClass';
import { toastApiError, toastError, toastInfo, toastSuccess } from '../components/toast';

const MAX_BUFFER = 100000;
const ROW_H = 24;

function getNum(r: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const v = r[k];
    if (v === undefined || v === null || v === '') continue;
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

function getStr(r: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'string' && v.length > 0) return v;
    if (typeof v === 'number') return String(v);
  }
  return '';
}

/** WS 帧形态兼容:frames 表行形 / ek 行形 */
export function normalizeLiveFrame(raw: unknown): FrameRow | null {
  let r = raw as Record<string, unknown> | null;
  if (!r || typeof r !== 'object') return null;
  if (r['frame'] && typeof r['frame'] === 'object') r = r['frame'] as Record<string, unknown>;
  const no = getNum(r, ['no', 'frame.number', 'frame_number']);
  if (no == null) return null;
  const ts = getNum(r, ['ts', 'frame.time_epoch', 'timestamp']) ?? Date.now() / 1000;
  return {
    no,
    ts,
    src: getStr(r, ['src', 'ip.src', 'ipv6.src', 'arp.src.proto_ipv4']),
    dst: getStr(r, ['dst', 'ip.dst', 'ipv6.dst', 'arp.dst.proto_ipv4']),
    sport: getNum(r, ['sport', 'tcp.srcport', 'udp.srcport']),
    dport: getNum(r, ['dport', 'tcp.dstport', 'udp.dstport']),
    proto: getStr(r, ['proto', '_ws.col.Protocol', 'protocol']) || 'UNKNOWN',
    length: getNum(r, ['length', 'frame.len', 'frame_len']) ?? 0,
    info: getStr(r, ['info', '_ws.col.Info']) || '',
    stream: getNum(r, ['stream', 'tcp.stream', 'udp.stream']),
    analysis: [],
    expert: null,
  };
}

export default function LivePage() {
  const nav = useNavigate();
  const [ifaces, setIfaces] = useState<LiveInterface[]>([]);
  const [ifaceErr, setIfaceErr] = useState<string | null>(null);
  const [selected, setSelected] = useState('');
  const [running, setRunning] = useState(false);
  const [statusFrames, setStatusFrames] = useState(0);
  const [autoScroll, setAutoScroll] = useState(true);
  const [busy, setBusy] = useState(false);
  const [snaplen, setSnaplen] = useState('');

  const [, forceTick] = useReducer((x: number) => x + 1, 0);
  const bufRef = useRef<FrameRow[]>([]);
  const pendingTick = useRef(false);
  const autoScrollRef = useRef(autoScroll);
  const scrollRef = useRef<HTMLDivElement>(null);
  const vRef = useRef<{ scrollToIndex: (i: number, o?: { align?: 'start' | 'center' | 'end' }) => void } | null>(null);

  useEffect(() => {
    autoScrollRef.current = autoScroll;
  }, [autoScroll]);

  const scheduleTick = useCallback(() => {
    if (pendingTick.current) return;
    pendingTick.current = true;
    requestAnimationFrame(() => {
      pendingTick.current = false;
      forceTick();
      if (autoScrollRef.current) {
        const buf = bufRef.current;
        if (buf.length > 0) vRef.current?.scrollToIndex(buf.length - 1, { align: 'end' });
      }
    });
  }, []);

  // WebSocket 连接(自动重试几次)
  useEffect(() => {
    let closed = false;
    let retry = 0;
    let ws: WebSocket | null = null;
    const connect = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${proto}://${location.host}/ws/live`);
      ws.onmessage = (ev) => {
        try {
          const msg: unknown = JSON.parse(String(ev.data));
          const r = (msg ?? {}) as Record<string, unknown>;
          if (r['type'] === 'frame') {
            const f = normalizeLiveFrame(r['frame']);
            if (f) {
              const buf = bufRef.current;
              buf.push(f);
              if (buf.length > MAX_BUFFER) buf.splice(0, buf.length - MAX_BUFFER);
              scheduleTick();
            }
          } else if (r['type'] === 'status') {
            if (typeof r['running'] === 'boolean') setRunning(r['running']);
            const fc = Number(r['frame_count']);
            if (Number.isFinite(fc)) setStatusFrames(fc);
          }
        } catch {
          /* 忽略非法消息 */
        }
      };
      ws.onclose = () => {
        if (!closed && retry < 5) {
          retry++;
          window.setTimeout(connect, 1500 * retry);
        }
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
    };
  }, [scheduleTick]);

  // 接口列表 + 状态轮询
  useEffect(() => {
    let alive = true;
    api
      .liveInterfaces()
      .then((l) => {
        if (!alive) return;
        setIfaces(l);
        setIfaceErr(null);
        if (l.length > 0) setSelected((s) => s || String(l[0]?.name ?? ''));
      })
      .catch((e: unknown) => alive && setIfaceErr(e instanceof Error ? e.message : String(e)));
    const t = window.setInterval(() => {
      api
        .liveStatus()
        .then((s: LiveStatus) => {
          if (!alive) return;
          setRunning(!!s.running);
          setStatusFrames(Number(s.frame_count ?? 0));
        })
        .catch(() => {});
    }, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  const start = async () => {
    if (!selected) {
      toastError('请先选择接口');
      return;
    }
    setBusy(true);
    try {
      const sl = Number(snaplen);
      await api.liveStart(selected, Number.isFinite(sl) && sl > 0 ? sl : undefined);
      setRunning(true);
      toastSuccess('抓包已开始');
    } catch (e) {
      toastApiError(e, '启动失败(需要管理员权限与 Npcap)');
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    try {
      await api.liveStop();
      setRunning(false);
      toastInfo('已停止,缓冲区保留');
    } catch (e) {
      toastApiError(e, '停止失败');
    } finally {
      setBusy(false);
    }
  };

  const analyzeBuffer = async () => {
    if (bufRef.current.length === 0) {
      toastError('当前缓冲区没有报文');
      return;
    }
    // 1) 尝试专用入口
    try {
      const r = await api.liveAnalyze();
      if (r?.capture_id) {
        toastSuccess('已将当前数据转为捕获');
        nav(`/browse?capture=${r.capture_id}`);
        return;
      }
    } catch {
      /* 未实现则降级 */
    }
    // 2) 从 status 拿临时 pcap 路径 -> import
    try {
      const st = (await api.liveStatus()) as LiveStatus;
      const candidate = [st.temp_pcap, st['pcap_path'], st['temp_pcap_path'], st['path'], st['file']].find(
        (v): v is string => typeof v === 'string' && v.length > 0,
      );
      if (candidate) {
        const r = await api.importByPath(candidate);
        toastSuccess('已提交当前数据进行分析');
        nav(`/browse?capture=${r.capture_id}`);
      } else {
        toastError('后端未提供 live 分析入口,且 live/status 中没有临时 pcap 路径,无法分析当前数据');
      }
    } catch (e) {
      toastApiError(e, '分析当前数据失败');
    }
  };

  const buf = bufRef.current;
  const v = useVirtualizer({
    count: buf.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 20,
  });
  vRef.current = v;
  const items = v.getVirtualItems();

  return (
    <div className="live-page">
      <div className="live-toolbar">
        <span className={`status-chip ${running ? 'status-ready' : 'status-error'}`}>{running ? '抓包中' : '未运行'}</span>
        <label className="dim">接口:</label>
        <select value={selected} onChange={(e) => setSelected(e.target.value)} style={{ maxWidth: 420 }}>
          {ifaces.length === 0 && <option value="">(无可用接口)</option>}
          {ifaces.map((i) => (
            <option key={String(i.name ?? i.idx)} value={String(i.name)}>
              {i.idx}. {i.desc || i.name}
            </option>
          ))}
        </select>
        <label className="dim" title="可选,默认由后端决定">
          snaplen:
        </label>
        <input value={snaplen} onChange={(e) => setSnaplen(e.target.value)} style={{ width: 70 }} placeholder="默认" />
        <button className="btn primary" disabled={busy || running || !selected} onClick={() => void start()}>
          开始
        </button>
        <button className="btn" disabled={busy || !running} onClick={() => void stop()}>
          停止
        </button>
        <div className="vsep" />
        <button className={`preset${autoScroll ? ' active' : ''}`} onClick={() => setAutoScroll((a) => !a)}>
          {autoScroll ? '自动滚底:开' : '自动滚底:关'}
        </button>
        <button
          className="btn"
          onClick={() => {
            bufRef.current = [];
            forceTick();
          }}
        >
          清空
        </button>
        <button className="btn" disabled={buf.length === 0} onClick={() => void analyzeBuffer()}>
          分析当前数据
        </button>
        <div className="spacer" />
        <span className="dim mono num">
          缓冲 {fmtNum(buf.length)} 帧{running ? '' : ''}
          {statusFrames > 0 && !running ? ` · 后端累计 ${fmtNum(statusFrames)}` : ''}
        </span>
      </div>

      {ifaceErr && <div className="err-text live-err">获取接口列表失败:{ifaceErr}(请确认后端已启动且安装了 Npcap)</div>}

      <div className="frame-list live-list">
        <div className="frame-grid frame-header">
          <span>#</span>
          <span>时间</span>
          <span>源地址</span>
          <span>目的地址</span>
          <span>协议</span>
          <span>长度</span>
          <span>Info</span>
        </div>
        <div className="frame-scroll" ref={scrollRef}>
          {buf.length === 0 ? (
            <div className="list-empty">
              {ifaceErr
                ? '无法连接抓包服务,请先解决接口列表错误。'
                : '选择接口并点击「开始」后,报文将实时流入此处。'}
            </div>
          ) : (
            <div style={{ height: v.getTotalSize(), position: 'relative', minWidth: 1080 }}>
              <div style={{ height: items.length > 0 ? items[0].start : 0 }} />
              {items.map((it) => {
                const f = buf[it.index];
                if (!f) return <div key={it.key} style={{ height: it.size }} />;
                const c = classifyFrame(f);
                return (
                  <div
                    key={it.key}
                    className={`frame-row frame-grid${c.cls ? ` ${c.cls}` : ''}`}
                    style={{ height: it.size }}
                    title={f.info}
                  >
                    <span className="mono num">{f.no}</span>
                    <span className="mono num dim">{relTime(f.ts, buf[0]?.ts)}</span>
                    <span className="mono addr">{addrPort(f.src, f.sport)}</span>
                    <span className="mono addr">{addrPort(f.dst, f.dport)}</span>
                    <span>{f.proto}</span>
                    <span className="num">{f.length}</span>
                    <span className="info">{f.info}</span>
                  </div>
                );
              })}
              <div
                style={{
                  height:
                    items.length > 0
                      ? v.getTotalSize() - (items[items.length - 1].start + items[items.length - 1].size)
                      : 0,
                }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
