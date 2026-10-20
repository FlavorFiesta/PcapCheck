// Follow Stream:按 stream 分组,双向着色(c2s / s2c),点击消息回跳帧号
import { useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../api/endpoints';
import type { FollowResp } from '../api/types';
import { absTime } from '../lib/format';

interface Props {
  captureId: string;
  stream: number;
  proto: 'tcp' | 'udp';
  onJump: (no: number) => void;
  onClose: () => void;
}

export default function FollowStream({ captureId, stream, proto, onJump, onClose }: Props) {
  const [data, setData] = useState<FollowResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    api
      .follow(captureId, stream, proto, ctrl.signal)
      .then((r) => {
        setData(r);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      });
    return () => ctrl.abort();
  }, [captureId, stream, proto]);

  const msgs = data?.messages ?? [];
  const v = useVirtualizer({
    count: msgs.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 56,
    overscan: 8,
  });

  return (
    <div className="pane follow-pane">
      <div className="fs-header">
        <span>
          {proto.toUpperCase()} 流 <b className="mono">{stream}</b>
        </span>
        <span className="dim mono">
          {data ? `${data.client} ↔ ${data.server}` : ''}
        </span>
        <span className="fs-legend">
          <span className="fs-dot c2s" /> 客户端 → 服务端
          <span className="fs-dot s2c" /> 服务端 → 客户端
        </span>
        <div className="spacer" />
        <span className="dim">{msgs.length} 条消息</span>
        <button className="btn small" onClick={onClose}>
          关闭
        </button>
      </div>

      {loading ? (
        <div className="dim" style={{ padding: 10 }}>
          加载中…
        </div>
      ) : error ? (
        <div className="err-text" style={{ padding: 10 }}>
          加载失败:{error}
        </div>
      ) : msgs.length === 0 ? (
        <div className="dim" style={{ padding: 10 }}>
          该流没有可显示的消息
        </div>
      ) : (
        <div className="fs-scroll" ref={scrollRef}>
          <div style={{ height: v.getTotalSize(), position: 'relative' }}>
            {v.getVirtualItems().map((it) => {
              const m = msgs[it.index];
              return (
                <div
                  key={it.key}
                  data-index={it.index}
                  ref={v.measureElement}
                  className={`fs-msg fs-${m.dir === 'c2s' ? 'c2s' : 's2c'}`}
                  style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${it.start}px)` }}
                  onClick={() => onJump(m.no)}
                  title="点击跳转到对应帧"
                >
                  <div className="fs-meta mono">
                    #{m.no} · {m.len} B · {m.dir === 'c2s' ? '客户端 → 服务端' : '服务端 → 客户端'} · {absTime(m.ts)}
                  </div>
                  <pre className="fs-data mono">{m.data}</pre>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
