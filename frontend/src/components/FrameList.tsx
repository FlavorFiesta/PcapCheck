// 三窗格之首:报文列表(@tanstack/react-virtual 虚拟滚动 + 分页缓存)
import { useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { classifyFrame } from '../lib/frameClass';
import { absTime, addrPort, relTime } from '../lib/format';
import { useFrames } from '../store/framesStore';
import type { FrameRow } from '../api/types';

const ROW_H = 24;

interface CtxMenu {
  x: number;
  y: number;
  frame: FrameRow;
}

interface Props {
  firstTs?: number;
  selectedNo: number | null;
  highlightNo: number | null;
  onSelect: (f: FrameRow) => void;
  onFollow: (stream: number, proto: 'tcp' | 'udp') => void;
  onApplyFilter: (expr: string) => void;
  jumpTarget: number | null;
  onJumpDone: () => void;
}

export default function FrameList({
  firstTs,
  selectedNo,
  highlightNo,
  onSelect,
  onFollow,
  onApplyFilter,
  jumpTarget,
  onJumpDone,
}: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const total = useFrames((s) => s.total);
  const version = useFrames((s) => s.version);
  const error = useFrames((s) => s.error);
  const [menu, setMenu] = useState<CtxMenu | null>(null);

  const virtualizer = useVirtualizer({
    count: total,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 12,
  });

  const items = virtualizer.getVirtualItems();

  // 分页预取:可见范围外多取一些,滚动接近底部时自动拉后续页
  useEffect(() => {
    if (items.length === 0) return;
    const start = items[0].index;
    const end = items[items.length - 1].index;
    useFrames.getState().ensureRange(start - 100, end + 400);
  });

  // 跳转到指定帧(证据帧回跳):等包含该帧的页加载完成后滚动定位
  useEffect(() => {
    if (jumpTarget == null) return;
    const idx = jumpTarget - 1;
    if (idx < 0) {
      onJumpDone();
      return;
    }
    if (total > 0 && idx >= total) {
      onJumpDone();
      return;
    }
    const f = useFrames.getState().getFrame(idx);
    if (f) {
      virtualizer.scrollToIndex(idx, { align: 'center' });
      onJumpDone();
    } else if (total > 0) {
      useFrames.getState().ensureRange(Math.max(0, idx - 100), idx + 100);
    }
  }, [jumpTarget, total, version, virtualizer, onJumpDone]);

  const paddingTop = items.length > 0 ? items[0].start : 0;
  const last = items.length > 0 ? items[items.length - 1] : null;
  const paddingBottom = last ? virtualizer.getTotalSize() - (last.start + last.size) : 0;

  return (
    <div className="frame-list" onClick={() => setMenu(null)}>
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
        {total === 0 ? (
          <div className="list-empty">
            {error ? `加载失败:${error}(重新选择捕获或切换过滤器可重试)` : '暂无报文(导入捕获文件,或调整过滤器)'}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', minWidth: 1080 }}>
            <div style={{ height: paddingTop }} />
            {items.map((it) => {
              const f = useFrames.getState().getFrame(it.index);
              if (!f) {
                return (
                  <div key={it.key} className="frame-row frame-grid row-loading" style={{ height: it.size }}>
                    <span className="dim mono">{it.index + 1}</span>
                    <span className="dim">加载中…</span>
                  </div>
                );
              }
              return (
                <RowView
                  key={it.key}
                  f={f}
                  height={it.size}
                  firstTs={firstTs}
                  selected={f.no === selectedNo}
                  highlighted={f.no === highlightNo}
                  onSelect={onSelect}
                  onFollow={onFollow}
                  onMenu={setMenu}
                />
              );
            })}
            <div style={{ height: paddingBottom }} />
          </div>
        )}
      </div>

      {menu && (
        <ContextMenu
          menu={menu}
          onClose={() => setMenu(null)}
          onFollow={(s, p) => {
            setMenu(null);
            onFollow(s, p);
          }}
          onFilter={(expr) => {
            setMenu(null);
            onApplyFilter(expr);
          }}
        />
      )}
    </div>
  );
}

function RowView({
  f,
  height,
  firstTs,
  selected,
  highlighted,
  onSelect,
  onFollow,
  onMenu,
}: {
  f: FrameRow;
  height: number;
  firstTs?: number;
  selected: boolean;
  highlighted: boolean;
  onSelect: (f: FrameRow) => void;
  onFollow: (stream: number, proto: 'tcp' | 'udp') => void;
  onMenu: (m: CtxMenu) => void;
}) {
  const c = classifyFrame(f);
  const cls = ['frame-row', 'frame-grid', c.cls ?? '', selected ? 'selected' : '', highlighted ? 'highlight' : '']
    .filter(Boolean)
    .join(' ');
  return (
    <div
      className={cls}
      style={{ height }}
      title={`${absTime(f.ts)} · ${f.info}`}
      onClick={() => onSelect(f)}
      onDoubleClick={() => {
        if (f.stream != null) onFollow(f.stream, 'tcp');
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        onMenu({ x: e.clientX, y: e.clientY, frame: f });
      }}
    >
      <span className="mono num">{f.no}</span>
      <span className="mono num dim" title={absTime(f.ts)}>
        {relTime(f.ts, firstTs)}
      </span>
      <span className="mono addr">{addrPort(f.src, f.sport)}</span>
      <span className="mono addr">{addrPort(f.dst, f.dport)}</span>
      <span>{f.proto}</span>
      <span className="num">{f.length}</span>
      <span className="info" title={f.info}>
        {f.info}
        {c.label ? <span className={`tag tag-${c.cls}`}>{c.label}</span> : null}
      </span>
    </div>
  );
}

function ContextMenu({
  menu,
  onClose,
  onFollow,
  onFilter,
}: {
  menu: CtxMenu;
  onClose: () => void;
  onFollow: (stream: number, proto: 'tcp' | 'udp') => void;
  onFilter: (expr: string) => void;
}) {
  useEffect(() => {
    const close = () => onClose();
    window.addEventListener('click', close);
    window.addEventListener('contextmenu', close);
    return () => {
      window.removeEventListener('click', close);
      window.removeEventListener('contextmenu', close);
    };
  }, [onClose]);

  const f = menu.frame;
  const hasStream = f.stream != null;
  return (
    <div className="ctx-menu" style={{ left: menu.x, top: menu.y }} onClick={(e) => e.stopPropagation()}>
      <button disabled={!hasStream} onClick={() => onFollow(f.stream as number, 'tcp')}>
        追踪 TCP 流{hasStream ? `(stream ${f.stream})` : ''}
      </button>
      <button disabled={!hasStream} onClick={() => onFollow(f.stream as number, 'udp')}>
        追踪 UDP 流
      </button>
      <div className="ctx-sep" />
      <button
        onClick={() => {
          void navigator.clipboard?.writeText(f.src ?? '');
          onClose();
        }}
      >
        复制源地址
      </button>
      <button
        onClick={() => {
          void navigator.clipboard?.writeText(f.dst ?? '');
          onClose();
        }}
      >
        复制目的地址
      </button>
      <div className="ctx-sep" />
      <button
        onClick={() => {
          onFilter(`ip==${f.src ?? ''}`);
          onClose();
        }}
      >
        过滤源 IP
      </button>
      <button
        onClick={() => {
          onFilter(`ip==${f.dst ?? ''}`);
          onClose();
        }}
      >
        过滤目的 IP
      </button>
    </div>
  );
}
