// 选中帧相关信息(概览):关键字段 + 分析标记 + Expert + 追踪流入口
import type { FrameRow } from '../api/types';
import { absTime } from '../lib/format';
import { expertItems, toStringArray } from '../lib/frameClass';

interface Props {
  frame: FrameRow | null;
  onFollow: (stream: number, proto: 'tcp' | 'udp') => void;
}

export default function FrameInfoPanel({ frame, onFollow }: Props) {
  if (!frame) {
    return (
      <div className="pane frame-info">
        <div className="pane-title">帧信息</div>
        <div className="dim" style={{ padding: 10 }}>
          未选中帧
        </div>
      </div>
    );
  }
  const analysis = toStringArray(frame.analysis);
  const expert = expertItems(frame.expert);
  return (
    <div className="pane frame-info">
      <div className="pane-title">帧信息</div>
      <div className="info-body">
        <div className="kv">
          <span className="k">帧号</span>
          <span className="v mono num">{frame.no}</span>
        </div>
        <div className="kv">
          <span className="k">绝对时间</span>
          <span className="v mono">{absTime(frame.ts)}</span>
        </div>
        <div className="kv">
          <span className="k">协议</span>
          <span className="v">{frame.proto}</span>
        </div>
        <div className="kv">
          <span className="k">长度</span>
          <span className="v mono num">{frame.length} B</span>
        </div>
        <div className="kv">
          <span className="k">源 → 目的</span>
          <span className="v mono">
            {frame.src}
            {frame.sport != null ? `:${frame.sport}` : ''} → {frame.dst}
            {frame.dport != null ? `:${frame.dport}` : ''}
          </span>
        </div>
        <div className="kv">
          <span className="k">流</span>
          <span className="v mono">{frame.stream ?? '-'}</span>
        </div>
        {frame.stream != null && (
          <div className="kv">
            <span className="k">追踪流</span>
            <span className="v">
              <button className="btn small" onClick={() => onFollow(frame.stream as number, 'tcp')}>
                TCP 流
              </button>{' '}
              <button className="btn small" onClick={() => onFollow(frame.stream as number, 'udp')}>
                UDP 流
              </button>
            </span>
          </div>
        )}
        {analysis.length > 0 && (
          <div className="kv">
            <span className="k">分析标记</span>
            <span className="v">
              {analysis.map((a) => (
                <span key={a} className="tag tag-row-error">
                  {a}
                </span>
              ))}
            </span>
          </div>
        )}
        {expert.length > 0 && (
          <div className="kv">
            <span className="k">Expert</span>
            <span className="v">
              {expert.map((e, i) => (
                <div key={i} className="expert-item">
                  [{String(e.severity ?? '')}] {e.message ?? ''}
                </div>
              ))}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
