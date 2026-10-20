// 浏览页(核心):三窗格 + 过滤器 + 统计 + 流追踪
import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import FilterBar from '../components/FilterBar';
import FollowStream from '../components/FollowStream';
import FrameInfoPanel from '../components/FrameInfoPanel';
import FrameList from '../components/FrameList';
import ProtocolTree from '../components/ProtocolTree';
import StatsPanel from '../components/StatsPanel';
import { HSplitter, VSplitter } from '../components/Splitter';
import type { FrameRow } from '../api/types';
import { useApp } from '../store/appStore';
import { useFrames } from '../store/framesStore';

type RightTab = 'info' | 'stats' | 'follow';

export default function BrowsePage() {
  const [params] = useSearchParams();
  const captureParam = params.get('capture');
  const frameParam = params.get('frame');
  const currentId = useApp((s) => s.currentId);
  const meta = useApp((s) => s.meta);
  const metaLoading = useApp((s) => s.metaLoading);
  const setCurrent = useApp((s) => s.setCurrent);

  const captureId = captureParam ?? currentId;

  const [listH, setListH] = useState(() => Math.max(180, Math.round(window.innerHeight * 0.38)));
  const [infoW, setInfoW] = useState(520);
  const [rightTab, setRightTab] = useState<RightTab>('info');
  const [selected, setSelected] = useState<FrameRow | null>(null);
  const [follow, setFollow] = useState<{ stream: number; proto: 'tcp' | 'udp' } | null>(null);
  const [jumpTarget, setJumpTarget] = useState<number | null>(frameParam ? Number(frameParam) : null);
  const [highlightNo, setHighlightNo] = useState<number | null>(frameParam ? Number(frameParam) : null);

  const metaStatus = meta?.status ?? null;

  // URL ?capture= -> 全局当前捕获
  useEffect(() => {
    if (captureParam && captureParam !== currentId) setCurrent(captureParam);
  }, [captureParam, currentId, setCurrent]);

  // 捕获就绪后打开帧数据(保留当前过滤表达式)
  useEffect(() => {
    if (!captureId || metaLoading || metaStatus === 'importing') return;
    const st = useFrames.getState();
    if (st.captureId !== captureId) {
      st.open(captureId, st.filter);
    } else if (metaStatus === 'ready' && st.total === 0 && st.pages.size === 0 && st.pending.size === 0 && !st.error) {
      // 捕获从"导入中"变为"就绪":重新加载
      st.open(captureId, st.filter);
    }
  }, [captureId, metaLoading, metaStatus]);

  // 跳转目标:有过滤时先清空(无过滤时帧号即行号),并设置高亮
  useEffect(() => {
    if (jumpTarget == null) return;
    setHighlightNo(jumpTarget);
    const st = useFrames.getState();
    if (st.filter) st.applyFilter('');
  }, [jumpTarget]);

  // 高亮帧加载后自动选中,联动协议树
  const version = useFrames((s) => s.version);
  useEffect(() => {
    if (highlightNo == null) return;
    const f = useFrames.getState().getFrame(highlightNo - 1);
    if (f) setSelected(f);
  }, [highlightNo, version]);

  const handleSelect = useCallback((f: FrameRow) => {
    setSelected(f);
    setHighlightNo(null);
  }, []);

  const handleFollow = useCallback((stream: number, proto: 'tcp' | 'udp') => {
    setFollow({ stream, proto });
    setRightTab('follow');
  }, []);

  const handleApplyFilter = useCallback((expr: string) => {
    useFrames.getState().applyFilter(expr);
  }, []);

  const handleJumpDone = useCallback(() => setJumpTarget(null), []);

  const handleFollowJump = useCallback((no: number) => {
    setJumpTarget(no);
  }, []);

  const closeFollow = useCallback(() => {
    setFollow(null);
    setRightTab('info');
  }, []);

  if (!captureId) {
    return (
      <div className="page browse-empty">
        <h2>尚未选择捕获文件</h2>
        <p className="dim">
          请使用顶部「导入文件」上传 pcap/pcapng,或「路径导入」导入后端本机文件;
          也可前往 <Link to="/live">实时抓包</Link> 抓取数据后分析。
        </p>
      </div>
    );
  }

  return (
    <div className="browse-page">
      <FilterBar />
      <div className="browse-main">
        <div className="browse-list-wrap" style={{ height: listH }}>
          <FrameList
            firstTs={meta?.first_ts}
            selectedNo={selected?.no ?? null}
            highlightNo={highlightNo}
            onSelect={handleSelect}
            onFollow={handleFollow}
            onApplyFilter={handleApplyFilter}
            jumpTarget={jumpTarget}
            onJumpDone={handleJumpDone}
          />
        </div>
        <HSplitter onDelta={(dy) => setListH((h) => Math.min(Math.max(140, h + dy), window.innerHeight - 320))} />
        <div className="browse-bottom-wrap">
          <div className="pane-tabs">
            <button className={rightTab === 'info' ? 'active' : ''} onClick={() => setRightTab('info')}>
              帧信息
            </button>
            <button className={rightTab === 'stats' ? 'active' : ''} onClick={() => setRightTab('stats')}>
              统计
            </button>
            {follow && (
              <button className={rightTab === 'follow' ? 'active' : ''} onClick={() => setRightTab('follow')}>
                流追踪({follow.stream})
              </button>
            )}
          </div>
          <div className="browse-bottom">
            {rightTab === 'stats' ? (
              // 统计 tab 独占下侧全宽,保证会话表完整可见
              <div className="browse-bottom-full">
                <StatsPanel captureId={captureId} />
              </div>
            ) : (
              <>
                <div className="browse-bottom-left">
                  <ProtocolTree captureId={captureId} frameNo={selected?.no ?? null} />
                </div>
                <VSplitter onDelta={(dx) => setInfoW((w) => Math.min(Math.max(320, w - dx), window.innerWidth - 460))} />
                <div className="browse-bottom-right" style={{ width: infoW }}>
                  <div className="right-body">
                    {rightTab === 'info' && <FrameInfoPanel frame={selected} onFollow={handleFollow} />}
                    {rightTab === 'follow' && follow && (
                      <FollowStream
                        captureId={captureId}
                        stream={follow.stream}
                        proto={follow.proto}
                        onJump={handleFollowJump}
                        onClose={closeFollow}
                      />
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
