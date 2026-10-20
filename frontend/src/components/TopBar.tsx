// 顶部全局条:当前捕获、帧数、状态、导入按钮、后端连通状态
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/endpoints';
import type { CaptureMeta } from '../api/types';
import { fmtNum } from '../lib/format';
import { useApp } from '../store/appStore';
import { toastApiError, toastInfo, toastSuccess } from './toast';

async function pollUntilReady(id: string, onDone: (m: CaptureMeta) => void): Promise<void> {
  for (let i = 0; i < 600; i++) {
    await new Promise((r) => setTimeout(r, 500));
    try {
      const m = await api.getCapture(id);
      if (!m) {
        toastApiError(new Error('捕获信息格式异常(后端返回了非对象数据)'), '导入状态查询失败');
        return;
      }
      if (m.status !== 'importing') {
        onDone(m);
        return;
      }
    } catch (e) {
      toastApiError(e, '导入状态查询失败');
      return;
    }
  }
  toastInfo('导入超时,请稍后在捕获列表中查看状态');
}

export default function TopBar() {
  const nav = useNavigate();
  const captures = useApp((s) => s.captures);
  const currentId = useApp((s) => s.currentId);
  const meta = useApp((s) => s.meta);
  const backendOk = useApp((s) => s.backendOk);
  const loadCaptures = useApp((s) => s.loadCaptures);
  const setCurrent = useApp((s) => s.setCurrent);
  const refreshMeta = useApp((s) => s.refreshMeta);
  const fileRef = useRef<HTMLInputElement>(null);

  // 首次拉取捕获列表
  useEffect(() => {
    void loadCaptures();
  }, [loadCaptures]);

  // 导入中轮询 meta
  useEffect(() => {
    if (meta?.status !== 'importing') return;
    const t = window.setInterval(() => void refreshMeta(), 800);
    return () => window.clearInterval(t);
  }, [meta?.status, refreshMeta]);

  const finishImport = (id: string, m: CaptureMeta) => {
    setCurrent(id);
    void loadCaptures();
    if (m.status === 'ready') {
      toastSuccess(`导入完成:${m.name}(${fmtNum(m.frame_count)} 帧)`);
      // 导入只负责解析入库;用户在报告页明确选择规则诊断或 AI 直达分析。
      nav(`/report?capture=${encodeURIComponent(id)}`);
    } else {
      toastApiError(new Error(m.error ?? '导入失败'), '导入失败');
    }
  };

  const handleFile = async (f: File | undefined) => {
    if (!f) return;
    try {
      toastInfo(`正在上传 ${f.name} ...`);
      const r = await api.uploadCapture(f);
      await pollUntilReady(r.capture_id, (m) => finishImport(r.capture_id, m));
    } catch (e) {
      toastApiError(e, '导入失败');
    }
  };

  const handlePathImport = async () => {
    const p = window.prompt('输入 pcap/pcapng 文件的完整路径(后端本机):');
    if (!p || !p.trim()) return;
    try {
      const r = await api.importByPath(p.trim());
      await pollUntilReady(r.capture_id, (m) => finishImport(r.capture_id, m));
    } catch (e) {
      toastApiError(e, '路径导入失败');
    }
  };

  return (
    <header className="topbar">
      <select
        className="cap-select"
        value={currentId ?? ''}
        onChange={(e) => {
          const id = e.target.value || null;
          setCurrent(id);
          if (id) nav(`/browse?capture=${id}`);
        }}
      >
        <option value="">— 选择捕获文件 —</option>
        {captures.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name}
            {c.status !== 'ready' ? `(${c.status === 'importing' ? '导入中' : '错误'})` : ''}
          </option>
        ))}
      </select>

      {meta && (
        <span className="cap-info">
          <span className="cap-name" title={meta.path ?? ''}>
            {meta.name}
          </span>
          <span className="dim mono num">{fmtNum(meta.frame_count)} 帧</span>
          <span className={`status-chip status-${meta.status}`}>
            {meta.status === 'ready' ? '就绪' : meta.status === 'importing' ? `导入中 ${fmtNum(meta.frame_count)}` : '错误'}
          </span>
        </span>
      )}

      <div className="spacer" />

      <button className="btn" onClick={() => void refreshMeta()}>
        刷新
      </button>
      <button className="btn" onClick={() => void handlePathImport()}>
        路径导入
      </button>
      <button className="btn primary" onClick={() => fileRef.current?.click()}>
        导入文件
      </button>
      <input
        ref={fileRef}
        type="file"
        accept=".pcap,.pcapng,.cap,.pcapgz,.gz"
        hidden
        onChange={(e) => {
          void handleFile(e.target.files?.[0]);
          e.target.value = '';
        }}
      />
      <span className={`backend-dot${backendOk ? '' : ' bad'}`} title={backendOk ? '后端已连接(127.0.0.1:8123)' : '后端不可达,请启动后端服务'}>
        后端
      </span>
    </header>
  );
}
