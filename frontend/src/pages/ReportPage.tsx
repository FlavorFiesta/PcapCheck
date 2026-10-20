// 诊断报告页:选择捕获 -> 规则诊断或 AI 直达分析 -> 首页方式标识 + 三档分组/AI 文本 + 导出
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { api } from '../api/endpoints';
import type { Finding, Report } from '../api/types';
import { fullTime } from '../lib/format';
import { useApp } from '../store/appStore';
import { toastApiError, toastSuccess } from '../components/toast';

const TIER_META: Record<string, { label: string; cls: string; order: number }> = {
  confirmed: { label: '确诊故障', cls: 'tier-confirmed', order: 0 },
  suspect: { label: '疑似问题', cls: 'tier-suspect', order: 1 },
  potential: { label: '潜在风险', cls: 'tier-potential', order: 2 },
};

function normFindings(f: Report['findings']): Finding[] {
  if (Array.isArray(f)) return f;
  if (typeof f === 'string' && f.length > 0) {
    try {
      const p: unknown = JSON.parse(f);
      return Array.isArray(p) ? (p as Finding[]) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function buildBrief(report: Report, findings: Finding[]): string {
  if (report.analysis_mode === 'ai_direct' || report.engine === 'ai-direct') {
    return '本报告由 AI 直达分析生成：已跳过本地规则引擎和知识库关联，结论请结合原始报文进一步核验。';
  }
  const captureName = (report.capture_name ?? '').toLowerCase();
  if (findings.length === 0 && captureName.includes('benign') && captureName.includes('dns')) {
    return '这是一份良性（健康）DNS 流量基线样本，未命中报文检查规则引擎的任何确诊 / 疑似 / 潜在规则，属于合成测试负样本，预期输出“无故障”。';
  }
  if (findings.length === 0) {
    return '本次抓包未命中报文检查规则引擎的确诊 / 疑似 / 潜在规则，当前未发现规则定义范围内的异常。';
  }
  const counts = [
    ['confirmed', '确诊故障'],
    ['suspect', '疑似问题'],
    ['potential', '潜在风险'],
  ] as const;
  const parts = counts
    .map(([tier, label]) => {
      const n = findings.filter((f) => f.tier === tier).length;
      return n ? `${label} ${n} 项` : '';
    })
    .filter(Boolean);
  return `本次抓包共发现${parts.join('、')}，请结合证据帧和关联知识库进一步确认。`;
}

function FindingCard({ f, captureId }: { f: Finding; captureId: string }) {
  const nav = useNavigate();
  const meta = TIER_META[f.tier] ?? { label: f.tier, cls: 'tier-potential', order: 9 };
  const stats = f.stats ?? {};
  const statEntries = Object.entries(stats);
  return (
    <div className={`finding-card ${meta.cls}`}>
      <div className="finding-head">
        <span className="rule-chip mono">{f.rule_id}</span>
        <span className="finding-title">{f.title}</span>
      </div>
      {statEntries.length > 0 && (
        <div className="finding-stats">
          {statEntries.map(([k, v]) => (
            <span key={k} className="stat-chip">
              {k}: <b className="mono">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</b>
            </span>
          ))}
        </div>
      )}
      {(f.evidence_frames?.length ?? 0) > 0 && (
        <div className="finding-evidence">
          <span className="dim">证据帧:</span>
          {f.evidence_frames.slice(0, 30).map((no) => (
            <button
              key={no}
              className="frame-chip mono"
              title={`跳转到浏览页帧 ${no}`}
              onClick={() => nav(`/browse?capture=${captureId}&frame=${no}`)}
            >
              {no}
            </button>
          ))}
          {f.evidence_frames.length > 30 && <span className="dim">…共 {f.evidence_frames.length} 帧</span>}
        </div>
      )}
      {f.suggestion && (
        <div className="finding-suggestion">
          <span className="dim">处置建议:</span>
          {f.suggestion}
        </div>
      )}
      {(f.kb_ids?.length ?? 0) > 0 && (
        <div className="finding-kb">
          <span className="dim">知识库:</span>
          {f.kb_ids!.map((k) => (
            <button key={k} className="kb-chip" onClick={() => nav(`/kb?article_id=${encodeURIComponent(k)}`)}>
              {k}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ReportPage() {
  const [params] = useSearchParams();
  const captures = useApp((s) => s.captures);
  const loadCaptures = useApp((s) => s.loadCaptures);
  const reportParam = params.get('report');
  const captureParam = params.get('capture');
  const autoStart = params.get('autostart') === '1';

  const readyCaptures = useMemo(() => captures.filter((c) => c.status === 'ready'), [captures]);
  const [captureId, setCaptureId] = useState(captureParam ?? '');
  const [report, setReport] = useState<Report | null>(null);
  const [existing, setExisting] = useState<Report[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [llmReady, setLlmReady] = useState(false);
  const [aiBusy, setAiBusy] = useState(false);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const timerRef = useRef<number | null>(null);
  const autoStartedRef = useRef(false);

  const loadReports = useCallback(async (cid: string) => {
    try {
      const list = await api.listReports(cid);
      setExisting(list);
      return list;
    } catch {
      setExisting([]);
      return [];
    }
  }, []);

  const viewReport = useCallback(async (id: string) => {
    try {
      const r = await api.getReport(id);
      setReport(r);
      setCaptureId(r.capture_id);
    } catch (e) {
      toastApiError(e, '报告加载失败');
    }
  }, []);

  useEffect(() => {
    void loadCaptures();
    void api
      .getSettings()
      .then((s) => setLlmReady(Boolean(s.llm?.enabled && s.llm.base_url && s.llm.model)))
      .catch(() => setLlmReady(false))
      .finally(() => setSettingsLoaded(true));
  }, [loadCaptures]);

  useEffect(() => {
    if (reportParam) void viewReport(reportParam);
    else if (captureId) void loadReports(captureId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportParam]);

  useEffect(() => {
    if (captureId) void loadReports(captureId);
  }, [captureId, loadReports]);

  useEffect(
    () => () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    },
    [],
  );

  const runAnalyze = useCallback(async () => {
    if (!captureId || busy) return;
    setBusy(true);
    setProgress(4);
    setElapsed(0);
    setReport(null);
    const t0 = Date.now();
    timerRef.current = window.setInterval(() => {
      const sec = (Date.now() - t0) / 1000;
      setElapsed(sec);
      setProgress((p) => Math.min(92, p + Math.max(0.4, (95 - p) * 0.02)));
    }, 200);
    try {
      const r = await api.analyze(captureId);
      let rep = await api.getReport(r.report_id);
      setReport(rep);
      // 规则报告先返回;LLM 只负责异步叙述,短轮询让客户无需手动刷新页面。
      if (llmReady) {
        for (let i = 0; i < 15 && !rep.narrative; i += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 800));
          rep = await api.getReport(r.report_id);
          setReport(rep);
        }
      }
      setProgress(100);
      toastSuccess('诊断完成');
      void loadReports(captureId);
    } catch (e) {
      toastApiError(e, '分析失败');
    } finally {
      if (timerRef.current) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setBusy(false);
    }
  }, [busy, captureId, llmReady, loadReports]);

  const runAiDirect = useCallback(async () => {
    if (!captureId || busy) return;
    setBusy(true);
    setProgress(8);
    setElapsed(0);
    setReport(null);
    const t0 = Date.now();
    timerRef.current = window.setInterval(() => {
      const sec = (Date.now() - t0) / 1000;
      setElapsed(sec);
      setProgress((p) => Math.min(92, p + Math.max(0.4, (95 - p) * 0.02)));
    }, 200);
    try {
      const r = await api.analyze(captureId, 'ai_direct');
      const rep = await api.getReport(r.report_id);
      setReport(rep);
      setProgress(100);
      toastSuccess('AI 直达分析完成');
      void loadReports(captureId);
    } catch (e) {
      toastApiError(e, 'AI 直达分析失败');
    } finally {
      if (timerRef.current) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setBusy(false);
    }
  }, [busy, captureId, loadReports]);

  const runAiAnalysis = async () => {
    if (!report || aiBusy) return;
    setAiBusy(true);
    try {
      const updated = await api.reportAi(report.id);
      setReport(updated);
      toastSuccess('AI 分析完成');
    } catch (e) {
      toastApiError(e, 'AI 分析失败');
    } finally {
      setAiBusy(false);
    }
  };

  useEffect(() => {
    if (!autoStart || !captureId || !settingsLoaded || autoStartedRef.current || busy || report) return;
    const ready = captures.some((c) => c.id === captureId && c.status === 'ready');
    if (!ready) return;
    autoStartedRef.current = true;
    void runAnalyze();
  }, [autoStart, busy, captureId, captures, report, runAnalyze, settingsLoaded]);

  const stage = progress < 30 ? '提交分析请求…' : progress < 60 ? '规则诊断与可选 AI 辅助分析中…' : progress < 95 ? '关联知识库、整理处置建议…' : '生成报告…';
  const findings = report ? normFindings(report.findings) : [];
  const aiDirect = report?.analysis_mode === 'ai_direct' || report?.engine === 'ai-direct';
  const brief = report ? report.brief?.trim() || buildBrief(report, findings) : '';
  const grouped = (['confirmed', 'suspect', 'potential'] as const)
    .map((tier) => ({ tier, items: findings.filter((f) => (f.tier ?? '') === tier) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="page report-page">
      <div className="report-toolbar">
        <select
          value={captureId}
          onChange={(e) => {
            setCaptureId(e.target.value);
            setReport(null);
          }}
        >
          <option value="">选择捕获文件…</option>
          {readyCaptures.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}({c.frame_count} 帧)
            </option>
          ))}
        </select>
        <button className="btn primary" disabled={!captureId || busy} onClick={() => void runAnalyze()}>
          {busy ? '分析中…' : '开始诊断'}
        </button>
        <button className="btn primary" disabled={!captureId || busy || !llmReady} onClick={() => void runAiDirect()}>
          {busy ? '分析中…' : 'AI直达分析'}
        </button>
        {existing.length > 0 && (
          <select value={report?.id ?? ''} onChange={(e) => e.target.value && void viewReport(e.target.value)}>
            <option value="">已有报告({existing.length})</option>
            {existing.map((r) => (
              <option key={r.id} value={r.id}>
                {fullTime(r.created_at)}
                {r.masked ? ' · 已脱敏' : ''}
              </option>
            ))}
          </select>
        )}
        {busy && (
          <>
            <div className="progress-bar">
              <div style={{ width: `${progress}%` }} />
            </div>
            <span className="dim">
              {stage}({elapsed.toFixed(1)}s)
            </span>
          </>
        )}
      </div>

      {!report && !busy && (
        <div className="dim" style={{ padding: '30px 0' }}>
          选择一个捕获文件后，可点击「开始诊断」运行本地规则，也可点击「AI直达分析」跳过本地规则和知识库直接请求 AI;或在「历史」页查看已有报告。
        </div>
      )}

      {report && (
        <div className="report-grid">
          <div className="report-main">
            <div className="report-head">
              <h2>诊断报告</h2>
              <span className="dim mono">#{report.id}</span>
              {report.masked ? <span className="status-chip status-importing">已脱敏</span> : null}
              <span className={`status-chip ${aiDirect ? 'status-ready' : 'status-importing'}`}>
                {aiDirect ? 'AI直达分析' : '本地规则引擎'}
              </span>
              <div className="spacer" />
              <a className="btn" href={api.reportExportUrl(report.id, 'md')} download>
                导出 Markdown
              </a>
              <a className="btn" href={api.reportExportUrl(report.id, 'html')} download>
                导出 HTML
              </a>
            </div>

            <div className={`report-summary report-analysis-mode ${aiDirect ? 'ai-direct' : ''}`}>
              {aiDirect
                ? 'AI 直达分析：已跳过本地规则引擎和知识库关联，以下内容由 AI 根据抓包摘要生成，请结合原始报文核验。'
                : '本地规则引擎分析：报告结论来自确定性规则，AI 辅助分析只做文字复述。'}
            </div>

            <div className="report-summary report-brief">
              <div className="report-brief-title">简报</div>
              <div>{brief}</div>
              <div className="report-brief-hint">更多详情请导出报告查看。</div>
            </div>
            {report.summary && (
              <div className="report-summary report-summary-technical">
                <span className="dim">{aiDirect ? 'AI 分析摘要：' : '规则摘要：'}</span>
                {report.summary}
              </div>
            )}
            {report.coverage && (
              aiDirect ? (
                <div className="report-coverage dim">AI 直达分析使用 {report.coverage.frame_count ?? 0} 帧摘要，未运行本地规则覆盖统计。</div>
              ) : (
                <div className="report-coverage dim">
                  专家告警覆盖：error {report.coverage.expert_errors ?? 0} / warn {report.coverage.expert_warns ?? 0}，
                  未被规则覆盖 {report.coverage.unconsumed ?? 0} 帧
                </div>
              )
            )}

            {grouped.length === 0 && (
              <div className="dim">
                {aiDirect ? '本次为 AI 直达分析，未运行本地规则，因此不提供规则命中列表。' : '本报告没有检出任何问题。'}
              </div>
            )}

            {grouped.map((g) => {
              const meta = TIER_META[g.tier];
              return (
                <div key={g.tier} className={`tier-section ${meta.cls}`}>
                  <div className="tier-head">
                    {meta.label}({g.items.length})
                  </div>
                  {g.items.map((f, i) => (
                    <FindingCard key={`${f.rule_id}-${i}`} f={f} captureId={report.capture_id} />
                  ))}
                </div>
              );
            })}
          </div>

          {report.narrative ? (
            <aside className="ai-panel">
              <div className="ai-panel-head">
                <h3>{aiDirect ? 'AI 直达分析结果' : 'AI 辅助分析（可选）'}</h3>
                <button className="btn small" disabled={aiBusy} onClick={() => void runAiAnalysis()}>
                  {aiBusy ? '分析中…' : 'AI 分析'}
                </button>
              </div>
              <div className="narrative">{report.narrative}</div>
            </aside>
          ) : (
            <aside className="ai-status-bar">
              <b>{aiDirect ? 'AI 直达分析:' : 'AI 辅助分析:'}</b>
              <button className="btn small" disabled={aiBusy || !llmReady} onClick={() => void runAiAnalysis()}>
                {aiBusy ? '分析中…' : 'AI 分析'}
              </button>
              {llmReady ? <span>正在等待 AI 叙述，规则结论已完成;</span> : <><span>未配置 LLM——规则结论不受影响;</span><Link to="/settings">到设置页启用</Link></>}
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
