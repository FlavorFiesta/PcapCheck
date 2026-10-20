// 历史报告页:列表 + 前端过滤(文件名/日期/故障类型)
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/endpoints';
import type { Finding, Report } from '../api/types';
import { fmtNum, fullTime, pad2 } from '../lib/format';
import { useApp } from '../store/appStore';

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

export default function HistoryPage() {
  const nav = useNavigate();
  const captures = useApp((s) => s.captures);
  const loadCaptures = useApp((s) => s.loadCaptures);
  const [reports, setReports] = useState<Report[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nameF, setNameF] = useState('');
  const [dateF, setDateF] = useState('');
  const [typeF, setTypeF] = useState('');

  useEffect(() => {
    void loadCaptures();
    api
      .listReports()
      .then((r) => setReports(r))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [loadCaptures]);

  const rows = useMemo(() => {
    const list = (reports ?? []).map((r) => ({ report: r, findings: normFindings(r.findings) }));
    const nameOf = (r: Report) => r.capture_name ?? captures.find((c) => c.id === r.capture_id)?.name ?? r.capture_id;
    return list
      .filter(({ report: r, findings }) => {
        if (nameF && !nameOf(r).toLowerCase().includes(nameF.toLowerCase())) return false;
        if (dateF) {
          const d = new Date((r.created_at ?? 0) * 1000);
          const day = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
          if (day !== dateF) return false;
        }
        if (typeF) {
          const t = typeF.toLowerCase();
          const hit = findings.some(
            (f) => f.rule_id.toLowerCase().includes(t) || (f.title ?? '').toLowerCase().includes(t),
          );
          if (!hit) return false;
        }
        return true;
      })
      .sort((a, b) => (b.report.created_at ?? 0) - (a.report.created_at ?? 0));
  }, [reports, captures, nameF, dateF, typeF]);

  const tierCount = (fs: Finding[], tier: string) => fs.filter((f) => f.tier === tier).length;

  const deleteReport = async (id: string) => {
    if (!window.confirm('确定删除这份历史报告吗？对应抓包文件不会删除。')) return;
    try {
      await api.deleteReport(id);
      setReports((current) => (current ?? []).filter((r) => r.id !== id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="page history-page">
      <h2>历史报告</h2>
      <div className="history-toolbar">
        <input placeholder="按文件名过滤" value={nameF} onChange={(e) => setNameF(e.target.value)} />
        <input type="date" value={dateF} onChange={(e) => setDateF(e.target.value)} title="按日期过滤" />
        <input
          placeholder="按故障类型过滤(如 R01 / 重传)"
          value={typeF}
          onChange={(e) => setTypeF(e.target.value)}
          style={{ width: 240 }}
        />
        {(nameF || dateF || typeF) && (
          <button
            className="btn small"
            onClick={() => {
              setNameF('');
              setDateF('');
              setTypeF('');
            }}
          >
            清除
          </button>
        )}
      </div>

      {error ? (
        <div className="err-text">{error}</div>
      ) : !reports ? (
        <div className="dim">加载中…</div>
      ) : rows.length === 0 ? (
        <div className="dim">没有符合条件的报告。</div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>捕获文件</th>
              <th>引擎</th>
              <th>规则命中</th>
              <th>确诊</th>
              <th>疑似</th>
              <th>潜在</th>
              <th>脱敏</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ report: r, findings }) => (
              <tr key={r.id} className="row-click" onClick={() => nav(`/report?report=${r.id}`)}>
                <td className="mono">{fullTime(r.created_at)}</td>
                <td>{r.capture_name ?? captures.find((c) => c.id === r.capture_id)?.name ?? r.capture_id}</td>
                <td className="mono">{r.engine ?? '-'}</td>
                <td className="num">{fmtNum(findings.length)}</td>
                <td className="num tier-confirmed-text">{tierCount(findings, 'confirmed')}</td>
                <td className="num tier-suspect-text">{tierCount(findings, 'suspect')}</td>
                <td className="num tier-potential-text">{tierCount(findings, 'potential')}</td>
                <td>{r.masked ? '是' : '否'}</td>
                <td>
                  <button
                    className="btn small"
                    onClick={(e) => {
                      e.stopPropagation();
                      nav(`/report?report=${r.id}`);
                    }}
                  >
                    查看
                  </button>
                  <button
                    className="btn small"
                    onClick={(e) => {
                      e.stopPropagation();
                      void deleteReport(r.id);
                    }}
                  >
                    删除
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
