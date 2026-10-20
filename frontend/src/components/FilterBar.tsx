// 过滤器条:预设按钮组 + 极简表达式输入(POST /api/filter/compile 预检)
import { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { FILTER_PRESETS } from '../api/presets';
import { useFrames } from '../store/framesStore';
import { toastApiError } from './toast';

export default function FilterBar() {
  const filter = useFrames((s) => s.filter);
  const applyFilter = useFrames((s) => s.applyFilter);
  const total = useFrames((s) => s.total);
  const error = useFrames((s) => s.error);

  const [draft, setDraft] = useState(filter);
  const [compileHint, setCompileHint] = useState<string | null>(null);
  const [preErr, setPreErr] = useState<string | null>(null);

  // 外部(上下文菜单/预设)改变过滤器时同步输入框
  useEffect(() => {
    setDraft(filter);
  }, [filter]);

  const apply = async (expr: string) => {
    const e = expr.trim();
    if (!e) {
      setPreErr(null);
      setCompileHint(null);
      applyFilter('');
      return;
    }
    try {
      const r = await api.compileFilter(e);
      if (r.error) {
        setPreErr(r.error);
        toastApiError(new Error(r.error), '过滤器预检失败');
        return;
      }
      setPreErr(null);
      setCompileHint(r.tshark_filter ?? '');
      applyFilter(e);
    } catch (err) {
      setPreErr(err instanceof Error ? err.message : String(err));
    }
  };

  const activePreset = FILTER_PRESETS.find((p) => p.expr === filter);

  return (
    <div className="filter-bar">
      <div className="preset-group">
        {FILTER_PRESETS.map((p) => (
          <button
            key={p.key}
            className={`preset${(activePreset?.key ?? 'all') === p.key ? ' active' : ''}`}
            title={p.expr ? `filter:${p.expr}` : '显示全部报文'}
            onClick={() => {
              setCompileHint(null);
              setPreErr(null);
              setDraft(p.expr);
              applyFilter(p.expr);
            }}
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className={`filter-input-wrap${preErr ? ' has-error' : ''}`}>
        <span className="filter-label">过滤</span>
        <input
          className="mono"
          value={draft}
          placeholder={'极简表达式:ip==1.2.3.4 / port==443 / proto==tcp / stream==5 / contains "xx",支持 && || !(回车应用)'}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void apply(draft);
          }}
        />
        {compileHint !== null && (
          <span className="compile-hint mono" title="后端编译出的 tshark 显示过滤器">
            → {compileHint}
          </span>
        )}
      </div>

      {preErr ? (
        <span className="filter-err" title={preErr}>
          {preErr}
        </span>
      ) : error ? (
        <span className="filter-err" title={error}>
          {error}
        </span>
      ) : (
        <span className="dim shown-count mono num">{total > 0 ? `${total.toLocaleString('en-US')} 帧` : ''}</span>
      )}
    </div>
  );
}
