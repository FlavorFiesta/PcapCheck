// 知识库页:文章列表 + Markdown 渲染(marked),支持按规则 ID 筛选
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { marked } from 'marked';
import { api } from '../api/endpoints';
import type { KbArticle } from '../api/types';
import { toastApiError } from '../components/toast';

function stripFrontmatter(md: string): string {
  return md.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '');
}

function articleId(a: KbArticle): string {
  return a.id ?? a.path ?? a.file ?? a.name ?? a.title;
}

export default function KbPage() {
  const [params, setParams] = useSearchParams();
  const ruleParam = params.get('rule_id') ?? '';
  const articleParam = params.get('article_id') ?? '';
  const [ruleInput, setRuleInput] = useState(ruleParam);
  const [articles, setArticles] = useState<KbArticle[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [current, setCurrent] = useState<KbArticle | null>(null);
  const [html, setHtml] = useState('');
  const [loadingContent, setLoadingContent] = useState(false);

  useEffect(() => {
    setRuleInput(ruleParam);
  }, [ruleParam]);

  useEffect(() => {
    let alive = true;
    setArticles(null);
    setError(null);
    api
      .kbArticles(ruleParam || undefined)
      .then((a) => {
        if (!alive) return;
        setArticles(Array.isArray(a) ? a : a && typeof a === 'object' ? [a as KbArticle] : []);
      })
      .catch((e: unknown) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, [ruleParam]);

  const open = async (a: KbArticle) => {
    setCurrent(a);
    setLoadingContent(true);
    setHtml('');
    try {
      let content = a.content;
      if (!content) {
        const id = articleId(a);
        if (id && id !== a.title) {
          try {
            const one = await api.kbArticleById(id);
            if (one?.content) {
              content = one.content;
              setCurrent(one);
            }
          } catch {
            /* 尝试下一种方式 */
          }
        }
      }
      if (!content && a.rule_ids?.length) {
        try {
          const list = await api.kbArticles(a.rule_ids[0]);
          const hit = (Array.isArray(list) ? list : []).find((x) => articleId(x) === articleId(a) && x.content);
          if (hit?.content) content = hit.content;
        } catch {
          /* 忽略 */
        }
      }
      if (!content) {
        setHtml('<p class="dim">未能获取文章正文(后端未提供内容)。</p>');
      } else {
        setHtml(marked.parse(stripFrontmatter(content), { async: false }) as string);
      }
    } catch (e) {
      toastApiError(e, '文章加载失败');
      setHtml('<p class="err-text">文章加载失败。</p>');
    } finally {
      setLoadingContent(false);
    }
  };

  useEffect(() => {
    if (!articleParam) return;
    let alive = true;
    setLoadingContent(true);
    api
      .kbArticleById(articleParam)
      .then((article) => {
        if (!alive) return;
        if (!article) {
          setHtml('<p class="dim">文章不存在。</p>');
          return;
        }
        setCurrent(article);
        setHtml(marked.parse(stripFrontmatter(article.content ?? ''), { async: false }) as string);
      })
      .catch((e: unknown) => alive && toastApiError(e, '文章加载失败'))
      .finally(() => alive && setLoadingContent(false));
    return () => {
      alive = false;
    };
  }, [articleParam]);

  // 有 rule_id 查询时自动打开第一篇
  useEffect(() => {
    if (articles && articles.length > 0 && !current && !articleParam) void open(articles[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [articles]);

  return (
    <div className="kb-layout">
      <div className="kb-list">
        <div className="kb-list-head">
          <input
            placeholder="按规则 ID 筛选,如 R01"
            value={ruleInput}
            onChange={(e) => setRuleInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setParams(ruleInput.trim() ? { rule_id: ruleInput.trim() } : {});
            }}
          />
          <button className="btn small" onClick={() => setParams(ruleInput.trim() ? { rule_id: ruleInput.trim() } : {})}>
            筛选
          </button>
          {ruleParam && (
            <button className="btn small" onClick={() => setParams({})}>
              清除
            </button>
          )}
        </div>
        {error ? (
          <div className="err-text" style={{ padding: 10 }}>
            {error}
          </div>
        ) : !articles ? (
          <div className="dim" style={{ padding: 10 }}>
            加载中…
          </div>
        ) : articles.length === 0 ? (
          <div className="dim" style={{ padding: 10 }}>
            没有匹配的文章。
          </div>
        ) : (
          articles.map((a, i) => (
            <div
              key={articleId(a) + i}
              className={`kb-item${current && articleId(current) === articleId(a) ? ' active' : ''}`}
              onClick={() => void open(a)}
            >
              <div className="kb-title">{a.title}</div>
              <div className="kb-meta">
                {(a.rule_ids ?? []).map((r) => (
                  <span key={r} className="rule-chip mono">
                    {r}
                  </span>
                ))}
                {a.severity ? <span className="dim">{a.severity}</span> : null}
              </div>
            </div>
          ))
        )}
      </div>
      <div className="kb-content">
        {loadingContent ? (
          <div className="dim">加载中…</div>
        ) : current ? (
          <>
            <h2 className="kb-article-title">{current.title}</h2>
            <div className="article" dangerouslySetInnerHTML={{ __html: html }} />
          </>
        ) : (
          <div className="dim">从左侧选择一篇文章</div>
        )}
      </div>
    </div>
  );
}
