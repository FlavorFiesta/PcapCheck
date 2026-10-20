// REST 接口封装(与 docs/api_contract.md 一一对应)。
// 所有列表/分页接口在此做形状归一:后端返回包装对象或意外形状时降级为空列表并告警,
// 绝不把异常形状灌进组件状态(防全树渲染崩溃)。
import { request, uploadFile } from './client';
import type {
  AnalyzeResp,
  AppSettings,
  CaptureMeta,
  Conversation,
  FilterCompileResp,
  FollowMessage,
  FollowResp,
  FrameRow,
  FramesResp,
  ImportResp,
  IoPoint,
  KbArticle,
  LiveInterface,
  LiveStatus,
  Report,
} from './types';

function asObject(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' ? (v as Record<string, unknown>) : {};
}

function asArray<T>(v: unknown, what: string): T[] {
  if (Array.isArray(v)) return v as T[];
  if (v !== null && typeof v === 'object') {
    const rec = v as Record<string, unknown>;
    for (const k of ['items', 'data', 'list', 'rows', 'captures', 'reports', 'articles', 'interfaces', 'conversations']) {
      if (Array.isArray(rec[k])) return rec[k] as T[];
    }
  }
  console.warn(`[报文快速分析工具] ${what} 返回的不是数组,已按空列表处理:`, v);
  return [];
}

export const api = {
  // ---- 捕获 ----
  listCaptures: async (): Promise<CaptureMeta[]> =>
    asArray<CaptureMeta>(await request<unknown>('/api/captures'), '/api/captures'),
  getCapture: async (id: string): Promise<CaptureMeta | null> => {
    const m = await request<unknown>(`/api/captures/${encodeURIComponent(id)}`);
    return m !== null && typeof m === 'object' ? (m as CaptureMeta) : null;
  },
  deleteCapture: (id: string) => request<void>(`/api/captures/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  importByPath: (path: string) => request<ImportResp>('/api/captures/import', { method: 'POST', body: { path } }),
  uploadCapture: (file: File) => uploadFile<ImportResp>('/api/captures/upload', file),

  // ---- 报文 ----
  frames: async (
    id: string,
    offset: number,
    limit: number,
    filter: string,
    signal?: AbortSignal,
  ): Promise<FramesResp> => {
    const res = await request<unknown>(
      `/api/captures/${encodeURIComponent(id)}/frames?offset=${offset}&limit=${limit}${filter ? `&filter=${encodeURIComponent(filter)}` : ''}`,
      { signal },
    );
    if (Array.isArray(res)) return { total: res.length, frames: res as FrameRow[] };
    const rec = asObject(res);
    const frames = Array.isArray(rec['frames']) ? (rec['frames'] as FrameRow[]) : [];
    const total = typeof rec['total'] === 'number' ? (rec['total'] as number) : frames.length;
    return { total, frames };
  },
  frameDetail: (id: string, no: number, signal?: AbortSignal) =>
    request<unknown>(`/api/captures/${encodeURIComponent(id)}/frames/${no}/detail`, { signal }),

  // ---- 统计 ----
  statsPhs: (id: string, signal?: AbortSignal) =>
    request<unknown>(`/api/captures/${encodeURIComponent(id)}/stats/phs`, { signal }),
  statsIo: async (id: string, interval: number, signal?: AbortSignal): Promise<IoPoint[]> =>
    asArray<IoPoint>(
      await request<unknown>(`/api/captures/${encodeURIComponent(id)}/stats/io?interval=${interval}`, { signal }),
      '/stats/io',
    ),
  statsConversations: async (id: string, proto: string, signal?: AbortSignal): Promise<Conversation[]> =>
    asArray<Conversation>(
      await request<unknown>(`/api/captures/${encodeURIComponent(id)}/stats/conversations?proto=${proto}`, { signal }),
      '/stats/conversations',
    ),
  follow: async (id: string, stream: number, proto: 'tcp' | 'udp', signal?: AbortSignal): Promise<FollowResp> => {
    const r = await request<unknown>(`/api/captures/${encodeURIComponent(id)}/follow/${stream}?proto=${proto}`, {
      signal,
    });
    const rec = asObject(r);
    return {
      client: typeof rec['client'] === 'string' ? rec['client'] : '',
      server: typeof rec['server'] === 'string' ? rec['server'] : '',
      messages: asArray<FollowMessage>(rec['messages'], '/follow messages'),
    };
  },

  // ---- 过滤 ----
  compileFilter: (expr: string) => request<FilterCompileResp>('/api/filter/compile', { method: 'POST', body: { expr } }),

  // ---- 诊断 ----
  analyze: (id: string, mode: 'rules' | 'ai_direct' = 'rules') =>
    request<AnalyzeResp>(`/api/captures/${encodeURIComponent(id)}/analyze?mode=${mode}`, { method: 'POST' }),
  listReports: async (captureId?: string): Promise<Report[]> =>
    asArray<Report>(
      await request<unknown>(`/api/reports${captureId ? `?capture_id=${encodeURIComponent(captureId)}` : ''}`),
      '/api/reports',
    ),
  getReport: (id: string) => request<Report>(`/api/reports/${encodeURIComponent(id)}`),
  reportAi: (id: string) => request<Report>(`/api/reports/${encodeURIComponent(id)}/ai`, { method: 'POST' }),
  deleteReport: (id: string) => request<{ deleted: string }>(`/api/reports/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  reportExportUrl: (id: string, format: 'md' | 'html') => `/api/reports/${encodeURIComponent(id)}/export?format=${format}`,

  // ---- 设置 ----
  getSettings: () => request<AppSettings>('/api/settings'),
  putSettings: (s: AppSettings) => request<AppSettings>('/api/settings', { method: 'PUT', body: s }),
  testLlm: (s: AppSettings) => request<{ ok: boolean; reply?: string }>('/api/llm/test', { method: 'POST', body: s }),

  // ---- 知识库 ----
  kbArticles: async (ruleId?: string): Promise<KbArticle[]> =>
    asArray<KbArticle>(
      await request<unknown>(`/api/kb/articles${ruleId ? `?rule_id=${encodeURIComponent(ruleId)}` : ''}`),
      '/api/kb/articles',
    ),
  kbArticleById: async (id: string): Promise<KbArticle | null> => {
    const a = await request<unknown>(`/api/kb/articles/${encodeURIComponent(id)}`);
    return a !== null && typeof a === 'object' ? (a as KbArticle) : null;
  },

  // ---- 实时抓包 ----
  liveInterfaces: async (): Promise<LiveInterface[]> =>
    asArray<LiveInterface>(await request<unknown>('/api/live/interfaces'), '/api/live/interfaces'),
  liveStart: (iface: string, snaplen?: number) =>
    request<void>('/api/live/start', { method: 'POST', body: { iface, ...(snaplen ? { snaplen } : {}) } }),
  liveStop: () => request<void>('/api/live/stop', { method: 'POST' }),
  liveStatus: async (): Promise<LiveStatus> => {
    const s = await request<unknown>('/api/live/status');
    return asObject(s) as LiveStatus;
  },
  /** 后端若未实现该入口会 404,由调用方降级到 status -> import */
  liveAnalyze: () => request<ImportResp>('/api/live/analyze', { method: 'POST' }),
};
