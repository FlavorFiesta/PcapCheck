// 统一 fetch 封装:明确的中文错误提示;开发期可切换 mock(见 mock.ts)
import { mockEnabled, mockRequest } from './mock';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(message: string, status: number, detail = '') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function statusText(status: number, detail: string): string {
  if (status === 0) return `无法连接后端服务(127.0.0.1:8123)。请确认后端已启动(start.bat 或 uvicorn)。${detail}`;
  if (status === 400) return `请求参数错误:${detail || '请检查输入'}`;
  if (status === 404) return `资源不存在:${detail || '请确认捕获/报告是否存在'}`;
  if (status === 409) return `资源冲突:${detail}`;
  if (status === 413) return `文件过大,后端拒绝处理:${detail}`;
  if (status === 500) return `后端内部错误:${detail || '请查看后端日志'}`;
  if (status === 502 || status === 503) return `后端服务不可用(HTTP ${status}),请确认 uvicorn 正在运行。`;
  return `请求失败(HTTP ${status}):${detail}`;
}

interface ReqOpts {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

export async function request<T>(path: string, opts: ReqOpts = {}): Promise<T> {
  if (mockEnabled) return mockRequest<T>(path, opts);

  const method = opts.method ?? 'GET';
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    });
  } catch (e) {
    if ((e as Error)?.name === 'AbortError') throw e;
    throw new ApiError(statusText(0, ''), 0);
  }

  if (!res.ok) {
    let detail = '';
    try {
      const data: unknown = await res.json();
      if (data && typeof data === 'object') {
        const d = (data as Record<string, unknown>)['detail'];
        detail = typeof d === 'string' ? d : d !== undefined ? JSON.stringify(d) : JSON.stringify(data);
      } else if (typeof data === 'string') {
        detail = data;
      }
    } catch {
      detail = await res.text().catch(() => '');
    }
    throw new ApiError(statusText(res.status, detail.slice(0, 500)), res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    // 2xx 但不是 JSON:绝不能把 HTML/文本当数据塞进状态(会引发全树渲染崩溃)
    const ct = res.headers.get('content-type') ?? 'unknown';
    const snippet = text.replace(/\s+/g, ' ').trim().slice(0, 140);
    throw new ApiError(
      `后端返回了非 JSON 数据(HTTP ${res.status},Content-Type: ${ct})。常见原因:API 路由未注册,或被静态托管/SPA 回退拦截(回退需排除 /api 与 /ws)。响应片段:${snippet}`,
      res.status,
      text,
    );
  }
  return data as T;
}

export async function uploadFile<T>(path: string, file: File): Promise<T> {
  if (mockEnabled) return mockRequest<T>(path, {});
  const form = new FormData();
  form.append('file', file, file.name);
  let res: Response;
  try {
    res = await fetch(path, { method: 'POST', body: form });
  } catch {
    throw new ApiError(statusText(0, ''), 0);
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new ApiError(statusText(res.status, errText.slice(0, 300)), res.status, errText);
  }
  const text = await res.text();
  if (!text) return undefined as T;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    const ct = res.headers.get('content-type') ?? 'unknown';
    const snippet = text.replace(/\s+/g, ' ').trim().slice(0, 140);
    throw new ApiError(`后端返回了非 JSON 数据(HTTP ${res.status},Content-Type: ${ct})。响应片段:${snippet}`, res.status, text);
  }
  return data as T;
}
