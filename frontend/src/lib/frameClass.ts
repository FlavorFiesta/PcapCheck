// 异常帧着色分类(依据 frames 返回的 analysis / expert 字段)
// 约定:重传类橙红、RST 红、零窗口红、乱序黄、DNS 失败红、TLS 告警红、HTTP 5xx 红
import type { ExpertItem, FrameRow } from '../api/types';

export interface FrameClass {
  cls: string | null;
  label: string | null;
}

/** analysis/expert 后端可能给数组也可能给 json 字符串,统一成 string[] */
export function toStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x));
  if (typeof v === 'string' && v.length > 0) {
    try {
      const parsed: unknown = JSON.parse(v);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
      /* 普通字符串 */
    }
    return [v];
  }
  return [];
}

export function expertItems(v: unknown): ExpertItem[] {
  let arr: unknown[] = [];
  if (Array.isArray(v)) arr = v;
  else if (typeof v === 'string' && v.length > 0) {
    try {
      const parsed: unknown = JSON.parse(v);
      if (Array.isArray(parsed)) arr = parsed;
    } catch {
      arr = [];
    }
  }
  return arr.filter((x): x is ExpertItem => x !== null && typeof x === 'object');
}

function expertInfo(v: unknown): { text: string; hasError: boolean } {
  const items = expertItems(v);
  let text = '';
  let hasError = false;
  for (const e of items) {
    text += ` ${e.message ?? ''} ${e.group ?? ''}`;
    const sev = String(e.severity ?? '');
    const n = Number(sev);
    if (/error/i.test(sev) || (Number.isFinite(n) && n >= 4194304)) hasError = true;
  }
  return { text: text.toLowerCase(), hasError };
}

const RED = 'row-error';
const ORANGE = 'row-retrans';
const YELLOW = 'row-ooo';

export function classifyFrame(f: FrameRow): FrameClass {
  const a = toStringArray(f.analysis).map((x) => x.toLowerCase());
  const has = (...keys: string[]) => a.some((x) => keys.some((k) => x.includes(k)));
  const ex = expertInfo(f.expert);
  const proto = (f.proto ?? '').toUpperCase();
  const hay = `${ex.text} ${f.info ?? ''}`.toLowerCase();

  if (has('rst') || /\brst\b|connection reset/.test(ex.text)) return { cls: RED, label: 'RST' };
  if (has('zero_window', 'window_full')) return { cls: RED, label: '零窗口' };
  if (has('dns_fail', 'dns_failure') || (proto === 'DNS' && /servfail|nxdomain|rcode|fail/.test(ex.text))) {
    return { cls: RED, label: 'DNS失败' };
  }
  if (has('tls_alert') || /tls alert|alert \(level/.test(hay)) return { cls: RED, label: 'TLS告警' };
  if (has('http_5xx', 'http_5xx_error') || (proto === 'HTTP' && /http\/1\.[01]\s+5\d{2}|\b5\d{2}\s+(internal|bad|not found|forbidden|service)/.test(hay))) {
    return { cls: RED, label: 'HTTP 5xx' };
  }
  if (has('retransmission', 'fast_retransmission', 'spurious_retransmission')) return { cls: ORANGE, label: '重传' };
  if (has('out_of_order')) return { cls: YELLOW, label: '乱序' };
  if (has('duplicate_ack', 'lost_segment', 'ack_lost_segment')) return { cls: YELLOW, label: '重复ACK/丢包' };
  if (ex.hasError) return { cls: RED, label: '专家告警' };
  return { cls: null, label: null };
}
