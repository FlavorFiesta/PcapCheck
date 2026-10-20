// 时间 / 字节 / 地址格式化(等宽数字、高信息密度)
export function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/**
 * 帧绝对时间:一律 UTC 渲染并标注,与协议树(tshark 纪元口径)一致,
 * 避免本地时区把 epoch 0 显示成 08:00:00 这类歧义。
 */
export function absTime(ts: number): string {
  if (!Number.isFinite(ts)) return '-';
  const d = new Date(ts * 1000);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(
    d.getUTCMinutes(),
  )}:${pad2(d.getUTCSeconds())}.${String(d.getUTCMilliseconds()).padStart(3, '0')} UTC`;
}

/** 完整时间(报告/历史生成时间):与 absTime 同一口径,单一 UTC 串,禁止再拼日期 */
export function fullTime(ts: number | undefined | null): string {
  if (ts === undefined || ts === null || !Number.isFinite(ts)) return '-';
  return absTime(ts);
}

/** 相对时间(相对 first_ts),Wireshark 风格 6 位小数秒 */
export function relTime(ts: number, firstTs?: number): string {
  const base = typeof firstTs === 'number' && Number.isFinite(firstTs) ? firstTs : undefined;
  const v = base === undefined ? ts : ts - base;
  return Number.isFinite(v) ? v.toFixed(6) : '-';
}

export function fmtBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 || v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function fmtNum(n: number | undefined | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '-';
  return n.toLocaleString('en-US');
}

export function addrPort(addr: string | null | undefined, port: number | null | undefined): string {
  const a = addr ?? '';
  return port !== null && port !== undefined ? `${a}:${port}` : a;
}
