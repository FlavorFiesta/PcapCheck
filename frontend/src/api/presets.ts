// 预设过滤器按钮组。
// 契约内建表达式:ip==/port==/proto==/contains/stream==。
// 预设额外使用以下扩展记号(依据 frames.analysis / flags / 协议语义,
// 由后端编译为 tshark display filter;若后端尚未支持,frames 接口会报错并提示):
//   analysis==retransmission|out_of_order|zero_window  —— tcp.analysis.*
//   flag==rst                                          —— tcp.flags.reset
//   dns==fail / tls==alert / http==5xx                 —— DNS rcode!=0 / TLS alert / HTTP 5xx
export interface FilterPreset {
  key: string;
  label: string;
  expr: string;
}

export const FILTER_PRESETS: FilterPreset[] = [
  { key: 'all', label: '全部', expr: '' },
  { key: 'retrans', label: '重传', expr: 'analysis==retransmission' },
  { key: 'dnsfail', label: 'DNS失败', expr: 'dns==fail' },
  { key: 'tlsalert', label: 'TLS告警', expr: 'tls==alert' },
  { key: 'http5xx', label: 'HTTP 5xx', expr: 'http==5xx' },
  { key: 'rst', label: 'RST', expr: 'flag==rst' },
  { key: 'zerowin', label: '零窗口', expr: 'analysis==zero_window' },
  { key: 'ooo', label: '乱序', expr: 'analysis==out_of_order' },
];
