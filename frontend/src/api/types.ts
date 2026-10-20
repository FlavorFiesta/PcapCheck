// 报文快速分析工具前后端契约类型(docs/api_contract.md v1)

export type CaptureStatus = 'importing' | 'ready' | 'error';

export interface CaptureMeta {
  id: string;
  name: string;
  path?: string;
  size?: number;
  frame_count: number;
  first_ts?: number;
  last_ts?: number;
  protocols?: string[] | string | null;
  created_at?: number;
  status: CaptureStatus;
  error?: string | null;
}

export interface ExpertItem {
  severity?: string | number;
  message?: string;
  group?: string;
}

/** frames 列表接口返回的行(与 SQLite frames 表对应) */
export interface FrameRow {
  no: number;
  ts: number;
  src: string;
  dst: string;
  sport?: number | null;
  dport?: number | null;
  proto: string;
  length: number;
  info: string;
  stream?: number | null;
  /** json 数组:["retransmission","zero_window",...] */
  analysis?: string[] | string | null;
  /** json 数组:[{severity,message,group}] */
  expert?: ExpertItem[] | string | null;
}

export interface FramesResp {
  total: number;
  frames: FrameRow[];
}

export interface FilterCompileResp {
  tshark_filter?: string;
  error?: string;
}

export type FindingTier = 'confirmed' | 'suspect' | 'potential';

export interface Finding {
  rule_id: string;
  tier: FindingTier;
  title: string;
  evidence_frames: number[];
  stats?: Record<string, unknown>;
  suggestion?: string;
  kb_ids?: string[];
}

export interface Report {
  id: string;
  capture_id: string;
  created_at?: number;
  engine?: string;
  /** rules 或 ai_direct;旧报告缺省按 rules 处理 */
  analysis_mode?: 'rules' | 'ai_direct' | string;
  /** 后端可能返回 json 字符串,前端统一 normalize */
  findings: Finding[] | string | null;
  brief?: string | null;
  summary?: string | null;
  narrative?: string | null;
  masked?: number | boolean;
  capture_name?: string;
  coverage?: {
    mode?: string;
    frame_count?: number;
    local_rules_skipped?: boolean;
    local_kb_skipped?: boolean;
    expert_errors?: number;
    expert_warns?: number;
    unconsumed?: number;
    unconsumed_frames?: number[];
    note?: string;
  } | null;
}

export interface LlmSettings {
  base_url?: string;
  api_key?: string;
  model?: string;
  enabled?: boolean;
}

export interface AppSettings {
  tshark_path?: string;
  llm?: LlmSettings;
  masking?: { enabled?: boolean };
  kb_dir?: string;
}

export interface KbArticle {
  id?: string;
  path?: string;
  file?: string;
  name?: string;
  title: string;
  rule_ids?: string[];
  protocols?: string[];
  symptoms?: string;
  severity?: string;
  content?: string;
}

export interface LiveInterface {
  idx: number | string;
  name: string;
  desc?: string;
}

export interface LiveStatus {
  running?: boolean;
  frame_count?: number;
  ifaces?: unknown;
  /** 临时 pcap 路径(命名不确定,做宽松匹配) */
  temp_pcap?: string;
  [k: string]: unknown;
}

export interface FollowMessage {
  no: number;
  ts: number;
  dir: 'c2s' | 's2c' | string;
  data: string;
  len: number;
}

export interface FollowResp {
  client: string;
  server: string;
  messages: FollowMessage[];
}

/** 协议分级节点(后端解析 tshark -z io,phs,字段名做兼容) */
export interface PhsNode {
  label: string;
  frames?: number;
  bytes?: number;
  percent_frames?: number;
  percent_bytes?: number;
  children?: PhsNode[];
}

export interface Conversation {
  src: string;
  sport?: number | null;
  dst: string;
  dport?: number | null;
  frames: number;
  bytes: number;
  frames_ab?: number;
  bytes_ab?: number;
  frames_ba?: number;
  bytes_ba?: number;
}

export interface IoPoint {
  t: number;
  frames: number;
  bytes: number;
}

export interface ImportResp {
  capture_id: string;
}

export interface AnalyzeResp {
  report_id: string;
}
