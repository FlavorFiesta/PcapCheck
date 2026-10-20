// 协议树详情(两种形状自动适配):
// - 新形状:{"no":N,"tree":[{label, value?, children?: [...]}]} —— 后端协议字段树;
//   Wireshark 风格:层级缩进线、行高紧凑、label 全文展示、点击字段行复制文本、箭头折叠。
// - 旧形状:tshark -T json 原始信封([{_source:{layers:{...}}}] / {layers} / 裸 layers),自动降级为原渲染。
import { useEffect, useState } from 'react';
import { api } from '../api/endpoints';
import { toastError, toastSuccess } from './toast';

interface PNode {
  label: string;
  value?: string;
  children?: PNode[];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** 新形状检测:{"no":N,"tree":[...]} */
export function isTreeEnvelope(data: unknown): boolean {
  const rec = asRecord(data);
  return rec !== null && Array.isArray(rec['tree']);
}

/** 新形状节点归一:label 必有;value/children 可选;空 children 视为叶子 */
export function normTreeNode(v: unknown): PNode | null {
  const rec = asRecord(v);
  if (!rec) return null;
  const label = typeof rec['label'] === 'string' ? rec['label'] : '';
  if (!label) return null;
  const value = typeof rec['value'] === 'string' && rec['value'].length > 0 ? rec['value'] : undefined;
  const rawKids = rec['children'];
  if (Array.isArray(rawKids)) {
    const kids = rawKids.map(normTreeNode).filter((x): x is PNode => x !== null);
    if (kids.length > 0) return { label, value, children: kids };
  }
  return { label, value };
}

/** 旧形状:兼容三种返回形态:[{..._source.layers}] / {layers} / 直接是 layers */
function extractLayers(data: unknown): Record<string, unknown> {
  let cur: unknown = data;
  if (Array.isArray(cur)) cur = cur[0];
  const rec = asRecord(cur);
  if (!rec) return {};
  const src = asRecord(rec['_source']);
  if (src) {
    const layers = asRecord(src['layers']);
    if (layers) return layers;
  }
  const layers = asRecord(rec['layers']);
  if (layers) return layers;
  return rec;
}

function toNode(key: string, val: unknown): PNode {
  if (val === null || val === undefined) return { label: key, value: '' };
  if (typeof val !== 'object') return { label: key, value: String(val) };
  if (Array.isArray(val)) {
    if (val.every((x) => x === null || typeof x !== 'object')) {
      return { label: key, value: val.map((x) => String(x)).join(', ') };
    }
    const children: PNode[] = [];
    val.forEach((x) => {
      const rec = asRecord(x);
      if (rec) {
        for (const [k, v] of Object.entries(rec)) children.push(toNode(k, v));
      } else {
        children.push({ label: String(x) });
      }
    });
    return { label: key, children };
  }
  const rec = asRecord(val);
  if (rec) {
    return { label: key, children: Object.entries(rec).map(([k, v]) => toNode(k, v)) };
  }
  return { label: key, value: String(val) };
}

function buildTree(layers: Record<string, unknown>): PNode[] {
  return Object.entries(layers).map(([k, v]) => toNode(k, v));
}

export function TreeNode({ node, depth }: { node: PNode; depth: number }) {
  const [open, setOpen] = useState(depth < 3);
  const hasChildren = !!node.children?.length;
  const copyText = node.value !== undefined ? `${node.label}: ${node.value}` : node.label;

  const copy = () => {
    if (!navigator.clipboard) {
      toastError('当前环境不支持剪贴板访问');
      return;
    }
    navigator.clipboard
      .writeText(copyText)
      .then(() => toastSuccess('已复制字段文本'))
      .catch(() => toastError('复制失败'));
  };

  return (
    <div className="ptree-branch">
      <div
        className="ptree-row"
        title="点击复制字段文本;展开/折叠请点左侧箭头"
        onClick={(e) => {
          e.stopPropagation();
          copy();
        }}
      >
        <span
          className={`tw${hasChildren ? (open ? ' open' : '') : ' leaf'}`}
          title={hasChildren ? '展开/折叠' : undefined}
          onClick={(e) => {
            if (hasChildren) {
              e.stopPropagation();
              setOpen(!open);
            }
          }}
        />
        <span className="ptree-label">{node.label}</span>
        {node.value !== undefined && node.value !== '' && <span className="ptree-value">{node.value}</span>}
      </div>
      {hasChildren && open && (
        <div className="ptree-children">
          {node.children!.map((c, i) => (
            <TreeNode key={i} node={c} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

interface Props {
  captureId: string;
  frameNo: number | null;
}

export default function ProtocolTree({ captureId, frameNo }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tree, setTree] = useState<PNode[] | null>(null);
  const [isNewShape, setIsNewShape] = useState(false);

  useEffect(() => {
    if (frameNo == null) {
      setTree(null);
      setError(null);
      setLoading(false);
      return;
    }
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    api
      .frameDetail(captureId, frameNo, ctrl.signal)
      .then((d) => {
        if (isTreeEnvelope(d)) {
          // 新形状:{"no":N,"tree":[...]}
          const rec = asRecord(d)!;
          setIsNewShape(true);
          setTree((rec['tree'] as unknown[]).map(normTreeNode).filter((x): x is PNode => x !== null));
        } else {
          // 旧形状:tshark -T json 原始信封,自动降级
          setIsNewShape(false);
          setTree(buildTree(extractLayers(d)));
        }
        setLoading(false);
      })
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      });
    return () => ctrl.abort();
  }, [captureId, frameNo]);

  return (
    <div className="pane ptree-pane">
      <div className="pane-title">
        {frameNo != null ? `帧 ${frameNo} · ${isNewShape ? '协议字段树' : '协议树(原始解码)'}` : '协议树(点击列表选择帧)'}
      </div>
      <div className="ptree-body mono">
        {loading ? (
          <div className="dim" style={{ padding: 8 }}>
            加载中…
          </div>
        ) : error ? (
          <div className="err-text" style={{ padding: 8 }}>
            加载失败:{error}
          </div>
        ) : tree && tree.length > 0 ? (
          tree.map((n, i) => <TreeNode key={i} node={n} depth={0} />)
        ) : (
          <div className="dim" style={{ padding: 8 }}>
            在上方列表中选择一个报文查看协议树
          </div>
        )}
      </div>
    </div>
  );
}
