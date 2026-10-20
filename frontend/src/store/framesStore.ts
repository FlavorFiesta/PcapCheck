// 报文分页缓存 + 过滤器状态。
// 支撑几十万帧虚拟滚动:按 offset/limit 分页拉取,缓存已加载页,
// 滚动接近底部(可见范围 +400)时预取下一页,向上滚动回看命中缓存。
import { create } from 'zustand';
import { api } from '../api/endpoints';
import type { FrameRow } from '../api/types';

export const FRAME_PAGE_SIZE = 2000;

interface FramesState {
  captureId: string | null;
  filter: string;
  total: number;
  /** page 序号 -> 该页帧(offset = page * FRAME_PAGE_SIZE) */
  pages: Map<number, FrameRow[]>;
  pending: Set<number>;
  /** 请求失败过的页,避免滚动时无限重试 */
  failed: Set<number>;
  version: number;
  error: string | null;
  open: (captureId: string, filter?: string) => void;
  applyFilter: (filter: string) => void;
  ensurePage: (page: number) => void;
  ensureRange: (start: number, end: number) => void;
  getFrame: (index: number) => FrameRow | undefined;
}

let gen = 0;

export const useFrames = create<FramesState>()((set, get) => ({
  captureId: null,
  filter: '',
  total: 0,
  pages: new Map(),
  pending: new Set(),
  failed: new Set(),
  version: 0,
  error: null,

  open: (captureId, filter = get().filter) => {
    gen++;
    set({
      captureId,
      filter,
      total: 0,
      pages: new Map(),
      pending: new Set(),
      failed: new Set(),
      error: null,
      version: get().version + 1,
    });
    get().ensurePage(0);
  },

  applyFilter: (filter) => {
    const cid = get().captureId;
    if (!cid) {
      set({ filter });
      return;
    }
    get().open(cid, filter);
  },

  ensurePage: (page) => {
    const s = get();
    if (page < 0) return;
    if (s.pages.has(page) || s.pending.has(page) || s.failed.has(page)) return;
    if (s.total > 0 && page * FRAME_PAGE_SIZE >= s.total) return;
    const cid = s.captureId;
    if (!cid) return;
    s.pending.add(page);
    const myGen = gen;
    const usedFilter = s.filter;
    api
      .frames(cid, page * FRAME_PAGE_SIZE, FRAME_PAGE_SIZE, usedFilter)
      .then((res) => {
        if (myGen !== gen) return;
        set((st) => {
          st.pages.set(page, res.frames);
          st.pending.delete(page);
          return { total: res.total, version: st.version + 1 };
        });
      })
      .catch((e: unknown) => {
        if (myGen !== gen) return;
        const msg = e instanceof Error ? e.message : String(e);
        set((st) => {
          st.pending.delete(page);
          st.failed.add(page);
          return { error: msg, version: st.version + 1 };
        });
      });
  },

  ensureRange: (start, end) => {
    const s = get();
    if (s.total <= 0) return;
    const a = Math.max(0, Math.min(start, s.total - 1));
    const b = Math.max(0, Math.min(end, s.total - 1));
    const p0 = Math.floor(a / FRAME_PAGE_SIZE);
    const p1 = Math.floor(b / FRAME_PAGE_SIZE);
    for (let p = p0; p <= p1; p++) get().ensurePage(p);
  },

  getFrame: (index) => {
    if (index < 0) return undefined;
    const s = get();
    const page = Math.floor(index / FRAME_PAGE_SIZE);
    const arr = s.pages.get(page);
    if (!arr) return undefined;
    return arr[index - page * FRAME_PAGE_SIZE];
  },
}));
