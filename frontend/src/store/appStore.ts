// 全局应用状态:捕获列表、当前捕获、后端连通状态
import { create } from 'zustand';
import { api } from '../api/endpoints';
import { toastApiError } from '../components/toast';
import type { CaptureMeta } from '../api/types';

interface AppState {
  captures: CaptureMeta[];
  capturesLoaded: boolean;
  currentId: string | null;
  meta: CaptureMeta | null;
  metaLoading: boolean;
  /** 最近一次请求是否连通后端(false 表示后端不可达) */
  backendOk: boolean;
  loadCaptures: () => Promise<void>;
  setCurrent: (id: string | null) => void;
  refreshMeta: (id?: string) => Promise<CaptureMeta | null>;
}

export const useApp = create<AppState>()((set, get) => ({
  captures: [],
  capturesLoaded: false,
  currentId: null,
  meta: null,
  metaLoading: false,
  backendOk: true,

  loadCaptures: async () => {
    try {
      const list = await api.listCaptures();
      set({ captures: list, capturesLoaded: true, backendOk: true });
    } catch (e) {
      set({ captures: [], capturesLoaded: true, backendOk: false });
      toastApiError(e, '捕获列表加载失败');
    }
  },

  setCurrent: (id) => {
    set({ currentId: id, meta: null, metaLoading: false });
    if (id) void get().refreshMeta(id);
  },

  refreshMeta: async (id) => {
    const cid = id ?? get().currentId;
    if (!cid) return null;
    set({ metaLoading: true });
    try {
      const m = await api.getCapture(cid);
      set((s) => (s.currentId === cid ? { meta: m, metaLoading: false, backendOk: true } : { metaLoading: false }));
      return m;
    } catch {
      set((s) => (s.currentId === cid ? { meta: null, metaLoading: false } : { metaLoading: false }));
      return null;
    }
  },
}));
