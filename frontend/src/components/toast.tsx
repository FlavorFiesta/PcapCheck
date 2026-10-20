// 全局 Toast(右上角),错误默认停留更久
import { create } from 'zustand';

export type ToastKind = 'error' | 'info' | 'success';
export interface ToastItem {
  id: number;
  kind: ToastKind;
  text: string;
}

interface ToastState {
  list: ToastItem[];
  push: (kind: ToastKind, text: string) => void;
  remove: (id: number) => void;
}

let nextId = 1;

export const useToasts = create<ToastState>()((set) => ({
  list: [],
  push: (kind, text) => {
    const id = nextId++;
    set((s) => ({ list: [...s.list.slice(-6), { id, kind, text }] }));
    window.setTimeout(() => set((s) => ({ list: s.list.filter((t) => t.id !== id) })), kind === 'error' ? 6000 : 3000);
  },
  remove: (id) => set((s) => ({ list: s.list.filter((t) => t.id !== id) })),
}));

export function toastError(text: string): void {
  useToasts.getState().push('error', text);
}
export function toastInfo(text: string): void {
  useToasts.getState().push('info', text);
}
export function toastSuccess(text: string): void {
  useToasts.getState().push('success', text);
}
export function toastApiError(e: unknown, prefix?: string): void {
  const text = e instanceof Error ? e.message : String(e);
  useToasts.getState().push('error', prefix ? `${prefix}:${text}` : text);
}

export function ToastHost() {
  const list = useToasts((s) => s.list);
  return (
    <div className="toast-host">
      {list.map((t) => (
        <div key={t.id} className={`toast toast-${t.kind}`} onClick={() => useToasts.getState().remove(t.id)}>
          {t.text}
        </div>
      ))}
    </div>
  );
}
