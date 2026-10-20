// 可拖动分隔条(简单 splitter)
import { useRef } from 'react';

/** 水平方向布局的上下分隔,拖动产生 dy */
export function HSplitter({ onDelta }: { onDelta: (dy: number) => void }) {
  const dragging = useRef(false);
  const last = useRef(0);
  return (
    <div
      className="splitter splitter-h"
      onPointerDown={(e) => {
        dragging.current = true;
        last.current = e.clientY;
        e.currentTarget.setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        if (!dragging.current) return;
        onDelta(e.clientY - last.current);
        last.current = e.clientY;
      }}
      onPointerUp={() => {
        dragging.current = false;
      }}
      onPointerCancel={() => {
        dragging.current = false;
      }}
    />
  );
}

/** 垂直方向布局的左右分隔,拖动产生 dx */
export function VSplitter({ onDelta }: { onDelta: (dx: number) => void }) {
  const dragging = useRef(false);
  const last = useRef(0);
  return (
    <div
      className="splitter splitter-v"
      onPointerDown={(e) => {
        dragging.current = true;
        last.current = e.clientX;
        e.currentTarget.setPointerCapture(e.pointerId);
      }}
      onPointerMove={(e) => {
        if (!dragging.current) return;
        onDelta(e.clientX - last.current);
        last.current = e.clientX;
      }}
      onPointerUp={() => {
        dragging.current = false;
      }}
      onPointerCancel={() => {
        dragging.current = false;
      }}
    />
  );
}
