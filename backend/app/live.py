# -*- coding: utf-8 -*-
"""实时抓包:tshark -i 线程 + 环形缓冲 + WebSocket 推送 + temp pcap 落盘。

- 单例 LiveManager;start/stop/status/export;
- 读线程逐行解析 ek,帧进 deque(maxlen=默认 100)环形缓冲,
  同步写入临时 pcap(-w),并通过每客户端的 asyncio.Queue 推给 /ws/live;
- 队列满时丢帧(直播场景优先保实时)。
"""
from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import tshark_service
from .paths import DATA_DIR, ensure_dirs

log = logging.getLogger(__name__)


class LiveManager:
    def __init__(self, buffer_size: int = 100):
        self.buffer_size = buffer_size
        self._default_frame_limit = buffer_size
        self._proc: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._buffer: deque = deque(maxlen=buffer_size)
        self._temp_pcap: Optional[Path] = None
        self._iface: Optional[str] = None
        self._lock = threading.Lock()
        self._stop_flag = False
        self._frame_count = 0
        self._frame_limit = buffer_size
        self._clients: List[Dict[str, Any]] = []  # [{queue, loop}]
        self._stderr_f = None
        self._ifaces_cache: List[Dict[str, Any]] = []
        self._ifaces_cached_at = 0.0
        self._ifaces_cache_ttl = 30.0

    # ------------------------------------------------------------ WS 客户端
    def add_client(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._clients.append({"queue": queue, "loop": loop})

    def remove_client(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._clients = [c for c in self._clients if c["queue"] is not queue]

    def _broadcast(self, obj: Dict[str, Any]) -> None:
        with self._lock:
            clients = list(self._clients)
        for c in clients:
            try:
                c["loop"].call_soon_threadsafe(self._put_nowait, c["queue"], obj)
            except RuntimeError:
                self.remove_client(c["queue"])

    @staticmethod
    def _put_nowait(q: asyncio.Queue, obj: Dict[str, Any]) -> None:
        try:
            q.put_nowait(obj)
        except asyncio.QueueFull:
            pass  # 直播丢帧可接受

    # ------------------------------------------------------------ 控制
    def start(self, iface: str, frame_limit: Optional[int] = None,
              tshark_path: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise RuntimeError("实时抓包已在运行,请先停止")
        tshark = tshark_service.resolve_tshark(tshark_path)
        if not tshark:
            raise RuntimeError("未找到 tshark,请到设置里指定路径")
        limit = int(frame_limit or self._default_frame_limit)
        if limit < 1:
            raise RuntimeError("默认抓包数量必须是大于 0 的整数")
        ensure_dirs()
        self._temp_pcap = DATA_DIR / f"live_{time.strftime('%Y%m%d_%H%M%S')}.pcap"

        args = tshark_service.ek_live_args(iface, None, str(self._temp_pcap))
        self._stop_flag = False
        self._frame_count = 0
        self._frame_limit = limit
        self.buffer_size = limit
        self._buffer = deque(maxlen=limit)
        self._iface = iface
        self._stderr_f = tempfile.TemporaryFile()
        self._proc = tshark_service._popen(tshark, args, stderr_file=self._stderr_f)
        self._thread = threading.Thread(target=self._read_loop, name="live-capture", daemon=True)
        self._thread.start()
        self._broadcast({"type": "status", "running": True, "iface": iface,
                         "frame_count": 0})
        return {"iface": iface, "frame_limit": limit}

    def _read_loop(self) -> None:
        proc = self._proc
        last_status = 0.0
        try:
            for layers in tshark_service.iter_ek_proc(proc):
                frame = tshark_service.parse_ek_layers(layers)
                if frame is None:
                    continue
                self._buffer.append(frame)
                self._frame_count += 1
                self._broadcast({"type": "frame", "frame": _public_frame(frame)})
                if self._frame_count >= self._frame_limit:
                    log.info("实时抓包达到帧数上限:%s", self._frame_limit)
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
                now = time.time()
                if now - last_status > 2.0:
                    last_status = now
                    self._broadcast({"type": "status", "running": True,
                                     "iface": self._iface, "frame_count": self._frame_count})
        except Exception:
            log.exception("实时抓包读线程异常")
        finally:
            self._broadcast({"type": "status", "running": False, "iface": self._iface,
                             "frame_count": self._frame_count})

    def stop(self) -> Dict[str, Any]:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._stderr_f is not None:
            self._stderr_f.close()
            self._stderr_f = None
        self._proc = None
        self._thread = None
        return {"stopped": True, "frame_count": self._frame_count,
                "temp_pcap": str(self._temp_pcap) if self._temp_pcap else None}

    def status(self, tshark_path: Optional[str] = None,
               refresh_interfaces: bool = False) -> Dict[str, Any]:
        running = self._proc is not None and self._proc.poll() is None
        now = time.monotonic()
        if (refresh_interfaces or self._ifaces_cached_at <= 0
                or now - self._ifaces_cached_at >= self._ifaces_cache_ttl):
            tshark = tshark_service.resolve_tshark(tshark_path)
            if tshark:
                try:
                    self._ifaces_cache = tshark_service.list_interfaces(tshark)
                    self._ifaces_cached_at = now
                except Exception:
                    if not self._ifaces_cache:
                        self._ifaces_cache = []
        ifaces = list(self._ifaces_cache)
        return {
            "running": running,
            "frame_count": self._frame_count,
            "frame_limit": self._frame_limit,
            "buffer_size": self.buffer_size,
            "iface": self._iface,
            "temp_pcap": str(self._temp_pcap) if self._temp_pcap else None,
            "ifaces": ifaces,
        }

    def export_buffer(self, name: Optional[str] = None) -> str:
        """把当前数据转存为正式 capture(走统一导入管线,唯一诊断入口)。"""
        if self._temp_pcap is None or not self._temp_pcap.exists():
            raise RuntimeError("暂无可导出的抓包文件,请先开始抓包")
        from . import imports
        return imports.start_import(str(self._temp_pcap), name=name or self._temp_pcap.name)


def _public_frame(frame: Dict[str, Any]) -> Dict[str, Any]:
    """WS 推送的帧结构(去掉内部 extra 键)。"""
    return {k: v for k, v in frame.items() if k != "extra"}


MANAGER = LiveManager()
