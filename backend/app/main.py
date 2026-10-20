# -*- coding: utf-8 -*-
"""PcapCheck 后端入口。

- REST API 挂在 /api(见 app/api);
- WebSocket /ws/live:实时抓包推送 {type:"frame", frame:{...}} / {type:"status",...};
- backend/static 存在(前端 build 产物)则静态托管,否则返回内置着陆页;
- 启动时初始化 SQLite 与数据目录。
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .api import api_router
from .db import init_db
from .live import MANAGER
from .paths import BACKEND_DIR, ensure_dirs

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("pcapcheck")


def _startup() -> None:
    ensure_dirs()
    init_db()
    log.info("PcapCheck backend ready")


def _shutdown() -> None:
    """Do not leave tshark/dumpcap children behind when the desktop exits."""
    MANAGER.stop()


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _startup()
    try:
        yield
    finally:
        _shutdown()


app = FastAPI(title="报文检查 API", version="1.0.8", lifespan=_lifespan)

LOCAL_ORIGINS = [f"http://{host}:{port}" for host in ("localhost", "127.0.0.1")
                 for port in (8123, 5173)]

app.add_middleware(
    CORSMiddleware, allow_origins=LOCAL_ORIGINS, allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

class LocalOriginGuard:
    """Reject cross-site requests before endpoints run, including WebSockets."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            origin = headers.get(b"origin")
            denied = ((origin is not None and origin.decode("latin1") not in LOCAL_ORIGINS)
                      or headers.get(b"sec-fetch-site") == b"cross-site")
            if denied:
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    await send({"type": "http.response.start", "status": 403, "headers": []})
                    await send({"type": "http.response.body", "body": b"Forbidden origin"})
                return
        await self.app(scope, receive, send)

app.add_middleware(LocalOriginGuard)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])

def _resolve_static_dir() -> Path:
    """前端产物位置:backend/static 优先(手工部署),否则直接用 frontend/dist。"""
    candidates = [BACKEND_DIR / "static", BACKEND_DIR.parent / "frontend" / "dist"]
    for c in candidates:
        if (c / "index.html").exists():
            return c
    return candidates[0]


STATIC_DIR = _resolve_static_dir()


app.include_router(api_router)


@app.get("/")
def index():
    if (STATIC_DIR / "index.html").exists():
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))
    return HTMLResponse(
        "<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
        "<title>报文检查</title></head>"
        "<body style=\"font-family:'Microsoft YaHei',sans-serif;margin:48px\">"
        "<h1>报文检查后端运行中</h1>"
        "<p>REST API 前缀:<code>/api</code>;接口文档:<a href='/docs'>/docs</a>。</p>"
        "<p>前端构建产物放到 <code>backend/static</code> 后将自动托管。</p>"
        "</body></html>")


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    """实时抓包推送:每客户端一个有界队列,慢消费者丢帧不阻塞采集线程。"""
    await ws.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    MANAGER.add_client(queue, asyncio.get_running_loop())
    try:
        # 首条:当前状态快照
        status = MANAGER.status()
        await ws.send_json({"type": "status", "running": status.get("running", False),
                            "frame_count": status.get("frame_count", 0)})
        while True:
            # 读客户端消息(如心跳/控制),同时转发队列里的帧
            get_msg = asyncio.create_task(ws.receive_text())
            get_item = asyncio.create_task(queue.get())
            done, pending = await asyncio.wait({get_msg, get_item},
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            if get_msg in done:
                msg = get_msg.result()
                if msg in ("stop", "close"):
                    break
                # 其他消息忽略
            if get_item in done:
                await ws.send_json(get_item.result())
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        MANAGER.remove_client(queue)
        try:
            await ws.close()
        except Exception:
            pass


# 前端 build 静态托管(放最后,避免吞掉 /api 与 /docs)
# SPA 回退:非 /api 的未知路径一律回 index.html,否则 /browse?capture=x 这类前端路由会 404
if (STATIC_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")),
              name="assets")

    from fastapi.responses import FileResponse

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        candidate = STATIC_DIR / full_path
        if full_path and candidate.resolve().is_relative_to(STATIC_DIR.resolve()) \
                and candidate.is_file():
            return FileResponse(candidate)
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))
