# -*- coding: utf-8 -*-
"""API 路由聚合(按契约分组)。"""
from __future__ import annotations

from fastapi import APIRouter

from . import captures, live_api, reports, settings_api

api_router = APIRouter(prefix="/api")
api_router.include_router(captures.router)
api_router.include_router(reports.router)
api_router.include_router(settings_api.router)  # 含 /settings /filter/compile /kb/articles
api_router.include_router(live_api.router)
