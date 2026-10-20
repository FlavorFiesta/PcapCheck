# -*- coding: utf-8 -*-
"""报文检查原生桌面 GUI。

这个入口把网页端的核心诊断工作台移植为 Tkinter 原生窗口:
深色侧栏、顶部导入栏、规则/AI 直达诊断报告、历史报告、实时抓包、知识库统计和系统设置均在本地窗口内完成。
诊断逻辑仍由 FastAPI/tshark/规则引擎提供,原生界面只负责交互和展示。
"""
from __future__ import annotations

import json
import ctypes
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    TkRoot = TkinterDnD.Tk
except ImportError:  # Source checkouts can still open; packaged builds include tkinterdnd2.
    DND_FILES = None
    TkRoot = tk.Tk


ROOT = (Path(sys.executable).resolve().parent
        if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1])
BACKEND = ROOT / "backend"
BASE_URL = "http://127.0.0.1:8123"
PYTHON = BACKEND / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)
RUNTIME_DATA = ROOT / "data" if getattr(sys, "frozen", False) else BACKEND / "data"

BG = "#14161b"
DEEP = "#101218"
PANEL = "#1b1e25"
PANEL2 = "#20242d"
BORDER = "#2b3140"
TEXT = "#d7dbe3"
DIM = "#8b93a7"
ACCENT = "#4f8cff"
RED = "#ff6b62"
ORANGE = "#ffa657"
YELLOW = "#e8c66a"
GREEN = "#3fb27f"

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")
ANALYSIS_TIMEOUT_SECONDS = 360


def is_supported_capture(path: Path) -> bool:
    return str(path).lower().endswith(CAPTURE_SUFFIXES)


def parse_drop_files(data: str) -> list[Path]:
    """Parse TkDND's Tcl-list payload without breaking paths containing spaces."""
    if not data:
        return []
    try:
        values = tk.Tcl().splitlist(data)
    except tk.TclError:
        values = (data,)
    return [Path(value) for value in values if str(value).strip()]


def empty_report_title(message: str) -> str:
    return "诊断中" if message.startswith("正在") else "待诊断"


def _enable_windows_dpi_awareness() -> None:
    """让 Tk 使用每显示器 DPI，避免 Windows 缩放后窗口和文字发糊。"""
    if sys.platform != "win32":
        return
    try:
        # Windows 10 1703+: per-monitor V2 is the crispest mode for Tk windows.
        user32 = ctypes.windll.user32
        set_context = user32.SetProcessDpiAwarenessContext
        set_context.argtypes = [ctypes.c_void_p]
        set_context.restype = ctypes.c_bool
        if set_context(ctypes.c_void_p(-4)):
            return
    except (AttributeError, OSError):
        pass
    try:
        # Older Windows 10 fallback: PROCESS_PER_MONITOR_DPI_AWARE = 2.
        shcore = ctypes.windll.shcore
        shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        pass


class ApiError(RuntimeError):
    pass


def api_request(path: str, method: str = "GET", body: dict[str, Any] | None = None,
                timeout: float = 15) -> Any:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise ApiError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ApiError(f"无法连接报文检查后端: {exc}") from exc
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ApiError("后端返回了无法识别的数据") from exc


def backend_ready() -> bool:
    try:
        api_request("/api/captures", timeout=1.5)
        return True
    except ApiError:
        return False


def ensure_backend() -> subprocess.Popen[Any] | None:
    """启动本地后端;如果已有服务则不接管它。"""
    if backend_ready():
        return None
    log_path = RUNTIME_DATA / "desktop-gui-backend.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("a", encoding="utf-8")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if getattr(sys, "frozen", False):
        backend_exe = ROOT / "backend" / "PcapCheckBackend.exe"
        if not backend_exe.is_file():
            log.close()
            raise ApiError(f"缺少后端程序: {backend_exe}")
        command = [str(backend_exe), "--host", "127.0.0.1", "--port", "8123"]
        cwd = ROOT
    else:
        command = [str(PYTHON), "-m", "uvicorn", "app.main:app",
                   "--host", "127.0.0.1", "--port", "8123"]
        cwd = BACKEND
    process = subprocess.Popen(command, cwd=str(cwd), stdout=log, stderr=subprocess.STDOUT,
                               creationflags=creationflags)
    for _ in range(30):
        if backend_ready():
            return process
        if process.poll() is not None:
            log.close()
            raise ApiError(f"后端启动失败,请查看日志: {log_path}")
        time.sleep(0.5)
    process.terminate()
    log.close()
    raise ApiError(f"后端启动超时,请查看日志: {log_path}")


def norm_findings(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return norm_findings(parsed)
    return []


def build_brief(report: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if report.get("analysis_mode") == "ai_direct" or report.get("engine") == "ai-direct":
        return "本报告由 AI 直达分析生成：已跳过本地规则引擎和知识库关联，结论请结合原始报文进一步核验。"
    name = str(report.get("capture_name") or "").lower()
    if not findings and "benign" in name and "dns" in name:
        return ("这是一份良性（健康）DNS 流量基线样本，未命中报文检查规则引擎的任何确诊 / 疑似 / 潜在规则，"
                "属于合成测试负样本，预期输出“无故障”。")
    if not findings:
        return "本次抓包未命中报文检查规则引擎的确诊 / 疑似 / 潜在规则，当前未发现规则定义范围内的异常。"
    labels = (("confirmed", "确诊故障"), ("suspect", "疑似问题"), ("potential", "潜在风险"))
    parts = []
    for tier, label in labels:
        count = sum(1 for item in findings if item.get("tier") == tier)
        if count:
            parts.append(f"{label} {count} 项")
    return f"本次抓包共发现{'、'.join(parts)}，请结合证据帧和关联知识库进一步确认。"


class ScrollableFrame(tk.Frame):
    """深色主题的纵向滚动容器,用于报告卡片。"""

    def __init__(self, master: tk.Misc, **kwargs: Any):
        super().__init__(master, bg=kwargs.pop("bg", BG), **kwargs)
        bg = self.cget("bg")
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.inner_id, width=e.width))
        # Mouse-wheel events are delivered to the child card under the pointer,
        # not necessarily to the canvas.  Bind at the toplevel and only handle
        # the event when the pointer is inside this particular scroller.
        self.bind_all("<MouseWheel>", self._wheel, add="+")
        self.bind_all("<Button-4>", self._wheel_up, add="+")
        self.bind_all("<Button-5>", self._wheel_down, add="+")

    def _contains_pointer(self) -> bool:
        x, y = self.winfo_pointerx(), self.winfo_pointery()
        left, top = self.winfo_rootx(), self.winfo_rooty()
        return left <= x < left + self.winfo_width() and top <= y < top + self.winfo_height()

    def _wheel(self, event: tk.Event) -> None:
        if self._contains_pointer():
            units = -1 if event.delta > 0 else 1
            self.canvas.yview_scroll(units, "units")

    def _wheel_up(self, event: tk.Event) -> None:
        if self._contains_pointer():
            self.canvas.yview_scroll(-1, "units")

    def _wheel_down(self, event: tk.Event) -> None:
        if self._contains_pointer():
            self.canvas.yview_scroll(1, "units")


class DesktopApp(TkRoot):
    TIER_META = {
        "confirmed": ("确诊故障", RED, "#3a2024"),
        "suspect": ("疑似问题", ORANGE, "#382c1e"),
        "potential": ("潜在风险", YELLOW, "#39331e"),
    }

    def __init__(self, owned_backend: subprocess.Popen[Any] | None):
        super().__init__()
        self._app_icon = self._create_app_icon()
        self.iconphoto(True, self._app_icon)
        self.owned_backend = owned_backend
        self.report: dict[str, Any] | None = None
        self.capture: dict[str, Any] | None = None
        self.all_captures: list[dict[str, Any]] = []
        self.captures: list[dict[str, Any]] = []
        self.report_records: list[dict[str, Any]] = []
        self.reports_by_capture: dict[str, list[dict[str, Any]]] = {}
        self.busy = False
        self.title("报文检查")
        self.geometry("1600x900")
        self.minsize(1280, 720)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._configure_styles()
        self._build_shell()
        self.show_page("report")
        self.after(100, self.refresh_captures)
        self._set_status("就绪。请选择 pcap/pcapng 文件，再选择规则诊断或 AI 直达分析。")

    @staticmethod
    def _create_app_icon() -> tk.PhotoImage:
        """创建一个无需外部资源的抓包文档图标,替换 Tk 默认图标。"""
        icon = tk.PhotoImage(width=32, height=32)
        icon.put("#0b1220", to=(0, 0, 31, 31))
        icon.put("#2563eb", to=(4, 4, 27, 27))
        icon.put("#f8fafc", to=(8, 5, 23, 26))
        icon.put("#bfdbfe", to=(19, 5, 23, 9))
        icon.put("#60a5fa", to=(11, 12, 20, 13))
        icon.put("#60a5fa", to=(11, 16, 20, 17))
        icon.put("#60a5fa", to=(11, 20, 17, 21))
        return icon

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Dark.TCombobox", fieldbackground=PANEL2, background=PANEL2,
                        foreground=TEXT, arrowcolor=DIM, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER, padding=4)
        style.map("Dark.TCombobox", fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", TEXT)])
        style.configure("Dark.Horizontal.TProgressbar", background=ACCENT, troughcolor=PANEL2,
                        bordercolor=PANEL2, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG,
                        bordercolor=BG, arrowcolor=DIM, lightcolor=PANEL2, darkcolor=PANEL2)
        style.map("Vertical.TScrollbar", background=[("active", BORDER)])

    def _button(self, parent: tk.Misc, text: str, command: Callable[[], None],
                primary: bool = False) -> tk.Button:
        return tk.Button(
            parent, text=text, command=command, font=("Microsoft YaHei UI", 10),
            fg="#ffffff" if primary else TEXT, bg=ACCENT if primary else PANEL2,
            activeforeground="#ffffff", activebackground="#4279df" if primary else "#2b3140",
            disabledforeground=DIM, highlightbackground=BORDER, highlightcolor=ACCENT,
            relief="flat", bd=0, padx=12, pady=6, cursor="hand2",
        )

    def _label(self, parent: tk.Misc, text: str, **kwargs: Any) -> tk.Label:
        defaults = {"text": text, "bg": parent.cget("bg") if hasattr(parent, "cget") else BG,
                    "fg": TEXT, "font": ("Microsoft YaHei UI", 10), "anchor": "w"}
        defaults.update(kwargs)
        return tk.Label(parent, **defaults)

    def _build_shell(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.sidebar = tk.Frame(self, bg=DEEP, width=190)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_propagate(False)
        brand = tk.Frame(self.sidebar, bg=DEEP)
        brand.pack(fill="x", padx=22, pady=(28, 28))
        tk.Label(brand, image=self._app_icon, bg=DEEP).pack(anchor="w", pady=(0, 12))
        self._label(brand, "报文检查", font=("Microsoft YaHei UI", 17, "bold")).pack(anchor="w")
        self._label(brand, "网络诊断工作台", fg=DIM, font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(5, 0))
        self.nav_buttons: dict[str, tk.Button] = {}
        for key, label in (("report", "一键分析"), ("captures", "报文列表"), ("history", "历史"),
                           ("live", "实时抓包"), ("kb", "知识库"), ("settings", "设置")):
            btn = tk.Button(self.sidebar, text=label, anchor="w", command=lambda k=key: self.show_page(k),
                            bg=DEEP, fg=DIM, activebackground="#1b2435", activeforeground=ACCENT,
                            relief="flat", bd=0, padx=28, pady=10, font=("Microsoft YaHei UI", 11))
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = btn
        footer = tk.Frame(self.sidebar, bg=DEEP)
        footer.pack(side="bottom", fill="x", padx=8, pady=16)
        self.backend_label = tk.Label(footer, text="● 后端检查中", bg=DEEP, fg=YELLOW,
                                      font=("Microsoft YaHei UI", 9), anchor="center")
        self.backend_label.pack(fill="x", pady=(0, 5))
        tk.Label(footer, text="v1.0.8", bg=DEEP, fg=DIM,
                 font=("Microsoft YaHei UI", 9), wraplength=145).pack(fill="x")

        self.page_host = tk.Frame(self, bg=BG)
        self.page_host.grid(row=0, column=1, sticky="nsew")
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)
        self.pages: dict[str, tk.Frame] = {}
        self._build_report_page()
        self._build_capture_list_page()
        self._build_history_page()
        self._build_live_page()
        self._build_kb_page()
        self._build_settings_page()

        self.status = tk.Label(self, text="", bg=DEEP, fg=DIM, anchor="w",
                               font=("Microsoft YaHei UI", 9), padx=12, pady=5)
        self.status.grid(row=1, column=1, sticky="ew")

    def _make_placeholder(self, title: str, desc: str) -> tk.Frame:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_columnconfigure(0, weight=1)
        self._label(page, title, fg=TEXT, font=("Microsoft YaHei UI", 19, "bold")).grid(
            row=0, column=0, padx=28, pady=(28, 8), sticky="w")
        card = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        card.grid(row=1, column=0, padx=28, pady=12, sticky="ew")
        self._label(card, desc, bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 11),
                    wraplength=900, justify="left").pack(fill="x", padx=20, pady=22)
        return page

    def _build_capture_list_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_rowconfigure(1, weight=1)
        page.grid_columnconfigure(0, weight=1)
        self.pages["captures"] = page

        head = tk.Frame(page, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 12))
        tk.Label(head, text="报文列表", bg=BG, fg=TEXT,
                 font=("Microsoft YaHei UI", 19, "bold")).pack(side="left")
        self._button(head, "刷新列表", self.refresh_captures).pack(side="right")

        self.capture_list_scroll = ScrollableFrame(page, bg=BG)
        self.capture_list_scroll.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 20))
        self.capture_list_scroll.inner.grid_columnconfigure(0, weight=1)
        self.capture_list_content = self.capture_list_scroll.inner
        self._render_capture_list([])

    @staticmethod
    def _report_has_ai(report: dict[str, Any]) -> bool:
        return bool(str(report.get("narrative") or "").strip())

    def _report_marker(self, report: dict[str, Any]) -> str:
        if report.get("analysis_mode") == "ai_direct" or report.get("engine") == "ai-direct":
            return " · AI直达分析"
        return " · AI辅助" if self._report_has_ai(report) else ""

    @staticmethod
    def _is_ai_direct(report: dict[str, Any] | None) -> bool:
        return bool(report and (report.get("analysis_mode") == "ai_direct" or report.get("engine") == "ai-direct"))

    def _report_capture_name(self, report: dict[str, Any]) -> str:
        return str(report.get("capture_name") or (self.capture or {}).get("name") or "-")

    @staticmethod
    def _format_size(value: Any) -> str:
        try:
            size = float(value)
        except (TypeError, ValueError):
            return "-"
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024
        return "-"

    def _render_capture_list(self, captures: list[dict[str, Any]], error: str | None = None) -> None:
        self._clear_children(self.capture_list_content)
        if error:
            tk.Label(self.capture_list_content, text=f"加载报文列表失败：{error}", bg=BG, fg=RED,
                     font=("Microsoft YaHei UI", 10), anchor="w").grid(row=0, column=0, sticky="ew", pady=16)
            return
        if not captures:
            tk.Label(self.capture_list_content, text="暂无已导入报文。请到“一键分析”选择 pcap/pcapng 文件。",
                     bg=BG, fg=DIM, font=("Microsoft YaHei UI", 11), anchor="w").grid(
                         row=0, column=0, sticky="ew", pady=20)
            return

        for row, capture in enumerate(captures):
            capture_id = str(capture.get("id") or "")
            reports = self.reports_by_capture.get(capture_id, [])
            status = str(capture.get("status") or "unknown")
            status_text, status_color = {
                "ready": ("已就绪", GREEN),
                "importing": ("导入中", YELLOW),
                "error": ("导入失败", RED),
            }.get(status, (status, DIM))
            card = tk.Frame(self.capture_list_content, bg=PANEL,
                            highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=row, column=0, sticky="ew", pady=(0, 10))
            card.grid_columnconfigure(0, weight=1)

            head = tk.Frame(card, bg=PANEL)
            head.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))
            tk.Label(head, text=str(capture.get("name") or "未命名报文"), bg=PANEL, fg=TEXT,
                     font=("Microsoft YaHei UI", 12, "bold"), anchor="w").pack(side="left")
            tk.Label(head, text=status_text, bg="#172238" if status == "ready" else "#2c281d",
                     fg=status_color, font=("Microsoft YaHei UI", 9), padx=8, pady=3).pack(side="left", padx=10)
            tk.Label(head, text=f"{capture.get('frame_count', 0)} 帧 · {self._format_size(capture.get('size'))}",
                     bg=PANEL, fg=DIM, font=("Consolas", 9)).pack(side="left")
            actions = tk.Frame(head, bg=PANEL)
            actions.pack(side="right")
            if status == "ready":
                self._button(actions, "查看报告", lambda c=capture: self._open_capture_record(c)).pack(side="left", padx=3)
                self._button(actions, "下载报文", lambda c=capture: self._download_capture(c)).pack(side="left", padx=3)
            delete = self._button(actions, "删除", lambda c=capture: self._delete_capture_record(c))
            delete.configure(fg=RED, activeforeground="#ffffff")
            delete.pack(side="left", padx=(3, 0))

            path_text = str(capture.get("path") or "")
            if path_text:
                tk.Label(card, text=f"路径：{path_text}", bg=PANEL, fg=DIM,
                         font=("Consolas", 8), anchor="w").grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

            report_box = tk.Frame(card, bg=PANEL2)
            report_box.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
            report_box.grid_columnconfigure(0, weight=1)
            tk.Label(report_box, text=f"已分析报告（{len(reports)}）", bg=PANEL2, fg=ACCENT,
                     font=("Microsoft YaHei UI", 10, "bold"), anchor="w").grid(
                         row=0, column=0, sticky="w", padx=12, pady=(9, 5))
            if not reports:
                tk.Label(report_box, text="尚未生成诊断报告。打开报文后可在一键分析中开始诊断。",
                         bg=PANEL2, fg=DIM, font=("Microsoft YaHei UI", 9), anchor="w").grid(
                             row=1, column=0, sticky="w", padx=12, pady=(0, 10))
            else:
                for report_row, report in enumerate(reports, start=1):
                    report_line = tk.Frame(report_box, bg=PANEL2)
                    report_line.grid(row=report_row, column=0, sticky="ew", padx=12, pady=(0, 6))
                    report_line.grid_columnconfigure(0, weight=1)
                    text = f"{self._report_time(report.get('created_at'))}{self._report_marker(report)}"
                    tk.Label(report_line, text=text, bg=PANEL2, fg=TEXT,
                             font=("Consolas", 9), anchor="w").grid(row=0, column=0, sticky="w")
                    report_actions = tk.Frame(report_line, bg=PANEL2)
                    report_actions.grid(row=0, column=1, sticky="e")
                    self._button(report_actions, "查看", lambda c=capture, r=report: self._open_capture_record(c, r)).pack(
                        side="left", padx=2)
                    self._button(report_actions, "下载 HTML", lambda r=report: self._download_report_html(r)).pack(
                        side="left", padx=2)
                    report_delete = self._button(report_actions, "删除报告",
                                                 lambda r=report: self._delete_history_report(r))
                    report_delete.configure(fg=RED, activeforeground="#ffffff")
                    report_delete.pack(side="left", padx=2)

    def _open_capture_record(self, capture: dict[str, Any], report: dict[str, Any] | None = None) -> None:
        self._select_capture(capture)
        self.show_page("report")
        if report:
            self.render_report(capture, report)
        else:
            self._render_empty_report("这个报文还没有诊断报告，点击“开始诊断”运行规则引擎。")

    def _download_capture(self, capture: dict[str, Any]) -> None:
        source = Path(str(capture.get("path") or ""))
        if not source.is_file():
            messagebox.showerror("下载报文失败", f"源文件不存在：\n{source}")
            return
        destination = filedialog.asksaveasfilename(
            title="下载报文", initialfile=source.name,
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap *.gz"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            shutil.copy2(source, destination)
            messagebox.showinfo("下载完成", f"报文已保存到：\n{destination}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("下载报文失败", str(exc))

    def _download_report_html(self, report: dict[str, Any]) -> None:
        report_id = str(report.get("id") or "")
        if not report_id:
            return
        destination = filedialog.asksaveasfilename(
            title="下载 HTML 报告", defaultextension=".html",
            initialfile=f"pcapcheck-report-{report_id}.html",
            filetypes=[("HTML", "*.html"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            request = urllib.request.Request(f"{BASE_URL}/api/reports/{report_id}/export?format=html")
            with urllib.request.urlopen(request, timeout=30) as response:
                Path(destination).write_bytes(response.read())
            messagebox.showinfo("下载完成", f"HTML 报告已保存到：\n{destination}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("下载报告失败", str(exc))

    def _delete_capture_record(self, capture: dict[str, Any]) -> None:
        capture_id = str(capture.get("id") or "")
        name = str(capture.get("name") or capture_id)
        if not capture_id or not messagebox.askyesno(
                "删除报文", f"确定删除“{name}”及其已分析报告吗？此操作不可恢复。"):
            return

        def worker() -> None:
            try:
                api_request(f"/api/captures/{capture_id}", "DELETE")
                if self.capture and self.capture.get("id") == capture_id:
                    self.capture = None
                    self.report = None
                    self.after(0, lambda: self._render_empty_report())
                self.after(0, self.refresh_captures)
                self.after(0, self.refresh_history)
                self.root_status("报文及对应报告已删除。")
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("删除报文失败", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _build_history_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_rowconfigure(1, weight=1)
        page.grid_columnconfigure(0, weight=1)
        self.pages["history"] = page
        head = tk.Frame(page, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 12))
        tk.Label(head, text="历史报告", bg=BG, fg=TEXT,
                 font=("Microsoft YaHei UI", 19, "bold")).pack(side="left")
        self._button(head, "刷新历史", self.refresh_history).pack(side="right")
        self.history_scroll = ScrollableFrame(page, bg=BG)
        self.history_scroll.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 20))
        self.history_scroll.inner.grid_columnconfigure(0, weight=1)
        self.history_content = self.history_scroll.inner
        self._render_history([])

    def refresh_history(self) -> None:
        def worker() -> None:
            try:
                data = api_request("/api/reports")
                reports = data.get("reports", []) if isinstance(data, dict) else []
                self.after(0, lambda: self._render_history(reports))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self._render_history([], str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _report_counts(report: dict[str, Any]) -> tuple[int, int, int, int]:
        findings = norm_findings(report.get("findings"))
        return (len(findings), sum(f.get("tier") == "confirmed" for f in findings),
                sum(f.get("tier") == "suspect" for f in findings),
                sum(f.get("tier") == "potential" for f in findings))

    @staticmethod
    def _report_time(value: Any) -> str:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
        except (TypeError, ValueError, OverflowError):
            return str(value or "-")

    def _render_history(self, reports: list[dict[str, Any]], error: str | None = None) -> None:
        self._clear_children(self.history_content)
        if error:
            tk.Label(self.history_content, text=f"加载历史失败：{error}", bg=BG, fg=RED,
                     font=("Microsoft YaHei UI", 10), anchor="w").grid(row=0, column=0, sticky="ew", pady=16)
            return
        if not reports:
            tk.Label(self.history_content, text="暂无历史报告。完成一次一键分析后，报告会显示在这里。",
                     bg=BG, fg=DIM, font=("Microsoft YaHei UI", 11), anchor="w").grid(row=0, column=0, sticky="ew", pady=20)
            return
        for row, report in enumerate(reports):
            total, confirmed, suspect, potential = self._report_counts(report)
            card = tk.Frame(self.history_content, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=row, column=0, sticky="ew", pady=(0, 10))
            card.grid_columnconfigure(1, weight=1)
            tk.Label(card, text=self._report_time(report.get("created_at")), bg=PANEL, fg=DIM,
                     font=("Consolas", 9), width=20, anchor="w").grid(row=0, column=0, rowspan=2, padx=14, pady=14, sticky="nw")
            capture_name = report.get("capture_name") or report.get("capture_id", "-")
            name_line = tk.Frame(card, bg=PANEL)
            name_line.grid(row=0, column=1, padx=8, pady=(12, 2), sticky="ew")
            tk.Label(name_line, text=str(capture_name), bg=PANEL, fg=TEXT,
                     font=("Microsoft YaHei UI", 11, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
            if self._is_ai_direct(report) or self._report_has_ai(report):
                tk.Label(name_line, text="AI直达分析" if self._is_ai_direct(report) else "AI辅助",
                         bg="#172238", fg=ACCENT,
                         font=("Microsoft YaHei UI", 9), padx=7, pady=2).grid(row=0, column=1, padx=10, sticky="w")
            summary = (f"AI直达分析 · {report.get('capture_frame_count', 0)} 帧 · 未运行本地规则"
                       if self._is_ai_direct(report) else
                       f"{total} 项规则 · 确诊 {confirmed} · 疑似 {suspect} · 潜在 {potential} · {report.get('engine', '-') }")
            tk.Label(card, text=summary, bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 9), anchor="w").grid(
                row=1, column=1, padx=8, pady=(0, 12), sticky="ew")
            actions = tk.Frame(card, bg=PANEL)
            actions.grid(row=0, column=2, rowspan=2, padx=14, pady=12)
            self._button(actions, "查看", lambda r=report: self._open_history_report(r)).pack(side="left", padx=(0, 6))
            self._button(actions, "下载 HTML", lambda r=report: self._download_report_html(r)).pack(
                side="left", padx=(0, 6))
            delete = self._button(actions, "删除", lambda r=report: self._delete_history_report(r), primary=False)
            delete.configure(fg=RED, activeforeground="#ffffff")
            delete.pack(side="left")

    def _open_history_report(self, report: dict[str, Any]) -> None:
        capture = next((c for c in self.captures if c.get("id") == report.get("capture_id")), None)
        if capture is None:
            capture = {"id": report.get("capture_id"), "name": report.get("capture_name", ""),
                       "frame_count": report.get("capture_frame_count", 0)}
        self.render_report(capture, report)

    def _delete_history_report(self, report: dict[str, Any]) -> None:
        report_id = str(report.get("id", ""))
        if not report_id or not messagebox.askyesno("删除历史报告", "确定删除这份历史报告吗？对应抓包文件不会删除。"):
            return
        def worker() -> None:
            try:
                api_request(f"/api/reports/{report_id}", "DELETE")
                self.after(0, self.refresh_history)
                self.after(0, self.refresh_captures)
                self.root_status("历史报告已删除。")
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("删除失败", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _build_live_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_rowconfigure(1, weight=1)
        page.grid_columnconfigure(0, weight=1)
        self.pages["live"] = page
        head = tk.Frame(page, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 12))
        tk.Label(head, text="实时抓包", bg=BG, fg=TEXT,
                 font=("Microsoft YaHei UI", 19, "bold")).pack(side="left")
        self.live_status_label = tk.Label(head, text="● 未运行", bg=BG, fg=DIM,
                                          font=("Microsoft YaHei UI", 10))
        self.live_status_label.pack(side="left", padx=16)
        self._button(head, "刷新接口", self.refresh_live_interfaces).pack(side="right")

        panel = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        panel.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 20))
        panel.grid_rowconfigure(2, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        controls = tk.Frame(panel, bg=PANEL)
        controls.grid(row=0, column=0, sticky="ew", padx=16, pady=16)
        tk.Label(controls, text="接口", bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 10)).pack(side="left")
        self.live_iface_var = tk.StringVar(value="")
        self.iface_combo = ttk.Combobox(controls, textvariable=self.live_iface_var, state="readonly",
                                        style="Dark.TCombobox", width=42)
        self.iface_combo.pack(side="left", padx=(8, 12))
        tk.Label(controls, text="默认抓包", bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 10),
                 cursor="question_arrow").pack(side="left")
        self.live_frame_limit_var = tk.StringVar(value="100")
        tk.Entry(controls, textvariable=self.live_frame_limit_var, bg=PANEL2, fg=TEXT, insertbackground=TEXT,
                 relief="flat", width=10).pack(side="left", padx=(8, 12))
        self.live_start_btn = self._button(controls, "开始", self.start_live, primary=True)
        self.live_start_btn.pack(side="left", padx=4)
        self.live_stop_btn = self._button(controls, "停止", self.stop_live)
        self.live_stop_btn.configure(state="disabled")
        self.live_stop_btn.pack(side="left", padx=4)
        self._button(controls, "分析当前数据", self.analyze_live, primary=True).pack(side="left", padx=12)
        self.live_count_label = tk.Label(controls, text="0 帧", bg=PANEL, fg=DIM,
                                         font=("Consolas", 10))
        self.live_count_label.pack(side="right")
        self.live_hint_label = tk.Label(
            panel, text="提示：开始抓包后前几秒正在建立缓冲，可能暂时没有报文，请稍候。",
            bg=PANEL, fg=YELLOW, font=("Microsoft YaHei UI", 10), anchor="w")
        self.live_hint_label.grid(row=1, column=0, sticky="ew", padx=16)
        self.live_text = tk.Text(panel, bg="#11141a", fg=TEXT, insertbackground=TEXT,
                                 relief="flat", font=("Consolas", 10), state="disabled")
        self.live_text.grid(row=2, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.live_lines: list[str] = []
        self.live_iface_values: list[str] = []
        self.live_stop_event = threading.Event()
        self.live_running = False
        self.live_poll_after: str | None = None
        self.live_warmup = False

    def refresh_live_interfaces(self) -> None:
        def worker() -> None:
            try:
                data = api_request("/api/live/interfaces")
                interfaces = data.get("interfaces", []) if isinstance(data, dict) else []
                usable = [item for item in interfaces if item.get("capture", True)]
                values = [f"{item.get('idx', '')}. {item.get('desc') or item.get('name', '')}" for item in usable]
                names = [str(item.get("name", item.get("idx", ""))) for item in usable]
                warning = data.get("warning", "") if isinstance(data, dict) else ""
                self.after(0, lambda: self._set_live_interfaces(values, names, warning=warning))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self._set_live_interfaces([], [], str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _set_live_interfaces(self, values: list[str], names: list[str], error: str | None = None,
                             warning: str = "") -> None:
        self.live_iface_values = names
        self.iface_combo.configure(values=values)
        self.live_iface_var.set(values[0] if values else "")
        self.live_start_btn.configure(state="normal" if names else "disabled")
        if error:
            self.live_status_label.configure(text="● 接口读取失败", fg=RED)
            self._set_status(f"枚举网卡失败：{error}")
        elif warning:
            self.live_status_label.configure(text="● 未发现可抓包网卡", fg=ORANGE)
            self.live_hint_label.configure(text=warning, fg=ORANGE)
            self._set_status(warning)
        else:
            self.live_hint_label.configure(text="提示：开始抓包后前几秒正在建立缓冲，可能暂时没有报文，请稍候。", fg=YELLOW)

    def _selected_live_iface(self) -> str:
        index = self.iface_combo.current()
        if 0 <= index < len(self.live_iface_values):
            return self.live_iface_values[index]
        return self.live_iface_var.get().split(". ", 1)[-1].strip()

    def start_live(self) -> None:
        iface = self._selected_live_iface()
        if not iface:
            messagebox.showinfo("实时抓包", "请先选择网卡接口。")
            return
        try:
            frame_limit = int(self.live_frame_limit_var.get()) if self.live_frame_limit_var.get().strip() else 100
            if frame_limit < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("实时抓包", "默认抓包数量必须是大于 0 的整数。")
            return
        def worker() -> None:
            try:
                api_request("/api/live/start", "POST", {"iface": iface, "frame_limit": frame_limit})
                self.after(0, self._live_started)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("启动抓包失败", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _live_started(self) -> None:
        self.live_running = True
        self.live_stop_event.clear()
        self.live_start_btn.configure(state="disabled")
        self.live_stop_btn.configure(state="normal")
        self.live_status_label.configure(text="● 抓包中", fg=GREEN)
        self.live_warmup = True
        self.live_hint_label.configure(text="提示：正在建立抓包缓冲，前几秒可能暂时没有报文，请稍候。", fg=YELLOW)
        self._set_status("实时抓包已开始，正在建立缓冲…")
        threading.Thread(target=self._live_ws_worker, daemon=True).start()
        self._poll_live_status()

    def _live_ws_worker(self) -> None:
        async def consume() -> None:
            import asyncio
            import websockets
            try:
                async with websockets.connect("ws://127.0.0.1:8123/ws/live", ping_interval=20) as socket:
                    while not self.live_stop_event.is_set():
                        try:
                            raw = await asyncio.wait_for(socket.recv(), timeout=1.0)
                        except asyncio.TimeoutError:
                            continue
                        try:
                            msg = json.loads(str(raw))
                        except json.JSONDecodeError:
                            continue
                        if msg.get("type") == "frame":
                            frame = msg.get("frame") or {}
                            no = frame.get("no", frame.get("frame.number", "?"))
                            proto = frame.get("proto", frame.get("_ws.col.Protocol", "UNKNOWN"))
                            src = frame.get("src", frame.get("ip.src", ""))
                            dst = frame.get("dst", frame.get("ip.dst", ""))
                            info = frame.get("info", frame.get("_ws.col.Info", ""))
                            self.after(0, self._append_live_line, f"{str(no):>6}  {str(proto):<8} {src} → {dst}  {info}")
            except Exception as exc:  # noqa: BLE001
                if not self.live_stop_event.is_set():
                    self.after(0, lambda exc=exc: self._set_status(f"实时帧流连接结束：{exc}"))
        try:
            import asyncio
            asyncio.run(consume())
        except Exception as exc:  # noqa: BLE001
            if not self.live_stop_event.is_set():
                self.after(0, lambda exc=exc: self._set_status(f"实时帧流不可用：{exc}"))

    def _append_live_line(self, line: str) -> None:
        self.live_lines.append(line)
        self.live_lines = self.live_lines[-500:]
        self.live_text.configure(state="normal")
        self.live_text.delete("1.0", "end")
        self.live_text.insert("1.0", "\n".join(self.live_lines))
        self.live_text.see("end")
        self.live_text.configure(state="disabled")

    def _poll_live_status(self) -> None:
        if not self.live_running:
            return
        def worker() -> None:
            try:
                status = api_request("/api/live/status")
                count = status.get("frame_count", 0) if isinstance(status, dict) else 0
                self.after(0, lambda: self.live_count_label.configure(text=f"{count} 帧"))
                if isinstance(status, dict) and not status.get("running", False) and self.live_running:
                    self.after(0, self._live_stopped)
                if count > 0 and self.live_warmup:
                    self.after(0, self._live_ready)
            except ApiError:
                pass
        threading.Thread(target=worker, daemon=True).start()
        self.live_poll_after = self.after(2000, self._poll_live_status)

    def stop_live(self) -> None:
        def worker() -> None:
            try:
                api_request("/api/live/stop", "POST")
            except ApiError:
                pass
            self.after(0, self._live_stopped)
        threading.Thread(target=worker, daemon=True).start()

    def _live_stopped(self) -> None:
        self.live_running = False
        self.live_stop_event.set()
        self.live_start_btn.configure(state="normal")
        self.live_stop_btn.configure(state="disabled")
        self.live_status_label.configure(text="● 已停止", fg=DIM)
        self.live_warmup = False
        self.live_hint_label.configure(text="提示：抓包已停止，当前缓冲仍可分析。", fg=DIM)
        self._set_status("实时抓包已停止，当前缓冲仍可分析。")

    def _live_ready(self) -> None:
        self.live_warmup = False
        self.live_hint_label.configure(text="提示：已收到报文，实时抓包正常运行。", fg=GREEN)

    def analyze_live(self) -> None:
        def worker() -> None:
            try:
                if self.live_running:
                    api_request("/api/live/stop", "POST")
                    self.after(0, self._live_stopped)
                result = api_request("/api/live/analyze", "POST", {"name": "实时抓包"}, timeout=120)
                capture = api_request(f"/api/captures/{result['capture_id']}")
                report = api_request(f"/api/reports/{result['report_id']}")
                self.after(0, lambda: self.render_report(capture, report))
                self.after(0, self.refresh_captures)
                self.after(0, self.refresh_history)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("分析实时数据失败", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _build_kb_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_columnconfigure(0, weight=1)
        self.pages["kb"] = page
        head = tk.Frame(page, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 12))
        tk.Label(head, text="知识库", bg=BG, fg=TEXT, font=("Microsoft YaHei UI", 19, "bold")).pack(side="left")
        self._button(head, "刷新统计", self.refresh_kb_stats).pack(side="right")
        self.kb_stats_label = tk.Frame(page, bg=BG)
        self.kb_stats_label.grid(row=1, column=0, sticky="ew", padx=28, pady=8)
        for column in range(4):
            self.kb_stats_label.grid_columnconfigure(column, weight=1)
        self.kb_path_label = tk.Label(page, text="", bg=BG, fg=DIM, font=("Microsoft YaHei UI", 10), anchor="w")
        self.kb_path_label.grid(row=2, column=0, sticky="ew", padx=28, pady=12)
        self.refresh_kb_stats()

    def refresh_kb_stats(self) -> None:
        def worker() -> None:
            try:
                data = api_request("/api/kb/articles")
                articles = data.get("articles", []) if isinstance(data, dict) else []
                settings = api_request("/api/settings")
                self.after(0, lambda: self._render_kb_stats(articles, settings.get("kb_dir", "") if isinstance(settings, dict) else ""))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self._render_kb_stats([], "", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _render_kb_stats(self, articles: list[dict[str, Any]], path: str, error: str | None = None) -> None:
        self._clear_children(self.kb_stats_label)
        if error:
            tk.Label(self.kb_stats_label, text=f"知识库读取失败：{error}", bg=BG, fg=RED,
                     font=("Microsoft YaHei UI", 10)).grid(row=0, column=0, columnspan=4, sticky="w")
            return
        rule_ids = {str(r) for a in articles for r in (a.get("rule_ids") or [])}
        protocols = {str(p) for a in articles for p in (a.get("protocols") or [])}
        stats = (("文章数量", len(articles), ACCENT), ("覆盖规则", len(rule_ids), GREEN),
                 ("涉及协议", len(protocols), YELLOW), ("来源", "本地 Markdown", ORANGE))
        for index, (label, value, color) in enumerate(stats):
            card = tk.Frame(self.kb_stats_label, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 8, 0))
            tk.Label(card, text=str(value), bg=PANEL, fg=color, font=("Consolas", 22, "bold")).pack(anchor="w", padx=16, pady=(14, 2))
            tk.Label(card, text=label, bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=16, pady=(0, 14))
        self.kb_path_label.configure(text=f"知识库目录：{path or '未配置'}\n报告中的规则命中会自动关联对应知识库文章。")

    def _build_settings_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_columnconfigure(0, weight=1)
        self.pages["settings"] = page
        tk.Label(page, text="系统设置", bg=BG, fg=TEXT, font=("Microsoft YaHei UI", 19, "bold")).grid(
            row=0, column=0, sticky="w", padx=28, pady=(24, 12))
        form = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        form.grid(row=1, column=0, sticky="ew", padx=28, pady=4)
        form.grid_columnconfigure(1, weight=1)
        self.settings_vars: dict[str, tk.Variable] = {
            "tshark_path": tk.StringVar(), "base_url": tk.StringVar(), "api_key": tk.StringVar(),
            "model": tk.StringVar(), "kb_dir": tk.StringVar(), "llm_enabled": tk.BooleanVar(value=False),
            "masking_enabled": tk.BooleanVar(value=False),
        }
        row = 0
        tk.Label(form, text="分析引擎", bg=PANEL, fg=ACCENT, font=("Microsoft YaHei UI", 13, "bold")).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 8)); row += 1
        row = self._settings_entry(form, row, "tshark 路径", "tshark_path", "例如 C:\\Program Files\\Wireshark\\tshark.exe")
        tk.Label(form, text="云端 AI API（OpenAI 兼容协议）", bg=PANEL, fg=ACCENT,
                 font=("Microsoft YaHei UI", 13, "bold")).grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 8)); row += 1
        enabled = tk.Checkbutton(form, text="启用 AI 辅助分析（不改变规则结论）", variable=self.settings_vars["llm_enabled"],
                                 bg=PANEL, fg=TEXT, activebackground=PANEL, activeforeground=TEXT,
                                 selectcolor=PANEL2, anchor="w", font=("Microsoft YaHei UI", 10))
        enabled.grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=5); row += 1
        row = self._settings_entry(form, row, "Base URL", "base_url", "https://api.example.com/v1")
        row = self._settings_entry(form, row, "API Key", "api_key", "留空保留已保存密钥；填写新值可替换", password=True)
        row = self._settings_entry(form, row, "模型", "model", "deepseek-chat / gpt-4o-mini")
        tk.Label(form, text="本地数据", bg=PANEL, fg=ACCENT, font=("Microsoft YaHei UI", 13, "bold")).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 8)); row += 1
        row = self._settings_entry(form, row, "知识库目录", "kb_dir", "后端本机的 Markdown 目录")
        tk.Label(form, text="隐私保护", bg=PANEL, fg=ACCENT,
                 font=("Microsoft YaHei UI", 13, "bold")).grid(row=row, column=0, columnspan=2,
                                                               sticky="w", padx=18, pady=(18, 8)); row += 1
        masking = tk.Checkbutton(form, text="分析前对 IP / 域名脱敏（默认关闭）", variable=self.settings_vars["masking_enabled"],
                                 bg=PANEL, fg=TEXT, activebackground=PANEL, activeforeground=TEXT,
                                 selectcolor=PANEL2, anchor="w", font=("Microsoft YaHei UI", 10))
        masking.grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=5); row += 1
        self.settings_message = tk.Label(form, text="", bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 9), anchor="w")
        self.settings_message.grid(row=row, column=0, columnspan=2, sticky="ew", padx=18, pady=(8, 2)); row += 1
        actions = tk.Frame(form, bg=PANEL)
        actions.grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=(4, 18))
        self._button(actions, "测试 API 连接", self.test_llm_settings).pack(side="left", padx=(0, 8))
        self._button(actions, "保存设置", self.save_settings, primary=True).pack(side="left")
        self.settings_loaded = False

    def _settings_entry(self, parent: tk.Misc, row: int, label: str, key: str,
                        placeholder: str, password: bool = False) -> int:
        tk.Label(parent, text=label, bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 10), width=16, anchor="w").grid(
            row=row, column=0, sticky="w", padx=18, pady=5)
        tk.Entry(parent, textvariable=self.settings_vars[key], show="*" if password else "",
                 bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Consolas", 10),
                 width=70).grid(row=row, column=1, sticky="ew", padx=(0, 18), pady=5, ipady=5)
        return row + 1

    def load_settings_form(self) -> None:
        def worker() -> None:
            try:
                settings = api_request("/api/settings")
                self.after(0, lambda: self._apply_settings(settings if isinstance(settings, dict) else {}))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self.settings_message.configure(text=f"加载设置失败：{exc}", fg=RED))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_settings(self, settings: dict[str, Any]) -> None:
        llm_settings = settings.get("llm") or {}
        masking = settings.get("masking") or {}
        self.settings_vars["tshark_path"].set(settings.get("tshark_path", ""))
        self.settings_vars["base_url"].set(llm_settings.get("base_url", ""))
        self.settings_vars["api_key"].set(llm_settings.get("api_key", ""))
        self.settings_vars["model"].set(llm_settings.get("model", ""))
        self.settings_vars["llm_enabled"].set(bool(llm_settings.get("enabled")))
        self.settings_vars["kb_dir"].set(settings.get("kb_dir", ""))
        self.settings_vars["masking_enabled"].set(bool(masking.get("enabled", False)))
        self.settings_loaded = True
        self.settings_message.configure(text="设置已加载。", fg=DIM)

    def _settings_payload(self) -> dict[str, Any]:
        v = self.settings_vars
        return {"tshark_path": str(v["tshark_path"].get()), "kb_dir": str(v["kb_dir"].get()),
                "masking": {"enabled": bool(v["masking_enabled"].get())},
                "llm": {"enabled": bool(v["llm_enabled"].get()), "base_url": str(v["base_url"].get()),
                        "api_key": str(v["api_key"].get()), "model": str(v["model"].get())}}

    def save_settings(self) -> None:
        payload = self._settings_payload()
        def worker() -> None:
            try:
                saved = api_request("/api/settings", "PUT", payload)
                self.after(0, lambda: self._apply_settings(saved))
                self.after(0, lambda: self.settings_message.configure(text="设置已保存。", fg=GREEN))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self.settings_message.configure(text=f"保存失败：{exc}", fg=RED))
        threading.Thread(target=worker, daemon=True).start()

    def test_llm_settings(self) -> None:
        payload = self._settings_payload()
        self.settings_message.configure(text="正在测试云端 API…", fg=YELLOW)
        def worker() -> None:
            try:
                result = api_request("/api/llm/test", "POST", payload, timeout=45)
                self.after(0, lambda: self.settings_message.configure(text=f"连接成功：{result.get('reply', '模型已响应')}", fg=GREEN))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: self.settings_message.configure(text=f"连接失败：{exc}", fg=RED))
        threading.Thread(target=worker, daemon=True).start()

    def _build_report_page(self) -> None:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_rowconfigure(3, weight=1)
        page.grid_columnconfigure(0, weight=1)
        self.pages["report"] = page

        heading = tk.Frame(page, bg=BG)
        heading.grid(row=0, column=0, sticky="ew", padx=32, pady=(26, 20))
        self._label(heading, "一键分析", font=("Microsoft YaHei UI", 20, "bold")).pack(anchor="w")
        self._label(heading, "从一份抓包开始，定位网络中的异常。", fg=DIM).pack(anchor="w", pady=(6, 0))

        self.drop_zone = tk.Frame(
            page, bg=PANEL, cursor="hand2", height=138, takefocus=True,
            highlightbackground=BORDER, highlightcolor=ACCENT, highlightthickness=1,
        )
        self.drop_zone.grid(row=1, column=0, sticky="ew", padx=32, pady=(0, 20))
        self.drop_zone.grid_propagate(False)
        drop_copy = tk.Frame(self.drop_zone, bg=PANEL)
        drop_copy.place(relx=0.5, rely=0.5, anchor="center")
        self.drop_title = tk.Label(
            drop_copy, text="拖放抓包文件到这里，或点击选择文件", bg=PANEL, fg=TEXT,
            font=("Microsoft YaHei UI", 14, "bold"), cursor="hand2",
        )
        self.drop_title.pack()
        self.drop_hint = tk.Label(
            drop_copy, text="支持 PCAP、PCAPNG、CAP 及 gzip 压缩抓包 · 每次导入一个文件",
            bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 9), cursor="hand2",
        )
        self.drop_hint.pack(pady=(10, 0))
        self.drop_zone.bind("<Return>", lambda _event: self.choose_capture())
        self.drop_zone.bind("<space>", lambda _event: self.choose_capture())
        for widget in (self.drop_zone, drop_copy, self.drop_title, self.drop_hint):
            widget.bind("<Button-1>", lambda _event: self.choose_capture())
            widget.bind("<Enter>", self._drop_zone_enter)
            widget.bind("<Leave>", self._drop_zone_leave)
        if DND_FILES and hasattr(self.drop_zone, "drop_target_register"):
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_capture_drop)

        toolbar = tk.Frame(page, bg=BG)
        toolbar.grid(row=2, column=0, sticky="ew", padx=32, pady=(0, 14))
        toolbar.grid_columnconfigure(1, weight=1)
        self._label(toolbar, "当前抓包", fg=DIM, font=("Microsoft YaHei UI", 9)).grid(row=0, column=0, sticky="w", padx=(0, 14))
        self.report_capture_var = tk.StringVar(value="选择捕获文件…")
        self.report_capture_combo = ttk.Combobox(toolbar, textvariable=self.report_capture_var,
                                                 state="readonly", style="Dark.TCombobox", width=28)
        self.report_capture_combo.grid(row=0, column=1, padx=(0, 16), ipady=5, sticky="ew")
        self.report_capture_combo.bind("<<ComboboxSelected>>", self._on_report_capture)
        self.analyze_btn = self._button(toolbar, "开始诊断", self.analyze_selected, primary=True)
        self.analyze_btn.grid(row=0, column=2, padx=(0, 8))
        self.ai_btn = self._button(toolbar, "AI 分析", self.analyze_ai_direct)
        self.ai_btn.configure(state="disabled")
        self.ai_btn.grid(row=0, column=3)
        self._label(toolbar, "诊断报告", fg=DIM, font=("Microsoft YaHei UI", 9)).grid(row=1, column=0, sticky="w", padx=(0, 14), pady=(16, 0))
        self.report_var = tk.StringVar(value="")
        self.report_combo = ttk.Combobox(toolbar, textvariable=self.report_var, state="readonly",
                                         style="Dark.TCombobox", width=26)
        self.report_combo.grid(row=1, column=1, padx=(0, 16), pady=(16, 0), ipady=5, sticky="ew")
        self.report_combo.bind("<<ComboboxSelected>>", self._on_report_selected)
        self.report_progress = ttk.Progressbar(toolbar, style="Dark.Horizontal.TProgressbar",
                                               mode="determinate", maximum=100, length=180)
        self.report_progress.grid(row=1, column=2, padx=(0, 8), pady=(16, 0), sticky="ew")
        stage_slot = tk.Frame(toolbar, bg=BG, width=150, height=39)
        stage_slot.grid(row=1, column=3, pady=(16, 0), sticky="ew")
        stage_slot.grid_propagate(False)
        self.stage_label = tk.Label(stage_slot, text="待诊断", bg=BG, fg=DIM,
                                    font=("Microsoft YaHei UI", 9), anchor="w")
        self.stage_label.pack(fill="both", expand=True)

        body = tk.Frame(page, bg=BG)
        body.grid(row=3, column=0, sticky="nsew", padx=32, pady=(0, 24))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        self.report_scroll = ScrollableFrame(body, bg=BG)
        self.report_scroll.grid(row=0, column=0, sticky="nsew")
        self.report_scroll.inner.grid_columnconfigure(0, weight=1)
        self.report_content = self.report_scroll.inner
        self._render_empty_report()

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if not page:
            return
        page.tkraise()
        if key == "history" and hasattr(self, "history_content"):
            self.refresh_history()
        elif key == "captures" and hasattr(self, "capture_list_content"):
            self.refresh_captures()
        elif key == "live" and hasattr(self, "iface_combo"):
            self.refresh_live_interfaces()
        elif key == "kb" and hasattr(self, "kb_stats_label"):
            self.refresh_kb_stats()
        elif key == "settings" and hasattr(self, "settings_loaded") and not self.settings_loaded:
            self.load_settings_form()
        for name, btn in self.nav_buttons.items():
            btn.configure(bg="#172238" if name == key else DEEP,
                          fg=ACCENT if name == key else DIM)

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def _set_stage(self, text: str, color: str = DIM) -> None:
        self.stage_label.configure(text=text, fg=color)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.analyze_btn.configure(state=state)
        self._set_drop_zone_enabled(not busy)
        self.ai_btn.configure(state="disabled" if busy or not self.capture else "normal")
        self.report_progress.configure(value=8 if busy else (100 if self.report else 0))
        if busy:
            self._set_stage("诊断中…", YELLOW)
        elif self.report:
            self._set_stage("诊断完成", GREEN)
        elif self.stage_label.cget("text") == "诊断中…":
            self._set_stage("待诊断")

    def _capture_label(self, capture: dict[str, Any]) -> str:
        return f"{capture.get('name', '未命名')}（{capture.get('frame_count', 0)} 帧）"

    def _capture_by_label(self, label: str) -> dict[str, Any] | None:
        return next((c for c in self.captures if self._capture_label(c) == label), None)

    def refresh_captures(self) -> None:
        def worker() -> None:
            try:
                data = api_request("/api/captures")
                captures = data.get("captures", []) if isinstance(data, dict) else []
                reports_data = api_request("/api/reports")
                reports = reports_data.get("reports", []) if isinstance(reports_data, dict) else []
                self.after(0, lambda: self._set_captures(captures, reports))
                self.after(0, lambda: self.backend_label.configure(text="● 后端已连接", fg=GREEN))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self.backend_label.configure(text="● 后端不可达", fg=RED))
                self.after(0, lambda exc=exc: self._set_status(f"后端连接失败：{exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def _set_captures(self, captures: list[dict[str, Any]], reports: list[dict[str, Any]] | None = None) -> None:
        self.all_captures = [c for c in captures if isinstance(c, dict)]
        if reports is not None:
            self.reports_by_capture = {}
            for report in reports:
                if not isinstance(report, dict):
                    continue
                capture_id = str(report.get("capture_id") or "")
                self.reports_by_capture.setdefault(capture_id, []).append(report)
        self.captures = [c for c in self.all_captures if c.get("status") == "ready"]
        labels = [self._capture_label(c) for c in self.captures]
        self.report_capture_combo.configure(values=labels)
        current = next((c for c in self.captures if self.capture and c.get("id") == self.capture.get("id")), None)
        if current:
            self._select_capture(current)
        elif self.capture and not current:
            self.capture = None
            self.report = None
            self.report_capture_var.set("选择捕获文件…")
            self._render_empty_report()
        if hasattr(self, "capture_list_content"):
            self._render_capture_list(self.all_captures)

    def _select_capture(self, capture: dict[str, Any]) -> None:
        changed = not self.capture or self.capture.get("id") != capture.get("id")
        label = self._capture_label(capture)
        self.report_capture_var.set(label)
        self.capture = capture
        if changed:
            self.report = None
            self._set_reports([])
            self._render_empty_report("已切换抓包文件，请选择历史报告或重新开始诊断。")
        self.ai_btn.configure(state="disabled" if self.busy else "normal")
        self._load_reports(capture.get("id"))

    def _on_report_capture(self, _event: object = None) -> None:
        capture = self._capture_by_label(self.report_capture_var.get())
        if capture:
            self._select_capture(capture)

    def _load_reports(self, capture_id: str | None) -> None:
        if not capture_id:
            return
        def worker() -> None:
            try:
                data = api_request(f"/api/reports?capture_id={capture_id}")
                reports = data if isinstance(data, list) else data.get("reports", []) if isinstance(data, dict) else []
                def apply_reports() -> None:
                    if self.capture and str(self.capture.get("id")) == str(capture_id):
                        self._set_reports(reports)
                self.after(0, apply_reports)
            except ApiError:
                def clear_reports() -> None:
                    if self.capture and str(self.capture.get("id")) == str(capture_id):
                        self._set_reports([])
                self.after(0, clear_reports)
        threading.Thread(target=worker, daemon=True).start()

    def _set_reports(self, reports: list[dict[str, Any]]) -> None:
        self.report_records = reports
        values = [f"{self._report_capture_name(item)} · {self._report_time(item.get('created_at'))}"
                  f"{self._report_marker(item)}" for item in reports]
        self.report_combo.configure(values=values)
        self.report_var.set("选择报告" if values else "暂无报告")

    def _on_report_selected(self, _event: object = None) -> None:
        index = self.report_combo.current()
        if index < 0 or index >= len(self.report_records):
            return
        report_id = self.report_records[index].get("id")
        if not report_id:
            return
        capture = dict(self.capture or {})
        capture_id = str(capture.get("id") or "")
        def worker() -> None:
            try:
                report = api_request(f"/api/reports/{report_id}")
                def apply_report() -> None:
                    current_id = str((self.capture or {}).get("id") or "")
                    if current_id == capture_id and str(report.get("capture_id") or "") == capture_id:
                        self.render_report(capture, report)
                self.after(0, apply_report)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("报告加载失败", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def choose_capture(self) -> None:
        if self.busy:
            return
        path = filedialog.askopenfilename(
            title="选择 pcap/pcapng 抓包文件",
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz"),
                       ("All files", "*.*")],
        )
        if path:
            self._accept_capture_path(Path(path))

    def _set_drop_zone_enabled(self, enabled: bool) -> None:
        if not hasattr(self, "drop_zone"):
            return
        self.drop_enabled = enabled
        color = BORDER
        title = "拖放抓包文件到这里，或点击选择文件" if enabled else "正在处理当前抓包文件…"
        self.drop_zone.configure(highlightbackground=color)
        self.drop_title.configure(text=title, fg=TEXT if enabled else DIM)

    def _drop_zone_enter(self, _event: object = None) -> None:
        if not self.busy:
            self.drop_zone.configure(bg=PANEL2, highlightbackground=ACCENT)
            self.drop_title.configure(bg=PANEL2)
            self.drop_hint.configure(bg=PANEL2)
            for child in self.drop_title.master.winfo_children():
                child.configure(bg=PANEL2)
            self.drop_title.master.configure(bg=PANEL2)

    def _drop_zone_leave(self, _event: object = None) -> None:
        self.drop_zone.configure(bg=PANEL, highlightbackground=BORDER)
        self.drop_title.master.configure(bg=PANEL)
        self.drop_title.configure(bg=PANEL)
        self.drop_hint.configure(bg=PANEL)

    def _on_capture_drop(self, event: object) -> str:
        if self.busy:
            return "break"
        paths = parse_drop_files(str(getattr(event, "data", "")))
        if len(paths) != 1:
            messagebox.showwarning("无法导入", "请每次只拖入一个抓包文件。")
            return "break"
        self._accept_capture_path(paths[0])
        return "break"

    def _accept_capture_path(self, path: Path) -> None:
        if not path.is_file():
            messagebox.showerror("无法导入", "文件不存在或无法读取，请重新选择。")
            return
        if not is_supported_capture(path):
            messagebox.showerror("无法导入", "仅支持 PCAP、PCAPNG、CAP 或 gzip 压缩抓包文件。")
            return
        self._start_pipeline(path)

    def _start_pipeline(self, path: Path) -> None:
        if self.busy:
            return
        self.show_page("report")
        self._set_busy(True)
        self.report_capture_var.set(f"正在导入：{path.name}")
        self._render_empty_report("正在导入并解析抓包文件…")
        threading.Thread(target=self._pipeline_worker, args=(path,), daemon=True).start()

    def _pipeline_worker(self, path: Path) -> None:
        try:
            self.root_status("提交导入请求…")
            started = api_request("/api/captures/import", "POST", {"path": str(path)})
            capture_id = str(started["capture_id"])
            capture = None
            for _ in range(240):
                capture = api_request(f"/api/captures/{capture_id}")
                if capture.get("status") == "ready":
                    break
                if capture.get("status") == "error":
                    raise ApiError(str(capture.get("error") or "抓包解析失败"))
                self.root_status(f"自动解析中… 已完成 {capture.get('frame_count', 0)} 帧")
                time.sleep(0.5)
            if not capture or capture.get("status") != "ready":
                raise ApiError("解析超时,请检查 tshark 配置")
            self.after(0, self._set_capture_after_import, capture)
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda exc=exc: messagebox.showerror("诊断失败", str(exc)))
            self.root_status("诊断失败,请检查后端日志或 tshark 配置。")
        finally:
            self.after(0, lambda: self._set_busy(False))

    def _set_captures_after_import(self, capture: dict[str, Any], report: dict[str, Any]) -> None:
        capture_id = str(capture.get("id") or "")
        self.reports_by_capture[capture_id] = [report]
        self._set_captures(self.all_captures + [capture])
        self._select_capture(capture)
        self.render_report(capture, report)

    def _set_capture_after_import(self, capture: dict[str, Any]) -> None:
        """导入完成后等待用户选择规则诊断或 AI 直达分析。"""
        self._set_captures(self.all_captures + [capture])
        self._select_capture(capture)
        self._render_empty_report("导入完成，请选择“开始诊断”或“AI直达分析”。")
        self._set_status(f"导入完成：{capture.get('name', '')}，请选择分析方式。")

    def analyze_selected(self) -> None:
        capture = self._capture_by_label(self.report_capture_var.get())
        if not capture:
            messagebox.showinfo("开始诊断", "请先选择一个已就绪的捕获文件。")
            return
        if self.busy:
            return
        self._set_busy(True)
        self._render_empty_report("正在生成诊断报告…")
        capture_id = str(capture["id"])
        def worker() -> None:
            try:
                self.root_status("规则诊断与可选 AI 辅助分析中…")
                result = api_request(
                    f"/api/captures/{capture_id}/analyze", "POST",
                    timeout=ANALYSIS_TIMEOUT_SECONDS,
                )
                report = api_request(f"/api/reports/{result['report_id']}")
                def apply_report() -> None:
                    if str((self.capture or {}).get("id") or "") != capture_id:
                        return
                    self.render_report(capture, report)
                    if not str(report.get("narrative") or "").strip():
                        self._poll_report_narrative(str(result["report_id"]), capture)
                self.after(0, apply_report)
                self.after(0, lambda: self._load_reports(capture_id))
                self.after(0, self.refresh_captures)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("分析失败", str(exc)))
                self.root_status("分析失败,请检查后端日志。")
            finally:
                self.after(0, lambda: self._set_busy(False))
        threading.Thread(target=worker, daemon=True).start()

    def _poll_report_narrative(self, report_id: str, capture: dict[str, Any],
                               attempts: int = 15) -> None:
        """Refresh an asynchronously generated AI narrative without blocking Tk."""
        if attempts <= 0:
            return
        capture_id = str(capture.get("id") or "")

        def worker() -> None:
            try:
                report = api_request(f"/api/reports/{report_id}", timeout=30)
            except ApiError:
                report = None

            def apply() -> None:
                if str((self.capture or {}).get("id") or "") != capture_id:
                    return
                if isinstance(report, dict) and str(report.get("narrative") or "").strip():
                    self.render_report(capture, report)
                    return
                if attempts > 1:
                    self.after(
                        2000,
                        lambda: DesktopApp._poll_report_narrative(
                            self, report_id, capture, attempts - 1
                        ),
                    )

            self.after(0, apply)

        threading.Thread(target=worker, daemon=True).start()

    def analyze_ai_direct(self) -> None:
        """直接把当前抓包摘要交给 AI,跳过本地规则和知识库。"""
        capture = self._capture_by_label(self.report_capture_var.get()) or self.capture
        if not capture:
            messagebox.showinfo("AI直达分析", "请先选择一个已就绪的捕获文件。")
            return
        if self.busy:
            return
        self.capture = capture
        self._set_busy(True)
        self._render_empty_report("正在请求 AI 直达分析（跳过本地规则和知识库）…")
        capture_id = str(capture["id"])

        def worker() -> None:
            try:
                self.root_status("AI 直达分析中（跳过本地规则和知识库）…")
                result = api_request(f"/api/captures/{capture_id}/analyze?mode=ai_direct", "POST", timeout=60)
                report = api_request(f"/api/reports/{result['report_id']}")
                self.after(0, lambda: self.render_report(capture, report))
                self.after(0, lambda: self._load_reports(capture_id))
                self.after(0, self.refresh_captures)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("AI直达分析失败", str(exc)))
                self.root_status("AI直达分析失败；可改用本地规则诊断。")
            finally:
                self.after(0, lambda: self._set_busy(False))
        threading.Thread(target=worker, daemon=True).start()

    def root_status(self, text: str) -> None:
        def apply_status() -> None:
            self._set_status(text)
            self._set_stage("诊断中…" if self.busy else text, YELLOW if self.busy else DIM)
        self.after(0, apply_status)

    def _clear_children(self, parent: tk.Misc) -> None:
        for child in parent.winfo_children():
            child.destroy()

    def _reset_report_scroll(self) -> None:
        """切换报告/重新诊断时回到报告顶部,避免沿用上一份报告的滚动位置。"""
        if not hasattr(self, "report_scroll"):
            return
        self.report_scroll.canvas.yview_moveto(0.0)
        self.after_idle(lambda: self.report_scroll.canvas.yview_moveto(0.0))

    def _render_empty_report(self, message: str = "选择一个捕获文件,点击“开始诊断”运行规则引擎,或点击“AI直达分析”跳过本地规则和知识库。") -> None:
        self._reset_report_scroll()
        self._clear_children(self.report_content)
        card = tk.Frame(self.report_content, bg=BG)
        card.grid(row=0, column=0, sticky="ew", pady=(24, 8))
        title = empty_report_title(message)
        tk.Label(card, text=title, bg=BG, fg=TEXT, font=("Microsoft YaHei UI", 16, "bold"),
                 anchor="w").pack(fill="x", pady=(0, 10))
        description = tk.Label(card, text=message, bg=BG, fg=DIM, font=("Microsoft YaHei UI", 10),
                               anchor="w", justify="left", wraplength=760)
        description.pack(fill="x", pady=(0, 24))
        card.bind("<Configure>", lambda event: description.configure(wraplength=max(200, event.width - 24)))
        self.ai_btn.configure(state="disabled" if self.busy or not self.capture else "normal")

    def _add_stat_chips(self, parent: tk.Misc, stats: dict[str, Any]) -> None:
        if not stats:
            return
        row = tk.Frame(parent, bg=PANEL2)
        row.pack(fill="x", padx=14, pady=(9, 3))
        for key, value in stats.items():
            text = f"{key}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}"
            tk.Label(row, text=text, bg="#151820", fg=DIM, font=("Consolas", 9),
                     padx=7, pady=4).pack(side="left", padx=(0, 6), pady=2)

    def run_ai_analysis(self) -> None:
        if not self.report or getattr(self, "ai_busy", False):
            return
        self.ai_busy = True
        self.ai_btn.configure(state="disabled", text="分析中…")
        self._set_status("正在请求 AI 辅助分析，规则结论不会改变…")
        report_id = str(self.report.get("id"))

        def worker() -> None:
            try:
                report = api_request(f"/api/reports/{report_id}/ai", "POST", timeout=45)
                self.after(0, lambda: self.render_report(self.capture or {}, report))
                self.after(0, self.refresh_history)
                self.after(0, self.refresh_captures)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda exc=exc: messagebox.showerror("AI 分析失败", str(exc)))
                self.root_status("AI 分析失败；规则诊断结果仍然有效。")
            finally:
                self.after(0, self._finish_ai)
        threading.Thread(target=worker, daemon=True).start()

    def _finish_ai(self) -> None:
        self.ai_busy = False
        if hasattr(self, "ai_btn"):
            self.ai_btn.configure(state="normal" if self.report else "disabled", text="AI 分析")

    def _add_finding_card(self, parent: tk.Misc, finding: dict[str, Any], color: str) -> None:
        card = tk.Frame(parent, bg=PANEL2, highlightbackground=color, highlightthickness=2)
        card.pack(fill="x", padx=14, pady=(0, 12))
        head = tk.Frame(card, bg=PANEL2)
        head.pack(fill="x", padx=14, pady=(12, 5))
        tk.Label(head, text=str(finding.get("rule_id", "-")), bg="#111722", fg=ACCENT,
                 font=("Consolas", 10, "bold"), padx=8, pady=3).pack(side="left")
        tk.Label(head, text=str(finding.get("title", "未命名问题")), bg=PANEL2, fg=TEXT,
                 font=("Microsoft YaHei UI", 12, "bold"), anchor="w").pack(side="left", padx=10, fill="x", expand=True)
        self._add_stat_chips(card, finding.get("stats") if isinstance(finding.get("stats"), dict) else {})
        evidence = finding.get("evidence_frames") or []
        if evidence:
            line = tk.Frame(card, bg=PANEL2)
            line.pack(fill="x", padx=14, pady=(5, 4))
            tk.Label(line, text="证据帧:", bg=PANEL2, fg=DIM, font=("Microsoft YaHei UI", 9)).pack(side="left")
            for no in evidence[:30]:
                tk.Button(line, text=str(no), bg="#111722", fg=ACCENT, relief="flat", bd=0,
                          font=("Consolas", 9), padx=5, pady=2,
                          command=lambda n=no: self._set_status(f"证据帧 {n}：原生迁移版已保留帧号，可在报文明细中复核。"))\
                    .pack(side="left", padx=(5, 0))
            if len(evidence) > 30:
                tk.Label(line, text=f"…共 {len(evidence)} 帧", bg=PANEL2, fg=DIM,
                         font=("Microsoft YaHei UI", 9)).pack(side="left", padx=6)
        suggestion = str(finding.get("suggestion") or "")
        if suggestion:
            tk.Label(card, text=f"处置建议: {suggestion}", bg=PANEL2, fg=TEXT,
                     font=("Microsoft YaHei UI", 10), justify="left", anchor="w",
                     wraplength=760).pack(fill="x", padx=14, pady=(5, 7))
        kb_ids = finding.get("kb_ids") or []
        if kb_ids:
            line = tk.Frame(card, bg=PANEL2)
            line.pack(fill="x", padx=14, pady=(0, 12))
            tk.Label(line, text="知识库:", bg=PANEL2, fg=DIM, font=("Microsoft YaHei UI", 9)).pack(side="left")
            for kb in kb_ids:
                tk.Label(line, text=str(kb), bg="#111722", fg=ACCENT, font=("Consolas", 9), padx=6, pady=2).pack(side="left", padx=5)

    def render_report(self, capture: dict[str, Any], report: dict[str, Any]) -> None:
        self.capture = capture
        self.report = report
        self.show_page("report")
        self._reset_report_scroll()
        self.report_progress.configure(value=100)
        self.stage_label.configure(text="诊断完成", fg=GREEN)
        self.ai_btn.configure(state="normal")
        self.ai_btn.configure(state="normal")
        findings = norm_findings(report.get("findings"))
        ai_direct = self._is_ai_direct(report)
        self._clear_children(self.report_content)
        header = tk.Frame(self.report_content, bg=BG)
        header.grid(row=0, column=0, sticky="ew", padx=4, pady=(5, 10))
        tk.Label(header, text="诊断报告", bg=BG, fg=TEXT, font=("Microsoft YaHei UI", 20, "bold")).pack(side="left")
        tk.Label(header, text=f"#{report.get('id', '-')}", bg=BG, fg=DIM, font=("Consolas", 10)).pack(side="left", padx=14)
        if report.get("masked"):
            tk.Label(header, text="已脱敏", bg="#3c321b", fg=YELLOW, font=("Microsoft YaHei UI", 9), padx=8, pady=3).pack(side="left")
        tk.Label(header, text="AI直达分析" if ai_direct else "本地规则引擎",
                 bg="#172238" if ai_direct else "#20242d", fg=ACCENT if ai_direct else DIM,
                 font=("Microsoft YaHei UI", 9), padx=8, pady=3).pack(side="left", padx=6)
        self._button(header, "导出 HTML", lambda: self.export_report("html")).pack(side="right")

        mode_card = tk.Frame(self.report_content, bg="#172238" if ai_direct else PANEL2,
                             highlightbackground=ACCENT if ai_direct else BORDER, highlightthickness=1)
        mode_card.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        mode_text = ("AI 直达分析：已跳过本地规则引擎和知识库关联，以下内容由 AI 根据抓包摘要生成，请结合原始报文核验。"
                     if ai_direct else "本地规则引擎分析：报告结论来自确定性规则，AI 辅助分析只做文字复述。")
        tk.Label(mode_card, text=mode_text, bg=mode_card.cget("bg"),
                 fg=TEXT if ai_direct else DIM, font=("Microsoft YaHei UI", 10),
                 justify="left", anchor="w", wraplength=900).pack(fill="x", padx=14, pady=10)

        brief = report.get("brief") or build_brief(report | {"capture_name": capture.get("name")}, findings)
        brief_card = tk.Frame(self.report_content, bg=PANEL, highlightbackground=ACCENT, highlightthickness=2)
        brief_card.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        tk.Label(brief_card, text="简报", bg=PANEL, fg=ACCENT, font=("Microsoft YaHei UI", 13, "bold"), anchor="w").pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(brief_card, text=brief, bg=PANEL, fg=TEXT, font=("Microsoft YaHei UI", 11), justify="left", anchor="w", wraplength=780).pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(brief_card, text="更多详情请导出 HTML 报告查看。", bg=PANEL, fg=DIM, font=("Microsoft YaHei UI", 9), anchor="w").pack(fill="x", padx=16, pady=(0, 12))

        row = 3
        if report.get("summary"):
            summary = tk.Frame(self.report_content, bg=PANEL, highlightbackground=ACCENT, highlightthickness=1)
            summary.grid(row=row, column=0, sticky="ew", padx=4, pady=4)
            tk.Label(summary, text=f"规则摘要：{report['summary']}", bg=PANEL, fg=DIM,
                     font=("Microsoft YaHei UI", 10), justify="left", anchor="w", wraplength=780).pack(fill="x", padx=14, pady=12)
            row += 1
        coverage = report.get("coverage") or {}
        if coverage:
            text = (f"专家告警覆盖：error {coverage.get('expert_errors', 0)} / warn {coverage.get('expert_warns', 0)}，"
                    f"未被规则覆盖 {coverage.get('unconsumed', 0)} 帧")
            tk.Label(self.report_content, text=text, bg=BG, fg=DIM, font=("Microsoft YaHei UI", 9), anchor="w").grid(
                row=row, column=0, sticky="ew", padx=4, pady=(8, 10))
            row += 1
        grouped = [(tier, [f for f in findings if f.get("tier") == tier]) for tier in ("confirmed", "suspect", "potential")]
        for tier, items in grouped:
            if not items:
                continue
            label, color, header_bg = self.TIER_META[tier]
            section = tk.Frame(self.report_content, bg=header_bg, highlightbackground=color, highlightthickness=1)
            section.grid(row=row, column=0, sticky="ew", padx=4, pady=(3, 12))
            tk.Label(section, text=f"{label}({len(items)})", bg=header_bg, fg=color,
                     font=("Microsoft YaHei UI", 14, "bold"), anchor="w").pack(fill="x", padx=14, pady=10)
            for finding in items:
                self._add_finding_card(section, finding, color)
            row += 1
        if not findings:
            empty_text = ("本次为 AI 直达分析，未运行本地规则，因此不提供规则命中列表。"
                          if ai_direct else "本报告没有检出任何问题。")
            tk.Label(self.report_content, text=empty_text, bg=BG, fg=DIM,
                     font=("Microsoft YaHei UI", 11), anchor="w").grid(row=row, column=0, sticky="ew", padx=4, pady=20)
            row += 1
        narrative = str(report.get("narrative") or "").strip()
        if narrative:
            self._add_ai_report_card(self.report_content, row, narrative, ai_direct=ai_direct)
        status = (f"AI直达分析完成：{capture.get('name', '')}，{capture.get('frame_count', 0)} 帧。"
                  if ai_direct else
                  f"诊断完成：{capture.get('name', '')}，{capture.get('frame_count', 0)} 帧，命中 {len(findings)} 项规则。")
        self._set_status(status)

    def _add_ai_report_card(self, parent: tk.Misc, row: int, narrative: str,
                            ai_direct: bool = False) -> None:
        card = tk.Frame(parent, bg="#1d293d", highlightbackground=ACCENT, highlightthickness=2)
        card.grid(row=row, column=0, sticky="ew", padx=4, pady=(4, 14))
        tk.Label(card, text="AI 直达分析" if ai_direct else "AI 辅助分析", bg="#1d293d", fg=ACCENT,
                 font=("Microsoft YaHei UI", 14, "bold"), anchor="w").pack(fill="x", padx=16, pady=(12, 5))
        tk.Label(card, text=narrative, bg="#1d293d", fg=TEXT,
                 font=("Microsoft YaHei UI", 10), justify="left", anchor="nw",
                 wraplength=800).pack(fill="x", padx=16, pady=(0, 12))

    def export_report(self, fmt: str) -> None:
        if not self.report or fmt != "html":
            return
        suffix = ".html"
        path = filedialog.asksaveasfilename(
            title="导出诊断报告", defaultextension=suffix,
            initialfile=f"pcapcheck-report-{self.report.get('id', 'report')}{suffix}",
            filetypes=[("HTML", "*.html")],
        )
        if not path:
            return
        try:
            request = urllib.request.Request(f"{BASE_URL}/api/reports/{self.report['id']}/export?format=html")
            with urllib.request.urlopen(request, timeout=30) as response:
                Path(path).write_bytes(response.read())
            messagebox.showinfo("导出完成", f"报告已保存到:\n{path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("导出失败", str(exc))

    def close(self) -> None:
        if hasattr(self, "live_stop_event"):
            self.live_stop_event.set()
        if getattr(self, "live_poll_after", None):
            try:
                self.after_cancel(self.live_poll_after)
            except tk.TclError:
                pass
        if getattr(self, "live_running", False):
            try:
                api_request("/api/live/stop", "POST", timeout=2)
            except ApiError:
                pass
        if self.owned_backend and self.owned_backend.poll() is None:
            self.owned_backend.terminate()
            try:
                self.owned_backend.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.owned_backend.kill()
        self.destroy()


def main() -> None:
    try:
        _enable_windows_dpi_awareness()
        owned = ensure_backend()
        app = DesktopApp(owned)
        app.mainloop()
    except Exception as exc:  # noqa: BLE001
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("报文检查启动失败", str(exc))
        root.destroy()
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
