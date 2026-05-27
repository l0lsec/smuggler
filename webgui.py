#!/usr/bin/env python3
"""NiceGUI web frontend for smuggler.py.

Run with:  python3 webgui.py
Then open: http://127.0.0.1:8765

The GUI is a thin wrapper around the existing CLI. Every option in
`smuggler.py`'s argparse block is exposed as a form control; pressing
Start spawns `python3 -u smuggler.py <flags>` as a subprocess and streams
its (ANSI-colored) stdout into the browser in real time. Stop sends
SIGINT (which `ReplayManager` already treats as a clean shutdown), then
escalates to SIGTERM/SIGKILL.

Single-user, localhost-only by default.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import html
import os
import re
import shlex
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
	from nicegui import app, ui
except ImportError as exc:  # pragma: no cover - friendly error if user forgot pip install
	sys.stderr.write(
		"webgui.py needs nicegui. Install with:\n"
		"    pip install -r requirements.txt\n"
		"or  pip install 'nicegui>=2.0'\n"
		f"(import error: {exc})\n"
	)
	sys.exit(1)


SMUGGLER_DIR = Path(__file__).resolve().parent
SMUGGLER_PY = SMUGGLER_DIR / "smuggler.py"
PAYLOADS_DIR = SMUGGLER_DIR / "payloads"
TMP_DIR = SMUGGLER_DIR / "tmp" / "webgui"
TMP_DIR.mkdir(parents=True, exist_ok=True)

SCAN_TYPES = [
	"tecl", "clte", "cl0", "pause", "connection-state",
	"parser-discrepancy", "header-removal", "expect",
	"te0", "bare-lf", "hop-by-hop", "h2", "all",
]


# ---------------------------------------------------------------------------
# ANSI -> HTML
# ---------------------------------------------------------------------------

# Smuggler only ever uses a small subset of SGR codes (basic 8-color FG +
# bright/reset). We map them to inline-styled <span>s so the output keeps
# its color in the browser without pulling a heavyweight dep.
ANSI_FG = {
	"30": "#6b7280",  # black -> gray (visible on dark bg)
	"31": "#ef4444",  # red
	"32": "#22c55e",  # green
	"33": "#eab308",  # yellow
	"34": "#3b82f6",  # blue
	"35": "#d946ef",  # magenta
	"36": "#06b6d4",  # cyan
	"37": "#e5e7eb",  # white
	"90": "#9ca3af",
	"91": "#fca5a5",
	"92": "#86efac",
	"93": "#fde68a",
	"94": "#93c5fd",
	"95": "#f0abfc",
	"96": "#67e8f9",
	"97": "#ffffff",
}

_ANSI_RE = re.compile(r"\x1B\[([0-9;]*)m")
_ANSI_STRIP_RE = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")


def ansi_strip(text: str) -> str:
	return _ANSI_STRIP_RE.sub("", text)


def ansi_to_html(text: str) -> str:
	"""Convert smuggler-flavored ANSI into a small HTML span tree."""
	out: list[str] = []
	pos = 0
	open_spans = 0
	for m in _ANSI_RE.finditer(text):
		out.append(html.escape(text[pos:m.start()]))
		pos = m.end()
		params = m.group(1)
		codes = params.split(";") if params else ["0"]
		for code in codes:
			if code in ("", "0"):
				out.append("</span>" * open_spans)
				open_spans = 0
			elif code == "1":
				out.append('<span style="font-weight:600">')
				open_spans += 1
			elif code in ANSI_FG:
				out.append(f'<span style="color:{ANSI_FG[code]}">')
				open_spans += 1
			# other codes (22, 39, 49, etc.) are silently ignored - smuggler
			# doesn't emit them
	out.append(html.escape(text[pos:]))
	out.append("</span>" * open_spans)
	return "".join(out)


# ---------------------------------------------------------------------------
# Run config
# ---------------------------------------------------------------------------

@dataclass
class RunConfig:
	# Target mode: 'url' | 'list' | 'request'
	mode: str = "url"
	url: str = ""
	host_list: str = ""  # newline-separated, for stdin pipe mode
	# Request file: 'upload' | 'path' | 'inline'
	request_source: str = "path"
	request_path: str = ""
	request_inline: str = ""
	baseline_source: str = "path"  # 'path' | 'inline' | 'none'
	baseline_path: str = ""
	baseline_inline: str = ""

	# Shared flags
	vhost: str = ""
	method: str = "POST"
	timeout: float = 5.0
	configfile: str = "default.py"
	proxy: str = ""
	cookies: str = ""
	log_file: str = ""
	scan_types: list = field(default_factory=lambda: ["tecl", "clte"])
	pause_timeout: int = 61

	# Toggles
	replay: bool = False
	persistent_connection: bool = False
	exit_early: bool = False
	quiet: bool = False
	no_color: bool = False
	http2: bool = False


def _write_tmp_request(prefix: str, body: str) -> str:
	path = TMP_DIR / f"{prefix}-{uuid.uuid4().hex[:8]}.req"
	path.write_text(body, encoding="utf-8")
	return str(path)


def resolve_request_files(cfg: RunConfig) -> tuple[Optional[str], Optional[str]]:
	"""Materialize inline / uploaded request bodies into temp files on disk.

	Returns (request_path_or_None, baseline_path_or_None).
	Raises ValueError when the user picked a source but didn't provide content.
	"""
	req_path: Optional[str] = None
	if cfg.mode == "request":
		if cfg.request_source == "inline":
			if not cfg.request_inline.strip():
				raise ValueError("Inline request body is empty.")
			req_path = _write_tmp_request("req", cfg.request_inline)
		elif cfg.request_source in ("path", "upload"):
			if not cfg.request_path:
				raise ValueError("No request file selected.")
			req_path = cfg.request_path

	baseline_path: Optional[str] = None
	if cfg.baseline_source == "inline" and cfg.baseline_inline.strip():
		baseline_path = _write_tmp_request("baseline", cfg.baseline_inline)
	elif cfg.baseline_source in ("path", "upload") and cfg.baseline_path:
		baseline_path = cfg.baseline_path
	return req_path, baseline_path


def build_argv(cfg: RunConfig, req_path: Optional[str], baseline_path: Optional[str]) -> list[str]:
	"""Map a RunConfig into the argv passed to smuggler.py.

	The `-u` flag on the Python interpreter is mandatory: without it we'd
	only see stdout when the buffer flushes, which for smuggler is on
	process exit. With it, each `print_info` lands in the GUI immediately.
	"""
	argv: list[str] = [sys.executable, "-u", str(SMUGGLER_PY)]

	if cfg.mode == "url" and cfg.url.strip():
		argv += ["-u", cfg.url.strip()]
	# 'list' mode feeds stdin; no -u arg is added.

	if req_path:
		argv += ["-r", req_path]
	if baseline_path:
		argv += ["--baseline-request", baseline_path]

	if cfg.vhost.strip():
		argv += ["-v", cfg.vhost.strip()]
	if cfg.method and cfg.method != "POST":
		argv += ["-m", cfg.method]
	if cfg.exit_early:
		argv += ["-x"]
	if cfg.quiet:
		argv += ["-q"]
	if cfg.no_color:
		argv += ["--no-color"]
	try:
		t = float(cfg.timeout)
		if t and t != 5.0:
			argv += ["-t", str(t)]
	except (TypeError, ValueError):
		pass
	if cfg.configfile and cfg.configfile != "default.py":
		argv += ["-c", cfg.configfile]
	if cfg.proxy.strip():
		argv += ["--proxy", cfg.proxy.strip()]
	if cfg.cookies.strip():
		argv += ["--cookies", cfg.cookies]
	if cfg.log_file.strip():
		argv += ["-l", cfg.log_file.strip()]
	if cfg.replay:
		argv += ["--replay"]
	if cfg.persistent_connection:
		argv += ["--persistent-connection"]
	if cfg.http2:
		argv += ["--http2"]

	# scan types: only emit if user changed the default
	scans = [s for s in cfg.scan_types if s]
	if scans and set(scans) != {"tecl", "clte"}:
		argv += ["--scan-type", ",".join(scans)]
	if cfg.pause_timeout and cfg.pause_timeout != 61:
		argv += ["--pause-timeout", str(int(cfg.pause_timeout))]

	return argv


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

REPLAY_STATS_RE = re.compile(
	r"\[REPLAY\]\s+Total:\s*(?P<total>\d+)"
	r"\s*\|\s*Success:\s*(?P<success>\d+)"
	r"\s*\|\s*Failed:\s*(?P<failed>\d+)"
	r"\s*\|\s*Timeout:\s*(?P<timeout>\d+)"
	r"\s*\|\s*Error:\s*(?P<error>\d+)"
	r"(?:\s*\|\s*Baseline:\s*(?P<base_ok>\d+)/(?P<base_total>\d+))?"
	r"\s*\|\s*RPS:\s*(?P<rps>[\d.]+)"
	r"\s*\|\s*ID:\s*(?P<id>REQ-\d+)"
)


class RunState:
	"""Holds the currently active subprocess + UI handles for one session."""

	def __init__(self) -> None:
		self.proc: Optional[asyncio.subprocess.Process] = None
		self.task: Optional[asyncio.Task] = None
		self.started_at: float = 0.0
		self.argv: list[str] = []

	def is_running(self) -> bool:
		return self.proc is not None and self.proc.returncode is None


async def stream_process(
	cfg: RunConfig,
	argv: list[str],
	on_line,             # callable: str (raw line w/ ansi) -> None
	on_status,           # callable: dict -> None  (replay stats)
	on_exit,             # callable: int -> None
	state: RunState,
) -> None:
	"""Spawn smuggler.py, stream stdout line-by-line."""
	stdin_pipe = asyncio.subprocess.PIPE if cfg.mode == "list" else None
	try:
		proc = await asyncio.create_subprocess_exec(
			*argv,
			cwd=str(SMUGGLER_DIR),
			stdin=stdin_pipe,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.STDOUT,
		)
	except FileNotFoundError as e:
		on_line(f"\x1B[31m[webgui] failed to spawn: {e}\x1B[0m\n")
		on_exit(-1)
		return

	state.proc = proc
	state.argv = argv
	state.started_at = time.time()

	# 'list' mode: pipe the newline-separated hosts into stdin
	if cfg.mode == "list" and proc.stdin is not None:
		try:
			proc.stdin.write(cfg.host_list.encode("utf-8", errors="replace"))
			await proc.stdin.drain()
			proc.stdin.close()
		except Exception as e:  # noqa: BLE001
			on_line(f"\x1B[31m[webgui] stdin pipe failed: {e}\x1B[0m\n")

	assert proc.stdout is not None
	try:
		# `readline` here handles both \n and \r-terminated lines. smuggler
		# uses \r to overwrite the in-progress status line; we read whatever
		# the OS gives us in chunks to keep latency low.
		buf = b""
		while True:
			chunk = await proc.stdout.read(4096)
			if not chunk:
				if buf:
					on_line(buf.decode("utf-8", errors="replace"))
					buf = b""
				break
			buf += chunk
			# Flush every complete \n or \r terminated segment.
			while True:
				# Find the earliest line terminator
				idx_n = buf.find(b"\n")
				idx_r = buf.find(b"\r")
				idxs = [i for i in (idx_n, idx_r) if i != -1]
				if not idxs:
					break
				cut = min(idxs) + 1
				piece = buf[:cut]
				buf = buf[cut:]
				text = piece.decode("utf-8", errors="replace")
				on_line(text)
				# Replay stat parsing on the ANSI-stripped form
				stripped = ansi_strip(text)
				m = REPLAY_STATS_RE.search(stripped)
				if m:
					on_status(m.groupdict())
	finally:
		rc = await proc.wait()
		on_exit(rc)
		state.proc = None


async def stop_process(state: RunState, on_line) -> None:
	"""Send SIGINT, then escalate to SIGTERM and SIGKILL."""
	proc = state.proc
	if proc is None or proc.returncode is not None:
		return
	on_line("\x1B[33m[webgui] sending SIGINT (graceful stop)...\x1B[0m\n")
	try:
		proc.send_signal(signal.SIGINT)
	except ProcessLookupError:
		return
	try:
		await asyncio.wait_for(proc.wait(), timeout=3.0)
		return
	except asyncio.TimeoutError:
		pass
	on_line("\x1B[33m[webgui] escalating to SIGTERM...\x1B[0m\n")
	try:
		proc.terminate()
		await asyncio.wait_for(proc.wait(), timeout=3.0)
		return
	except (ProcessLookupError, asyncio.TimeoutError):
		pass
	on_line("\x1B[31m[webgui] escalating to SIGKILL...\x1B[0m\n")
	try:
		proc.kill()
	except ProcessLookupError:
		pass


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

LOG_CSS = """
.smug-log {
	background: #0b1020;
	color: #e5e7eb;
	font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
	font-size: 12px;
	line-height: 1.45;
	padding: 12px;
	border-radius: 6px;
	min-height: 320px;
	max-height: 60vh;
	overflow-y: auto;
	white-space: pre-wrap;
	word-break: break-word;
}
.smug-log .stat-line { background: rgba(255,255,255,0.04); }
.smug-counter { font-variant-numeric: tabular-nums; }
"""


def list_configs() -> list[str]:
	cfgs = sorted(p.name for p in (SMUGGLER_DIR / "configs").glob("*.py")
		if p.name != "__init__.py")
	return cfgs or ["default.py"]


def human_size(n: int) -> str:
	for unit in ("B", "KB", "MB", "GB"):
		if n < 1024:
			return f"{n:.0f} {unit}"
		n /= 1024
	return f"{n:.1f} TB"


@ui.page("/")
def main_page() -> None:  # noqa: C901 - flat layout, easier to read top-to-bottom
	ui.add_head_html(f"<style>{LOG_CSS}</style>")
	cfg = RunConfig()
	state = RunState()
	# UI handles captured by closures further down
	log_html_chunks: list[str] = []
	log_view: dict = {}

	# ---- Header ---------------------------------------------------------
	with ui.row().classes("w-full items-center justify-between"):
		with ui.row().classes("items-center gap-3"):
			ui.icon("bug_report", size="32px").classes("text-cyan-500")
			with ui.column().classes("gap-0"):
				ui.label("Smuggler").classes("text-2xl font-bold")
				ui.label("HTTP Request Smuggling / Desync scanner - web GUI") \
					.classes("text-xs text-gray-500")
		ui.link("github / @l0lsec", "https://github.com/l0lsec/smuggler", new_tab=True) \
			.classes("text-xs text-gray-400")

	ui.separator()

	# ---- Two-column layout ---------------------------------------------
	with ui.row().classes("w-full no-wrap gap-4"):
		# ============= LEFT: form ============================================
		with ui.column().classes("gap-3 w-1/2"):

			# --- Target -----
			with ui.card().classes("w-full"):
				ui.label("Target").classes("text-base font-semibold")
				with ui.tabs().classes("w-full") as target_tabs:
					# Tab `name` is the slug we use as cfg.mode; `label` is the
					# user-facing text. Keeping them in sync removes the
					# string-matching dance from the change handler.
					t_url = ui.tab("url", label="Single URL")
					t_list = ui.tab("list", label="List of hosts")
					t_req = ui.tab("request", label="Request file")
				with ui.tab_panels(target_tabs, value=t_url).classes("w-full") as target_panels:
					with ui.tab_panel(t_url):
						url_in = ui.input("URL", placeholder="https://target.com/path") \
							.bind_value(cfg, "url").classes("w-full")
						with ui.row().classes("w-full gap-2"):
							ui.input("Virtual host", placeholder="optional") \
								.bind_value(cfg, "vhost").classes("flex-grow")
							ui.select(
								["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
								"OPTIONS", "CONNECT", "TRACE"],
								label="Method",
							).bind_value(cfg, "method").classes("w-40")
					with ui.tab_panel(t_list):
						ui.label("One URL per line (piped to smuggler via stdin)") \
							.classes("text-xs text-gray-500")
						ui.textarea(placeholder="https://a.example.com\nhttps://b.example.com") \
							.bind_value(cfg, "host_list").classes("w-full font-mono") \
							.props("rows=6")
					with ui.tab_panel(t_req):
						with ui.row().classes("w-full items-center gap-3"):
							req_source = ui.toggle(
								{"path": "Path", "upload": "Upload", "inline": "Inline edit"},
								value="path",
							).bind_value(cfg, "request_source")
						req_path_row = ui.row().classes("w-full")
						with req_path_row:
							ui.input("Request file path",
								placeholder="tests/req_clean.txt") \
								.bind_value(cfg, "request_path").classes("w-full")
						req_upload_row = ui.row().classes("w-full")
						with req_upload_row:
							async def _on_req_upload(e):
								data = e.content.read()
								name = (e.name or "uploaded.req").replace("/", "_")
								dest = TMP_DIR / f"upload-{uuid.uuid4().hex[:8]}-{name}"
								dest.write_bytes(data)
								cfg.request_path = str(dest)
								ui.notify(f"Saved to {dest}")
							ui.upload(on_upload=_on_req_upload, auto_upload=True,
								max_files=1, label="Drop request file") \
								.classes("w-full")
						req_inline_row = ui.row().classes("w-full")
						with req_inline_row:
							ui.textarea(placeholder="Paste raw HTTP request here") \
								.bind_value(cfg, "request_inline") \
								.classes("w-full font-mono") \
								.props("rows=10")

						def _toggle_req_panels():
							req_path_row.set_visibility(cfg.request_source == "path")
							req_upload_row.set_visibility(cfg.request_source == "upload")
							req_inline_row.set_visibility(cfg.request_source == "inline")
						req_source.on_value_change(lambda _e: _toggle_req_panels())
						_toggle_req_panels()

				def _on_target_tab(e):
					# NiceGUI 3.x passes the tab `name` as a plain string;
					# 2.x passed the Tab element itself. Handle both so the
					# inline-request workflow doesn't silently stay in 'url'
					# mode and drop the user's pasted request.
					val = e.value if hasattr(e, "value") else target_tabs.value
					if hasattr(val, "_props"):
						name = val._props.get("name")
					else:
						name = val if isinstance(val, str) else None
					if name in {"url", "list", "request"}:
						cfg.mode = name
				target_tabs.on_value_change(_on_target_tab)

			# --- Mode / toggles -----
			with ui.card().classes("w-full"):
				ui.label("Mode").classes("text-base font-semibold")
				with ui.row().classes("w-full gap-4 flex-wrap"):
					replay_sw = ui.switch("Replay mode (sends request verbatim, loops until Stop)") \
						.bind_value(cfg, "replay")
					ui.switch("Persistent connection") \
						.bind_value(cfg, "persistent_connection")
					ui.switch("Exit on first finding").bind_value(cfg, "exit_early")
					ui.switch("Quiet").bind_value(cfg, "quiet")
					ui.switch("No color (raw output)").bind_value(cfg, "no_color")
					ui.switch("HTTP/2 downgrade").bind_value(cfg, "http2")

				# Baseline request (only meaningful with --replay)
				ui.separator()
				ui.label("Baseline request (used with --replay for differential comparison)") \
					.classes("text-xs text-gray-500")
				with ui.row().classes("w-full items-center gap-3"):
					baseline_source = ui.toggle(
						{"none": "None", "path": "Path", "upload": "Upload", "inline": "Inline"},
						value="none",
					).bind_value(cfg, "baseline_source")
				b_path_row = ui.row().classes("w-full")
				with b_path_row:
					ui.input("Baseline file path",
						placeholder="tests/baseline_test.txt") \
						.bind_value(cfg, "baseline_path").classes("w-full")
				b_upload_row = ui.row().classes("w-full")
				with b_upload_row:
					async def _on_baseline_upload(e):
						data = e.content.read()
						name = (e.name or "baseline.req").replace("/", "_")
						dest = TMP_DIR / f"baseline-{uuid.uuid4().hex[:8]}-{name}"
						dest.write_bytes(data)
						cfg.baseline_path = str(dest)
						ui.notify(f"Saved to {dest}")
					ui.upload(on_upload=_on_baseline_upload, auto_upload=True,
						max_files=1, label="Drop baseline file") \
						.classes("w-full")
				b_inline_row = ui.row().classes("w-full")
				with b_inline_row:
					ui.textarea(placeholder="Paste raw baseline request") \
						.bind_value(cfg, "baseline_inline") \
						.classes("w-full font-mono") \
						.props("rows=8")

				def _toggle_baseline():
					b_path_row.set_visibility(cfg.baseline_source == "path")
					b_upload_row.set_visibility(cfg.baseline_source == "upload")
					b_inline_row.set_visibility(cfg.baseline_source == "inline")
				baseline_source.on_value_change(lambda _e: _toggle_baseline())
				_toggle_baseline()

			# --- Network / auth -----
			with ui.card().classes("w-full"):
				ui.label("Network & auth").classes("text-base font-semibold")
				ui.input("Proxy", placeholder="http://127.0.0.1:8080") \
					.bind_value(cfg, "proxy").classes("w-full")
				ui.input("Cookies",
					placeholder="sessionid=abc123; csrftoken=xyz789") \
					.bind_value(cfg, "cookies").classes("w-full")
				with ui.row().classes("w-full gap-3"):
					ui.number("Socket timeout (s)", min=1, max=120, step=1) \
						.bind_value(cfg, "timeout").classes("w-40")
					ui.number("Pause timeout (s)", min=1, max=600, step=1) \
						.bind_value(cfg, "pause_timeout").classes("w-40")
					ui.input("Log file", placeholder="optional, e.g. run.log") \
						.bind_value(cfg, "log_file").classes("flex-grow")

			# --- Scan + config -----
			with ui.card().classes("w-full"):
				ui.label("Scans & config").classes("text-base font-semibold")
				ui.select(
					SCAN_TYPES, multiple=True,
					label="Scan types",
				).bind_value(cfg, "scan_types").classes("w-full").props("use-chips")
				ui.select(
					list_configs(),
					label="Config file",
				).bind_value(cfg, "configfile").classes("w-full")
				with ui.row().classes("w-full items-center gap-3"):
					# Live preview of the command we'll spawn
					cmd_preview = ui.label("").classes(
						"text-xs font-mono text-gray-500 break-all flex-grow")
					ui.button("Copy command", icon="content_copy",
						on_click=lambda: (ui.run_javascript(
							f"navigator.clipboard.writeText({_js_str(state.argv or _preview_cmd(cfg))})"
						), ui.notify("Command copied"))).props("flat dense")

				def refresh_cmd_preview():
					try:
						req, base = resolve_request_files_dry(cfg)
						argv = build_argv(cfg, req, base)
					except Exception:  # noqa: BLE001
						argv = []
					cmd_preview.set_text("$ " + " ".join(shlex.quote(a) for a in argv) if argv else "")

				# Refresh preview on any binding change
				ui.timer(0.5, refresh_cmd_preview)

			# --- Controls -----
			with ui.row().classes("w-full gap-2"):
				start_btn = ui.button("Start scan", icon="play_arrow") \
					.props("color=primary unelevated")
				stop_btn = ui.button("Stop", icon="stop") \
					.props("color=negative outline")
				stop_btn.set_visibility(False)
				ui.button("Clear log", icon="delete", on_click=lambda: clear_log()) \
					.props("flat")
				status_label = ui.label("Idle").classes("text-xs text-gray-500 self-center")

		# ============= RIGHT: log + extras ==================================
		with ui.column().classes("gap-3 w-1/2"):

			# --- Replay stats -----
			with ui.card().classes("w-full") as replay_card:
				ui.label("Replay live stats").classes("text-base font-semibold")
				with ui.row().classes("w-full no-wrap gap-3"):
					def stat(name):
						with ui.column().classes("items-center gap-0 flex-grow"):
							ui.label(name).classes("text-[10px] uppercase text-gray-500")
							lbl = ui.label("0").classes("text-xl font-semibold smug-counter")
							return lbl
					stats_lbls = {
						"total": stat("Total"),
						"success": stat("Success"),
						"failed": stat("Failed"),
						"timeout": stat("Timeout"),
						"error": stat("Error"),
						"rps": stat("RPS"),
					}
				baseline_row = ui.row().classes("w-full gap-3")
				with baseline_row:
					ui.label("Baseline:").classes("text-xs text-gray-500 self-center")
					baseline_lbl = ui.label("-").classes("text-sm smug-counter")
				latest_id_lbl = ui.label("").classes("text-[10px] text-gray-500")
			replay_card.set_visibility(False)

			# --- Output log -----
			with ui.card().classes("w-full"):
				with ui.row().classes("w-full items-center justify-between"):
					ui.label("Output").classes("text-base font-semibold")
					ui.label("").bind_text_from(state, "started_at",
						backward=lambda t: f"started {time.strftime('%H:%M:%S', time.localtime(t))}" if t else "") \
						.classes("text-xs text-gray-500")
				# sanitize=False: we control the HTML we inject (it's our own
				# ANSI->span output where the text payload is html.escape()'d
				# inside ansi_to_html). NiceGUI 3.x requires this kwarg.
				log_box = ui.html("", sanitize=False).classes("smug-log w-full")
				log_view["html"] = log_box

			# --- Payloads browser -----
			with ui.card().classes("w-full"):
				with ui.row().classes("w-full items-center justify-between"):
					ui.label("Payloads").classes("text-base font-semibold")
					ui.button("Refresh", icon="refresh",
						on_click=lambda: refresh_payloads()).props("flat dense")
				payloads_box = ui.column().classes("w-full gap-1")

	# Serve payloads/ as static so the download links work
	app.add_static_files("/payloads", str(PAYLOADS_DIR))

	# ------------------------------------------------------------------
	# Helpers / handlers
	# ------------------------------------------------------------------

	def push_log(text: str) -> None:
		if not text:
			return
		htm = ansi_to_html(text)
		# Smuggler uses \r to redraw progress lines; keep them but render with
		# a thin background so they're visibly distinct.
		if "\r" in text and "\n" not in text:
			htm = f'<span class="stat-line">{htm}</span>'
		log_html_chunks.append(htm)
		# Cap history at 4000 chunks so the DOM doesn't grow unboundedly on
		# long replay runs.
		if len(log_html_chunks) > 4000:
			del log_html_chunks[:1000]
		log_box = log_view.get("html")
		if log_box is not None:
			log_box.content = "".join(log_html_chunks)
			ui.run_javascript(
				"const el = document.querySelector('.smug-log');"
				"if (el) { el.scrollTop = el.scrollHeight; }"
			)

	def clear_log() -> None:
		log_html_chunks.clear()
		log_box = log_view.get("html")
		if log_box is not None:
			log_box.content = ""

	def push_status(groups: dict) -> None:
		stats_lbls["total"].set_text(groups["total"])
		stats_lbls["success"].set_text(groups["success"])
		stats_lbls["failed"].set_text(groups["failed"])
		stats_lbls["timeout"].set_text(groups["timeout"])
		stats_lbls["error"].set_text(groups["error"])
		stats_lbls["rps"].set_text(groups["rps"])
		if groups.get("base_total"):
			baseline_lbl.set_text(f"{groups['base_ok']} / {groups['base_total']}")
			baseline_row.set_visibility(True)
		else:
			baseline_row.set_visibility(False)
		latest_id_lbl.set_text(f"Latest request: {groups['id']}")

	def on_exit(rc: int) -> None:
		status_label.set_text(f"Exited (rc={rc})")
		start_btn.set_visibility(True)
		stop_btn.set_visibility(False)
		refresh_payloads()
		ui.notify(f"Smuggler finished (exit code {rc})",
			type="positive" if rc == 0 else "warning")

	async def on_start() -> None:
		if state.is_running():
			ui.notify("A run is already in progress.", type="warning")
			return
		try:
			req_path, baseline_path = resolve_request_files(cfg)
		except ValueError as e:
			ui.notify(str(e), type="negative")
			return

		# Basic guardrails matching smuggler.py argparse expectations
		if cfg.mode == "url" and not cfg.url.strip():
			ui.notify("Enter a URL or switch to another target mode.", type="negative")
			return
		if cfg.mode == "list" and not cfg.host_list.strip():
			ui.notify("Provide at least one host in the list.", type="negative")
			return
		if cfg.mode == "request" and not req_path:
			ui.notify("Pick or paste a request file.", type="negative")
			return
		if cfg.replay and not req_path:
			ui.notify("Replay mode needs a request file.", type="negative")
			return

		argv = build_argv(cfg, req_path, baseline_path)
		clear_log()
		push_log(f"\x1B[36m$ {' '.join(shlex.quote(a) for a in argv)}\x1B[0m\n")
		status_label.set_text("Running...")
		start_btn.set_visibility(False)
		stop_btn.set_visibility(True)
		replay_card.set_visibility(cfg.replay)

		state.task = asyncio.create_task(stream_process(
			cfg, argv, push_log, push_status, on_exit, state,
		))

	async def on_stop() -> None:
		await stop_process(state, push_log)

	start_btn.on_click(on_start)
	stop_btn.on_click(on_stop)

	# ---- Payloads listing ----
	def refresh_payloads():
		payloads_box.clear()
		if not PAYLOADS_DIR.exists():
			with payloads_box:
				ui.label("(no payloads/ directory yet)").classes("text-xs text-gray-500")
			return
		files = sorted(PAYLOADS_DIR.glob("*.txt"),
			key=lambda p: p.stat().st_mtime, reverse=True)
		if not files:
			with payloads_box:
				ui.label("No payload files yet. Run a scan to populate.") \
					.classes("text-xs text-gray-500")
			return
		with payloads_box:
			for p in files[:200]:
				st = p.stat()
				mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
				with ui.row().classes("w-full items-center no-wrap gap-2"):
					ui.icon("description").classes("text-cyan-500")
					ui.label(p.name).classes("font-mono text-xs flex-grow truncate")
					ui.label(f"{human_size(st.st_size)} - {mtime}") \
						.classes("text-[10px] text-gray-500")
					ui.link("download", f"/payloads/{p.name}").props("target=_blank") \
						.classes("text-xs")
	refresh_payloads()


def resolve_request_files_dry(cfg: RunConfig) -> tuple[Optional[str], Optional[str]]:
	"""Like resolve_request_files, but for the cmd-preview only: doesn't
	write temp files (so we don't litter tmp/ every 0.5s). Returns
	placeholder paths for inline sources."""
	req = None
	if cfg.mode == "request":
		if cfg.request_source == "inline":
			req = "<inline-request.req>" if cfg.request_inline.strip() else None
		elif cfg.request_source in ("path", "upload"):
			req = cfg.request_path or None
	baseline = None
	if cfg.baseline_source == "inline" and cfg.baseline_inline.strip():
		baseline = "<inline-baseline.req>"
	elif cfg.baseline_source in ("path", "upload") and cfg.baseline_path:
		baseline = cfg.baseline_path
	return req, baseline


def _preview_cmd(cfg: RunConfig) -> str:
	req, base = resolve_request_files_dry(cfg)
	return " ".join(shlex.quote(a) for a in build_argv(cfg, req, base))


def _js_str(s: str) -> str:
	"""Safely embed a Python string as a JS string literal."""
	return "`" + s.replace("\\", "\\\\").replace("`", "\\`").replace("$", "\\$") + "`"


def parse_cli() -> argparse.Namespace:
	p = argparse.ArgumentParser(description="Smuggler web GUI")
	p.add_argument("--host", default="127.0.0.1",
		help="Bind address (default: 127.0.0.1 -- localhost only).")
	p.add_argument("--port", type=int, default=8765,
		help="Port to listen on (default: 8765).")
	p.add_argument("--public", action="store_true",
		help="Bind to 0.0.0.0 instead of localhost. UNSAFE - anyone with "
		"network access can launch scans from your machine.")
	return p.parse_args()


if __name__ in {"__main__", "__mp_main__"}:
	args = parse_cli()
	bind = "0.0.0.0" if args.public else args.host
	print(f"[smuggler-gui] serving on http://{bind}:{args.port}", file=sys.stderr)
	if args.public:
		print("[smuggler-gui] WARNING: bound on 0.0.0.0 - this is unsafe for an "
			"offensive tool. Anyone who reaches this port can launch scans.",
			file=sys.stderr)
	# favicon: NiceGUI accepts a file path or an emoji (NOT a Quasar icon
	# name -- those only work on in-page ui.icon() calls).
	ui.run(host=bind, port=args.port, title="Smuggler GUI",
		reload=False, show=False, favicon="🐛")
