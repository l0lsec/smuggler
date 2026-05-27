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


# ---------------------------------------------------------------------------
# Payload introspection helpers
# ---------------------------------------------------------------------------
#
# Smuggler dumps payload files into ./payloads/ on every CRITICAL finding.
# The filename encodes scheme + host + scan type + mutation, e.g.
#   https_eprocurement_phoenix_gov_CLTE_xprespace-0a.txt
# The bytes that *cause* the desync (bare LF, tab, 0x09, 0xa0, etc.) are
# invisible in a plain text view, so the GUI needs a hex view too.

def _parse_payload_meta(path: Path) -> dict:
	"""Read a payload file and pull out the bits the GUI needs.

	Returns a dict with: raw (bytes), scheme, port, host, scan_type, mutation.
	`host` is parsed from the Host: header inside the file (more reliable
	than reverse-engineering the underscored hostname in the filename).
	"""
	try:
		raw = path.read_bytes()
	except OSError:
		raw = b""
	scheme = "https" if path.name.lower().startswith("https_") else "http"
	port = 443 if scheme == "https" else 80
	host: Optional[str] = None
	# Walk the header block (up to the first blank line) looking for Host:.
	for line in raw.split(b"\n", 200):
		stripped = line.rstrip(b"\r")
		if not stripped:
			break
		if b":" in stripped:
			k, _, v = stripped.partition(b":")
			if k.strip().lower() == b"host":
				host = v.strip().decode("ascii", errors="replace")
				break
	# Filename pattern is <scheme>_<host>_<scan>_<mutation>.txt; mutation can
	# contain hyphens (e.g. "xprespace-0a") so we work from the right.
	stem = path.stem
	parts = stem.split("_")
	scan_type = parts[-2] if len(parts) >= 3 else "?"
	mutation = parts[-1] if len(parts) >= 2 else "?"
	# Sidecar files written by smuggler when it dumps the payload — give
	# the GUI's View dialog the response that came back and run-time
	# metadata (timing, confidence, gadget_hit, status_label).
	base = str(path)[:-4] if str(path).endswith(".txt") else str(path)
	response_raw: Optional[bytes] = None
	try:
		response_raw = Path(base + ".response.txt").read_bytes()
	except (OSError, FileNotFoundError):
		response_raw = None
	sidecar_meta: dict = {}
	try:
		import json as _json
		sidecar_meta = _json.loads(
			Path(base + ".meta.json").read_text(encoding="utf-8"))
	except (OSError, FileNotFoundError, ValueError):
		sidecar_meta = {}
	return {
		"raw": raw,
		"scheme": scheme,
		"port": port,
		"host": host,
		"scan_type": scan_type,
		"mutation": mutation,
		"response_raw": response_raw,
		"sidecar_meta": sidecar_meta,
	}


def _render_text_html(raw: bytes) -> str:
	"""Render bytes as text, with every non-printable byte highlighted.

	The point of the highlight is that the *single byte* that causes a CL.TE
	mutation (0x09 tab, 0x0a bare LF, 0xa0, etc.) becomes immediately
	visible -- which is exactly the bit you'd otherwise miss skimming the
	payload in a browser tab.
	"""
	out: list[str] = []
	hl = 'background:#7c2d12;color:#fde68a;border-radius:2px;padding:0 2px;margin:0 1px'
	for b in raw:
		if b == 0x0a:
			out.append(f'<span style="{hl}" title="LF (0x0a)">\\n</span>\n')
		elif b == 0x0d:
			out.append(f'<span style="{hl}" title="CR (0x0d)">\\r</span>')
		elif b == 0x09:
			out.append(f'<span style="{hl}" title="TAB (0x09)">\\t</span>')
		elif 0x20 <= b < 0x7f:
			out.append(html.escape(chr(b)))
		else:
			out.append(f'<span style="{hl}" title="0x{b:02x}">\\x{b:02x}</span>')
	return "".join(out)


def _render_hex_html(raw: bytes) -> str:
	"""Standard 16-byte-wide hex dump with non-printables emphasized.

	Cells are always exactly 2 visible chars (or 2 spaces) so the column
	alignment survives even though we wrap weird bytes in <span> tags.
	"""
	hl = 'color:#fde68a;font-weight:600'
	lines: list[str] = []
	for off in range(0, len(raw), 16):
		chunk = raw[off:off + 16]
		cells: list[str] = []
		for i in range(16):
			if i < len(chunk):
				b = chunk[i]
				hi = f"{b:02x}"
				if b in (0x09, 0x0a, 0x0d) or not (0x20 <= b < 0x7f):
					cell = f'<span style="{hl}">{hi}</span>'
				else:
					cell = hi
			else:
				cell = "  "
			cells.append(cell)
		left = " ".join(cells[:8])
		right = " ".join(cells[8:])
		ascii_cells: list[str] = []
		for b in chunk:
			if 0x20 <= b < 0x7f:
				ascii_cells.append(html.escape(chr(b)))
			else:
				ascii_cells.append('<span style="color:#9ca3af">.</span>')
		ascii_str = "".join(ascii_cells)
		lines.append(
			f'<span style="color:#9ca3af">{off:08x}</span>  '
			f'{left}  {right}  |{ascii_str}|'
		)
	return "\n".join(lines)


# ---------------------------------------------------------------------------
# Finding classification
# ---------------------------------------------------------------------------
#
# Smuggler emits findings as plain stdout lines. We parse them here into a
# Finding dataclass that the GUI can render into a structured panel. Two
# buckets matter for the operator:
#
#   - "confirmed": scanner had an intrinsic oracle that fired (gadget hit,
#     3-of-5 / 2-of-3 confirmation, status flip on hop-by-hop, parser
#     discrepancy on canary, etc). High confidence, ready to escalate.
#   - "potential": single-signal heuristic (timing-only TECL/CLTE,
#     keep-alive header-removal, Expect variant) where the scanner can't
#     prove it. Operator needs to confirm manually before reporting.

# Pattern -> (extract confidence, extract scan label) per smuggler emission.
# Pattern matching is deliberately strict: only lines that exactly look like
# a known finding-emission shape are picked up, so we don't classify the
# progress chatter as findings.

def _norm_label(raw: str) -> str:
	"""Canonicalize the scan label for grouping + lookup."""
	m = {
		"CLTE": "CLTE", "TECL": "TECL",
		"CL.0": "CL.0", "0.CL": "CL.0", "TE.0": "TE.0",
		"bare-LF": "BareLF", "bare-CR": "BareCR",
		"pause-based": "Pause", "Pause": "Pause",
		"Expect-based": "Expect", "Expect": "Expect",
		"header removal": "HdrRemoval", "HdrRemoval": "HdrRemoval",
		"ConnState": "ConnState", "ParserDisc": "ParserDisc",
		"HopByHop": "HopByHop", "HTTP/2": "H2", "H2": "H2",
	}
	return m.get(raw, raw)


def _classify_clte_tecl(m, line: str) -> tuple[str, str]:
	conf = "confirmed" if (m.group(1) == "CONFIRMED" or "[gadget=" in line) else "potential"
	return conf, m.group(2)


_FINDING_PATTERNS: list = [
	(re.compile(r"(CONFIRMED|Potential)\s+(CLTE|TECL)\s+Issue Found"),
		_classify_clte_tecl),
	(re.compile(r"Confirmed\s+(CL\.0|0\.CL|TE\.0)\s+desync"),
		lambda m, _line: ("confirmed", _norm_label(m.group(1)))),
	(re.compile(r"Confirmed\s+(bare-LF|bare-CR)\s+chunked\s+desync"),
		lambda m, _line: ("confirmed", _norm_label(m.group(1)))),
	(re.compile(r"Potential pause-based desync confirmed"),
		lambda _m, _line: ("confirmed", "Pause")),
	(re.compile(r"Connection state (?:discrepancy|reflection diff)"),
		lambda _m, _line: ("confirmed", "ConnState")),
	(re.compile(r"Discrepancy:\s+\S+\s+via"),
		lambda _m, _line: ("confirmed", "ParserDisc")),
	(re.compile(r"Front-end strips\s+\S+:"),
		lambda _m, _line: ("confirmed", "HopByHop")),
	(re.compile(r"Potential Expect-based desync"),
		lambda _m, _line: ("potential", "Expect")),
	(re.compile(r"Potential header removal vulnerability"),
		lambda _m, _line: ("potential", "HdrRemoval")),
]

# CRITICAL/Payload line emitted immediately after each finding (smuggler
# always calls write_fn after print_fn on success). We pair findings to
# payloads using the most-recent-unpaired-finding rule.
_PAYLOAD_LINE_RE = re.compile(r"Payload:\s+(\S+\.txt)\s+URL:\s+(\S+)")


def classify_finding(line: str) -> Optional[tuple[str, str]]:
	for rx, fn in _FINDING_PATTERNS:
		m = rx.search(line)
		if m:
			return fn(m, line)
	return None


@dataclass
class Finding:
	id: str
	ts: float
	confidence: str   # "confirmed" | "potential"
	scan: str         # normalized label (CLTE, CL.0, ParserDisc, ...)
	line: str         # full ANSI-stripped finding line (description)
	url: str = ""
	payload_path: str = ""
	payload_name: str = ""


# Per-scan-class confirmation playbook. Each entry is a list of markdown
# bullets. {payload}, {host}, {port}, {scheme}, {url} get formatted in.
# Keep it tight: each step should be something the operator can copy/paste
# or do in <2 minutes. The point is "what evidence makes this real".

_STEPS_GENERIC_REPRO = (
	"Reproduce the payload byte-exact on the wire (no `-crlf` — it would "
	"convert bare LFs in the payload):\n"
	"```\n"
	"(cat {payload}; sleep 5) | openssl s_client -quiet -connect {host}:{port} "
	"-servername {host}\n"
	"```\n"
	"A hanging socket or a 4xx/5xx on the *second* request through the "
	"connection is the desync signal."
)

_STEPS_REPLAY = (
	"Replay the payload through smuggler with a clean baseline and watch the "
	"timing distribution:\n"
	"```\n"
	"python3 smuggler.py -r {payload} --baseline-request tests/req_clean.txt --replay\n"
	"```\n"
	"Look for the smuggling request consistently timing out / 4xx-ing while "
	"the baseline returns 2xx on a fresh connection."
)

CONFIRMATION_STEPS: dict[str, list[str]] = {
	# --- Potential (manual confirmation actually required) -----------------
	"CLTE_potential": [
		_STEPS_GENERIC_REPRO,
		_STEPS_REPLAY,
		"Run with `--persistent-connection` to surface request-pair effects "
		"and rule out a transient timeout.",
		"Repeat at least 20 times. A timing-only finding needs a "
		"deterministic >2x gap between smuggling and baseline to be credible.",
		"Try the same mutation with `-c configs/exhaustive.py` to see if "
		"adjacent mutations (`prespace-09`, `endspace-0a`, etc.) also fire — "
		"a single isolated mutation hitting is sometimes a parser quirk, "
		"a cluster is strong evidence.",
	],
	"TECL_potential": [
		_STEPS_GENERIC_REPRO,
		_STEPS_REPLAY,
		"Run with `--persistent-connection`. TECL desyncs often only show up "
		"when the front-end keeps the back-end socket alive.",
		"Repeat ≥20 times and compare timing distributions; flag only if the "
		"gap is reproducible.",
	],
	"Expect_potential": [
		"Re-issue the exact Expect variant manually with `curl --http1.1 -v "
		"-H 'Expect: <value>' {url}` and compare the status / headers to a "
		"vanilla request.",
		"Try the full ladder: `Expect: 100-continue`, `Expect: y 100-continue`, "
		"`Expect:`, `Expect:  100-continue` (two spaces).",
		_STEPS_GENERIC_REPRO,
		"In Burp's Repeater, send the variant followed by a pipelined victim "
		"request on the same connection and check whether the victim "
		"response reflects the Expect probe.",
	],
	"HdrRemoval_potential": [
		"Re-run with `-q --scan-type header-removal --persistent-connection` "
		"and confirm ≥3 of the 5 paired probes still diverge.",
		"Manually send the harmless paired request, then the attack paired "
		"request, on the same keep-alive connection. The attack pair should "
		"strip a header that the harmless pair didn't.",
		"Likely impact: try smuggling security headers (`X-Forwarded-For`, "
		"`Authorization`, `Cookie`) — if the front-end strips them, the "
		"back-end will trust client-supplied values.",
	],

	# --- Confirmed (impact-demo playbook) ---------------------------------
	"CLTE_confirmed": [
		"Already confirmed via the /robots.txt gadget oracle — the smuggled "
		"request surfaced on a victim socket. This is real.",
		"Build the impact PoC: replace the smuggled `GET /robots.txt` in the "
		"payload with one of (in escalating impact order):\n"
		"  - a request whose response gets cached against a high-value URL "
		"(cache poisoning)\n"
		"  - a `POST` with oversized `Content-Length` that captures the next "
		"victim's `Cookie:` / `Authorization:` into a reflective parameter\n"
		"  - a request to an edge-blocked path (`/admin`, actuator, internal IP)",
		"For a `.gov` / production target, use a **self-collision** PoC: two "
		"of your own sessions on two of your own IPs, prove A receives B's "
		"response. Capture pcaps. No third-party impact required.",
		"Use Burp's HTTP Request Smuggler extension (or "
		"defparam/tiscripts DesyncAttack_CLTE.py) to stage the multi-request "
		"attack.",
	],
	"TECL_confirmed": [
		"Already confirmed via gadget oracle — real.",
		"Same escalation ladder as CLTE: cache poison → credential capture → "
		"front-end control bypass. Self-collision PoC preferred for "
		"production targets.",
		"Try `defparam/tiscripts/DesyncAttack_TECL.py` for staging.",
	],
	"CL.0_confirmed": [
		"Already confirmed via 3-of-5 pipelined victim oracle. Real.",
		"Impact demo: smuggle a request to a path the **front-end blocks but "
		"the back-end serves** — actuators, `/admin`, internal-only servlets. "
		"This is the cleanest CL.0 impact story.",
		"Verify with two parallel connections — attacker connection sends "
		"the smuggling request, victim connection sends a normal request, "
		"victim response leaks the smuggled response body or headers.",
	],
	"TE.0_confirmed": [
		"Already confirmed via 3-of-5 pipelined victim oracle. Real.",
		"Same impact ladder as CL.0 — typically front-end bypass.",
	],
	"BareLF_confirmed": [
		"Already confirmed via 3-of-5 pipelined victim oracle on bare-LF "
		"chunk framing. Real.",
		"Document the exact byte: the framing must use `\\n` (0x0a) without "
		"the preceding `\\r` in the chunk-size terminator. Most fixes are "
		"a single line of front-end config.",
		"Impact demo: same as CL.0/TE.0 — front-end control bypass or "
		"victim hijacking.",
	],
	"BareCR_confirmed": [
		"Already confirmed via 3-of-5 oracle on bare-CR framing.",
		"Same playbook as bare-LF.",
	],
	"Pause_confirmed": [
		"Confirmed via 2-of-3 reproducibility on the pause-based oracle.",
		"Note: the pause window is per-connection. Some CDNs only have this "
		"window for the *first* request on a fresh socket — re-test with "
		"`--persistent-connection` off to confirm whether subsequent "
		"requests still desync.",
		"Impact: classic CL.TE/TE.CL desync once the back-end has consumed "
		"the smuggled prefix. Same escalation ladder.",
	],
	"ConnState_confirmed": [
		"Confirmed via direct-vs-pipelined status flip. Real.",
		"Impact: the back-end pins state (auth, host routing, TLS context) "
		"to the *first* request on a connection — second request through "
		"the same socket inherits that state. Try smuggling a request that "
		"would be rejected on its own but is accepted in the back-end's "
		"first-request context.",
		"Re-test on a fresh socket vs after a known harmless request to "
		"confirm the binding.",
	],
	"ParserDisc_confirmed": [
		"Confirmed via baseline + canary technique. Real.",
		"Re-issue the exact technique + canary manually (Burp Repeater) and "
		"verify the status diff reproduces ≥3 times in a row.",
		"Impact depends on which technique fired — see the description "
		"line. Generally a parser-discrepancy is a stepping stone: it "
		"proves front-end and back-end disagree, which is the necessary "
		"condition for a follow-up smuggling/cache attack.",
	],
	"HopByHop_confirmed": [
		"Confirmed via 2-of-3 status flip when the named header is listed "
		"in `Connection:`. Real.",
		"Impact: front-end strips the header before it reaches the back-end. "
		"Now try smuggling `Connection: Authorization` (strips client auth), "
		"`Connection: X-Forwarded-For` (smuggles client IP), `Connection: "
		"X-Forwarded-Proto`, `Connection: Cookie`. Each unlocks a separate "
		"bypass class.",
		"Document with `curl` paired requests so the triager can replay.",
	],
	"H2_confirmed": [
		"Confirmed via parallel H1 victim oracle — the smuggled HTTP/1.1 "
		"prefix surfaced on a separate H1 connection. Real.",
		"Impact: H2-to-H1 downgrade smuggling. The H2 frontend forwarded "
		"a smuggling-capable H1 stream to the back-end. Same impact ladder "
		"as CL.TE.",
	],
}


def confirmation_steps_for(finding: Finding) -> list[str]:
	"""Return the playbook for this finding, formatted with its context."""
	key = f"{finding.scan}_{finding.confidence}"
	steps = CONFIRMATION_STEPS.get(key) or CONFIRMATION_STEPS.get(
		f"{finding.scan}_confirmed", [])
	if not steps:
		# Last-resort generic playbook so we never render an empty section.
		steps = [_STEPS_GENERIC_REPRO, _STEPS_REPLAY]
	# Format-string substitution
	meta = {"payload": "<no-payload>", "host": "TARGET_HOST",
		"port": 443, "scheme": "https", "url": finding.url or "TARGET_URL"}
	if finding.payload_path:
		pmeta = _parse_payload_meta(Path(finding.payload_path))
		meta.update({
			"payload": shlex.quote(finding.payload_path),
			"host": pmeta.get("host") or "TARGET_HOST",
			"port": pmeta["port"],
			"scheme": pmeta["scheme"],
		})
	out: list[str] = []
	for step in steps:
		try:
			out.append(step.format(**meta))
		except (KeyError, IndexError):
			out.append(step)
	return out


def render_findings_markdown(findings: list[Finding], argv: list[str]) -> str:
	"""Triage-ready Markdown report. Confirmed first, then Potential."""
	confirmed = [f for f in findings if f.confidence == "confirmed"]
	potential = [f for f in findings if f.confidence == "potential"]
	ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
	lines: list[str] = []
	lines.append(f"# Smuggler findings report — {ts}")
	lines.append("")
	if argv:
		lines.append("Invocation:")
		lines.append("```")
		lines.append("$ " + " ".join(shlex.quote(a) for a in argv))
		lines.append("```")
		lines.append("")
	lines.append(f"**Summary:** {len(confirmed)} confirmed, "
		f"{len(potential)} need manual confirmation.")
	lines.append("")

	def _emit(section: str, bucket: list[Finding]) -> None:
		lines.append(f"## {section} ({len(bucket)})")
		lines.append("")
		if not bucket:
			lines.append("_None._")
			lines.append("")
			return
		for i, f in enumerate(bucket, 1):
			lines.append(f"### {i}. {f.scan} — {f.line.strip()}")
			lines.append("")
			if f.url:
				lines.append(f"- URL: `{f.url}`")
			if f.payload_path:
				lines.append(f"- Payload: `{f.payload_path}`")
			lines.append(f"- Detected: {time.strftime('%H:%M:%S', time.localtime(f.ts))}")
			lines.append("")
			lines.append("**Confirmation / escalation steps:**")
			lines.append("")
			for n, step in enumerate(confirmation_steps_for(f), 1):
				# Markdown numbered-list with multi-line content; indent
				# subsequent lines by 3 spaces.
				step_lines = step.split("\n")
				lines.append(f"{n}. {step_lines[0]}")
				for sl in step_lines[1:]:
					lines.append(f"   {sl}")
			lines.append("")

	_emit("Confirmed", confirmed)
	_emit("Needs manual confirmation", potential)
	return "\n".join(lines)


def _repro_cmd_for_payload(path: Path, meta: dict) -> str:
	"""Build a shell one-liner that sends the payload verbatim on the wire.

	Crucial: no `-crlf` on openssl. That option converts every \\n on stdin
	into \\r\\n, which would destroy the bare-LF / lone-CR bytes that make
	the HRS payload work. The `sleep 5` keeps the connection open so we can
	observe the response (or a hanging socket, which itself proves the
	desync). Adjust the sleep to taste.
	"""
	host = meta.get("host") or "TARGET_HOST"
	port = meta["port"]
	pquoted = shlex.quote(str(path))
	if meta["scheme"] == "https":
		return (
			f"(cat {pquoted}; sleep 5) | "
			f"openssl s_client -quiet -connect {host}:{port} "
			f"-servername {host}"
		)
	return f"(cat {pquoted}; sleep 5) | ncat --no-shutdown {host} {port}"


@ui.page("/")
def main_page() -> None:  # noqa: C901 - flat layout, easier to read top-to-bottom
	ui.add_head_html(f"<style>{LOG_CSS}</style>")
	# NiceGUI 3.x requires an explicit client context whenever UI is mutated
	# from a background task. Our subprocess streamer (`stream_process`) runs
	# as an `asyncio.create_task(...)` and its `on_line` / `on_status` /
	# `on_exit` callbacks have no slot stack of their own, so every
	# `ui.notify(...)` / `findings_box.clear()` would raise
	# "The current slot cannot be determined because the slot stack for this
	# task is empty." Capture the client here while we ARE on the page-handler
	# stack and re-enter it from those callbacks via `with page_client:`.
	page_client = ui.context.client
	cfg = RunConfig()
	state = RunState()
	# UI handles captured by closures further down
	log_html_chunks: list[str] = []
	log_view: dict = {}
	# Shared mutable state for the payloads card: which files we've already
	# rendered, and which ones appeared after the most recent on_start()
	# (so we can flag them as "NEW" and notify).
	payload_state: dict = {
		"known": set(),         # all filenames ever seen since page load
		"new": set(),           # filenames added since the last run started
		"last_signature": None, # (count, max-mtime) — cheap change detector
	}
	# Handles the payload row callbacks need to mutate. Populated as the
	# form widgets are constructed below.
	ui_handles: dict = {}
	# Findings parsed out of smuggler's stdout in real time. Reset on Start.
	findings: list[Finding] = []
	# The most recent finding waiting for its CRITICAL/Payload pair line.
	# Smuggler always calls write_fn() right after print_fn() on success, so
	# the next "Payload: ... URL: ..." line we see belongs to this finding.
	pending_finding: dict = {"f": None}

	# ---- Header ---------------------------------------------------------
	with ui.row().classes("w-full items-center justify-between"):
		with ui.row().classes("items-center gap-3"):
			ui.icon("bug_report", size="32px").classes("text-cyan-500")
			with ui.column().classes("gap-0"):
				ui.label("Smuggler").classes("text-2xl font-bold")
				ui.label("HTTP Request Smuggling / Desync scanner - Web GUI") \
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
						# Expose the request-source widgets so the Payloads
						# card can stage "Replay this payload" with one click.
						ui_handles["req_source"] = req_source
						ui_handles["toggle_req_panels"] = _toggle_req_panels

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
				ui_handles["target_tabs"] = target_tabs

			# --- Mode / toggles -----
			with ui.card().classes("w-full"):
				ui.label("Mode").classes("text-base font-semibold")
				with ui.row().classes("w-full gap-4 flex-wrap"):
					replay_sw = ui.switch("Replay mode (sends request verbatim, loops until Stop)") \
						.bind_value(cfg, "replay")
					ui_handles["replay_sw"] = replay_sw
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

			# --- Findings -----
			# Real-time triage panel. Parsed from smuggler stdout into two
			# buckets: high-confidence (oracle fired) and "needs manual
			# confirmation" (single-signal heuristic).
			with ui.card().classes("w-full"):
				with ui.row().classes("w-full items-center justify-between"):
					ui.label("Findings").classes("text-base font-semibold")
					with ui.row().classes("gap-2 items-center"):
						findings_summary = ui.label("0 confirmed • 0 to confirm") \
							.classes("text-xs text-gray-500")
						ui.button("Backfill", icon="restore",
							on_click=lambda: backfill_findings_from_disk()) \
							.props("flat dense") \
							.tooltip("Create findings from existing payloads/*.txt")
						ui.button("Copy as Markdown", icon="article",
							on_click=lambda: _export_findings_md()) \
							.props("flat dense")
				findings_box = ui.column().classes("w-full gap-2")

			# --- Output log -----
			with ui.card().classes("w-full"):
				with ui.row().classes("w-full items-center justify-between"):
					ui.label("Output").classes("text-base font-semibold")
					with ui.row().classes("gap-2 items-center"):
						ui.label("").bind_text_from(state, "started_at",
							backward=lambda t: f"started {time.strftime('%H:%M:%S', time.localtime(t))}" if t else "") \
							.classes("text-xs text-gray-500")
						ui.button("Copy", icon="content_copy",
							on_click=lambda: copy_log_to_clipboard()) \
							.props("flat dense") \
							.tooltip("Copy output log to clipboard")
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
		# Background-task callbacks must enter the page's client context
		# explicitly or NiceGUI raises "slot stack is empty".
		with page_client:
			_push_log_inside(text)

	def _push_log_inside(text: str) -> None:
		# Parse before mutating HTML — findings panel is the user-facing
		# output, log is the debug view.
		_record_finding_from_line(text)
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

	def _record_finding_from_line(text: str) -> None:
		"""Pull Finding objects out of smuggler's stdout as it streams."""
		stripped = ansi_strip(text).strip()
		if not stripped:
			return
		# 1) Is this a finding header?
		classified = classify_finding(stripped)
		if classified is not None:
			conf, scan = classified
			# Pull the URL out of the line if it's a TECL/CLTE-shape message
			url = ""
			m = re.search(r"@\s+(https?://\S+)", stripped)
			if m:
				url = m.group(1).rstrip(",.;")
			f = Finding(
				id=uuid.uuid4().hex[:8],
				ts=time.time(),
				confidence=conf,
				scan=_norm_label(scan),
				line=stripped,
				url=url,
			)
			findings.append(f)
			pending_finding["f"] = f
			rerender_findings()
			label = "Confirmed" if conf == "confirmed" else "Needs manual confirm"
			ui.notify(f"{label}: {f.scan} finding",
				type="positive" if conf == "confirmed" else "warning")
			return
		# 2) Is this the CRITICAL/Payload line that pairs with the last finding?
		mp = _PAYLOAD_LINE_RE.search(stripped)
		if mp and pending_finding["f"] is not None:
			f = pending_finding["f"]
			payload_path = mp.group(1)
			f.payload_path = payload_path
			f.payload_name = os.path.basename(payload_path)
			if not f.url:
				f.url = mp.group(2)
			pending_finding["f"] = None
			rerender_findings()

	def clear_log() -> None:
		log_html_chunks.clear()
		log_box = log_view.get("html")
		if log_box is not None:
			log_box.content = ""

	def copy_log_to_clipboard() -> None:
		# Grab the rendered text (browser converts our ANSI spans to plain
		# text via innerText), strip the per-line copy markers we never add,
		# and hand it to the clipboard. Doing it in JS avoids shipping the
		# whole log buffer through a server-side round-trip.
		if not log_html_chunks:
			ui.notify("Output log is empty.", type="warning")
			return
		ui.run_javascript(
			"(async () => {"
			"  const el = document.querySelector('.smug-log');"
			"  if (!el) return;"
			"  const txt = el.innerText || el.textContent || '';"
			"  try { await navigator.clipboard.writeText(txt); }"
			"  catch (e) {"
			"    const ta = document.createElement('textarea');"
			"    ta.value = txt; document.body.appendChild(ta);"
			"    ta.select(); document.execCommand('copy');"
			"    document.body.removeChild(ta);"
			"  }"
			"})();"
		)
		ui.notify("Output copied to clipboard")

	def push_status(groups: dict) -> None:
		with page_client:
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
		with page_client:
			status_label.set_text(f"Exited (rc={rc})")
			start_btn.set_visibility(True)
			stop_btn.set_visibility(False)
			refresh_payloads(force=True)
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
		findings.clear()
		pending_finding["f"] = None
		rerender_findings()
		push_log(f"\x1B[36m$ {' '.join(shlex.quote(a) for a in argv)}\x1B[0m\n")
		status_label.set_text("Running...")
		start_btn.set_visibility(False)
		stop_btn.set_visibility(True)
		replay_card.set_visibility(cfg.replay)
		# Snapshot the payloads dir so anything that appears during this run
		# is flagged as NEW (and announced via ui.notify) by the periodic
		# refresher below.
		payload_state["new"] = set()
		try:
			payload_state["known"] = {p.name for p in PAYLOADS_DIR.glob("*.txt")}
		except OSError:
			payload_state["known"] = set()
		payload_state["last_signature"] = None
		refresh_payloads()

		state.task = asyncio.create_task(stream_process(
			cfg, argv, push_log, push_status, on_exit, state,
		))

	async def on_stop() -> None:
		await stop_process(state, push_log)

	start_btn.on_click(on_start)
	stop_btn.on_click(on_stop)

	# ---- Payload viewer dialog (built once, reused per click) ----
	#
	# Four panels: REQUEST annotated text, REQUEST hex dump, RESPONSE
	# annotated text, RESPONSE hex dump. The request comes from the
	# payload .txt; the response and run-time metadata (status, timing,
	# confidence, gadget hit) come from the sibling .response.txt and
	# .meta.json sidecars that smuggler writes alongside.
	with ui.dialog() as payload_dlg, ui.card().classes("w-[1000px] max-w-[95vw]"):
		pd_title = ui.label("").classes("text-base font-semibold font-mono break-all")
		pd_meta = ui.label("").classes("text-xs text-gray-500")
		pd_meta2 = ui.label("").classes("text-xs text-gray-400 mt-1")
		ui.separator()
		with ui.tabs().classes("w-full") as pd_tabs:
			pd_tab_req_text = ui.tab("req_text", label="Request — annotated")
			pd_tab_req_hex = ui.tab("req_hex", label="Request — hex")
			pd_tab_res_text = ui.tab("res_text", label="Response — annotated")
			pd_tab_res_hex = ui.tab("res_hex", label="Response — hex")
		with ui.tab_panels(pd_tabs, value=pd_tab_req_text).classes("w-full"):
			with ui.tab_panel(pd_tab_req_text):
				pd_req_text = ui.html("", sanitize=False).classes(
					"smug-log w-full whitespace-pre-wrap")
			with ui.tab_panel(pd_tab_req_hex):
				pd_req_hex = ui.html("", sanitize=False).classes(
					"smug-log w-full whitespace-pre")
			with ui.tab_panel(pd_tab_res_text):
				pd_res_text = ui.html("", sanitize=False).classes(
					"smug-log w-full whitespace-pre-wrap")
			with ui.tab_panel(pd_tab_res_hex):
				pd_res_hex = ui.html("", sanitize=False).classes(
					"smug-log w-full whitespace-pre")
		ui.separator()
		with ui.row().classes("w-full justify-between items-center"):
			pd_repro = ui.label("").classes(
				"text-[11px] font-mono text-gray-500 break-all flex-grow")
			with ui.row().classes("gap-2"):
				pd_copy_btn = ui.button("Copy repro cmd", icon="content_copy") \
					.props("flat dense")
				ui.button("Close", on_click=payload_dlg.close).props("flat")

	def view_payload(path: Path) -> None:
		meta = _parse_payload_meta(path)
		side = meta.get("sidecar_meta") or {}
		resp = meta.get("response_raw")
		pd_title.set_text(path.name)
		# Build the response-bytes summary. Three states:
		#   - resp bytes present  → "response: N bytes"
		#   - resp empty/None but sidecar says timeout/disconnect/error
		#                          → "response: (back-end hung/closed — see tab)"
		#   - resp None and no sidecar (legacy)
		#                          → "response: (not captured)"
		_sl = (side.get("status_label") or "").lower()
		if resp is not None and len(resp) > 0:
			resp_summary = f"response: {len(resp)} bytes"
		elif _sl == "timeout":
			resp_summary = "response: (back-end hung, no bytes received)"
		elif _sl == "disconnect":
			resp_summary = "response: (back-end closed, no bytes received)"
		elif _sl == "error":
			resp_summary = "response: (socket error)"
		elif resp is not None:
			resp_summary = "response: 0 bytes"
		else:
			resp_summary = "response: (not captured)"
		pd_meta.set_text(
			f"{meta['scheme']}://{meta.get('host') or '?'}:{meta['port']}"
			f"   |   scan: {meta['scan_type']}   |   mutation: {meta['mutation']}"
			f"   |   request: {len(meta['raw'])} bytes   |   {resp_summary}"
		)
		# Second meta line: run-time context from .meta.json (when present)
		if side:
			parts = []
			conf = side.get("confidence")
			if conf:
				parts.append(f"confidence: {str(conf).upper()}")
			if side.get("gadget_hit"):
				parts.append("gadget: HIT")
			if side.get("status_label"):
				parts.append(f"status: {side['status_label']}")
			if side.get("timing_s") is not None:
				parts.append(f"timing: {side['timing_s']:.3f}s")
			if side.get("timestamp"):
				parts.append(side["timestamp"].replace("T", " ").rstrip("Z"))
			pd_meta2.set_text("   |   ".join(parts))
			pd_meta2.set_visibility(True)
		else:
			pd_meta2.set_text("")
			pd_meta2.set_visibility(False)

		# Request panels
		pd_req_text.content = _render_text_html(meta["raw"])
		pd_req_hex.content = _render_hex_html(meta["raw"])

		# Response panels — four cases:
		#   1) No response sidecar AND no meta sidecar  → legacy payload
		#      (was dumped before sidecar capture was added).
		#   2) Response sidecar exists, length > 0      → render normally.
		#   3) Response sidecar exists, length == 0,
		#      AND meta says status was timeout/disconnect/error → the
		#      hang IS the desync signal; render a status-aware diagnostic.
		#   4) Response sidecar exists, length == 0, status == normal →
		#      back-end sent a zero-length body (rare but possible).
		status_label = (side.get("status_label") or "").lower()
		timing_s = side.get("timing_s")

		if resp is None and not side:
			# Case 1: pre-sidecar legacy payload
			placeholder = (
				'<div style="padding:14px;color:#fde68a;line-height:1.6">'
				'<strong>Response not captured for this payload.</strong><br><br>'
				'This payload was dumped before sidecar capture was enabled '
				'(or by a scanner class that does not yet store responses).<br>'
				'Re-run the scan to capture future responses automatically, '
				'or use the <em>Copy repro cmd</em> button below to fetch '
				'the response on the wire right now.'
				'</div>'
			)
			pd_res_text.content = placeholder
			pd_res_hex.content = placeholder
		elif (resp is None or len(resp) == 0) and status_label in (
				"timeout", "disconnect", "error"):
			# Case 3: the hang/disconnect IS the desync signal — explain
			# rather than just saying "empty".
			if status_label == "timeout":
				headline = (
					"The back-end never sent a response."
					if timing_s is None
					else f"The back-end hung for {timing_s:.3f}s without "
						"sending anything back, and the socket timed out."
				)
				explanation = (
					"This <strong>is</strong> the desync signal. The back-end "
					"is sitting on the socket waiting for the rest of the "
					"chunked body that the front-end already decided was "
					"complete — classic CL.TE / TE.CL behaviour. There is "
					"literally no response to show."
				)
			elif status_label == "disconnect":
				headline = (
					"The back-end closed the connection without sending a "
					"response"
					+ ("." if timing_s is None
						else f" after {timing_s:.3f}s.")
				)
				explanation = (
					"A clean RST/FIN before the timeout window often means "
					"the back-end's HTTP parser rejected the smuggled frame "
					"(invalid chunk size, length mismatch, etc.). Worth "
					"capturing the request on a proxy to see the back-end "
					"error verbatim if you have access."
				)
			else:  # error
				headline = "The request raised a socket-level exception."
				explanation = (
					"This is usually TLS, DNS, or proxy-side; less commonly "
					"a desync. Re-run with <code>-v</code> to see the "
					"underlying error."
				)
			diag = (
				f'<div style="padding:14px;color:#fde68a;line-height:1.6">'
				f'<strong>{headline}</strong><br><br>{explanation}<br><br>'
				f'<span style="color:#9ca3af">'
				f'status: <strong>{status_label}</strong>'
				+ (f' • timing: <strong>{timing_s:.3f}s</strong>'
					if timing_s is not None else '')
				+ ' • response bytes: <strong>0</strong>'
				+ '</span></div>'
			)
			pd_res_text.content = diag
			pd_res_hex.content = diag
		else:
			# Cases 2 and 4: render whatever bytes we have.
			data = resp if resp is not None else b""
			cap = 32 * 1024
			view = data[:cap]
			note = ""
			if len(data) > cap:
				note = (f'<div style="color:#fde68a;padding:6px 10px">'
					f'(showing first {cap} of {len(data)} bytes — full '
					f'response on disk in {path.name[:-4]}.response.txt)'
					f'</div>')
			elif len(data) == 0:
				note = ('<div style="color:#fde68a;padding:6px 10px">'
					'(back-end returned a zero-length body)</div>')
			pd_res_text.content = note + _render_text_html(view)
			pd_res_hex.content = note + _render_hex_html(view)

		repro = _repro_cmd_for_payload(path, meta)
		pd_repro.set_text("$ " + repro)
		pd_copy_btn.on_click(lambda _=None, c=repro: (
			ui.run_javascript(f"navigator.clipboard.writeText({_js_str(c)})"),
			ui.notify("Reproduction command copied"),
		))
		payload_dlg.open()

	def stage_replay(path: Path) -> None:
		"""Wire the form up so 'Start' will replay this payload verbatim.

		Doesn't auto-start — the user may still want to set --proxy,
		--persistent-connection, or a baseline before running.
		"""
		if state.is_running():
			ui.notify(
				"A scan is already running — stop it before staging a replay.",
				type="warning")
			return
		cfg.mode = "request"
		cfg.request_source = "path"
		cfg.request_path = str(path)
		cfg.replay = True
		# Force the UI widgets to reflect the new cfg (binding alone can lag
		# by one tick, and we want the user's next click to Just Work).
		tt = ui_handles.get("target_tabs")
		if tt is not None:
			tt.set_value("request")
		rs = ui_handles.get("req_source")
		if rs is not None:
			rs.set_value("path")
		tog = ui_handles.get("toggle_req_panels")
		if tog is not None:
			tog()
		rsw = ui_handles.get("replay_sw")
		if rsw is not None:
			rsw.value = True
		ui.notify(f"Staged {path.name} for replay — press Start.",
			type="positive")

	def copy_repro(path: Path) -> None:
		meta = _parse_payload_meta(path)
		cmd = _repro_cmd_for_payload(path, meta)
		ui.run_javascript(f"navigator.clipboard.writeText({_js_str(cmd)})")
		ui.notify("Reproduction command copied")

	def _md_to_html(text: str) -> str:
		"""Tiny markdown subset → HTML for the in-card step rendering.

		Just `code fences`, `inline backticks`, and **bold**. Anything else
		passes through escaped. Keeps us off a markdown dep for ~20 lines.
		"""
		out: list[str] = []
		in_code = False
		for raw_line in text.split("\n"):
			if raw_line.strip() == "```":
				if in_code:
					out.append("</code></pre>")
					in_code = False
				else:
					out.append('<pre style="background:#0b1020;color:#e5e7eb;'
						'padding:8px;border-radius:4px;overflow-x:auto;'
						'font-size:11px;margin:4px 0"><code>')
					in_code = True
				continue
			if in_code:
				out.append(html.escape(raw_line) + "\n")
				continue
			esc = html.escape(raw_line)
			esc = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", esc)
			esc = re.sub(r"`([^`]+)`",
				r'<code style="background:rgba(148,163,184,0.18);'
				r'padding:1px 4px;border-radius:3px;font-size:11px">\1</code>',
				esc)
			out.append(esc + "<br>")
		if in_code:
			out.append("</code></pre>")
		return "".join(out)

	def rerender_findings() -> None:
		confirmed = [f for f in findings if f.confidence == "confirmed"]
		potential = [f for f in findings if f.confidence == "potential"]
		findings_summary.set_text(
			f"{len(confirmed)} confirmed • {len(potential)} to confirm")
		findings_box.clear()
		if not findings:
			with findings_box:
				ui.label("No findings yet. Start a scan to populate.") \
					.classes("text-xs text-gray-500")
			return

		def _render_section(title: str, color_cls: str, icon: str,
				bucket: list[Finding]) -> None:
			if not bucket:
				return
			with findings_box:
				with ui.row().classes("w-full items-center gap-2 mt-1"):
					ui.icon(icon).classes(color_cls)
					ui.label(f"{title} ({len(bucket)})") \
						.classes(f"text-sm font-semibold {color_cls}")
				for f in bucket:
					with ui.expansion(
						f"{f.scan} — {f.line[:90]}"
						+ ("..." if len(f.line) > 90 else ""),
						icon=icon,
					).classes("w-full").props(
						"dense header-class=text-xs"):
						# Body of the expanded panel
						if f.url:
							ui.label(f"URL: {f.url}") \
								.classes("text-xs font-mono break-all")
						with ui.row().classes("text-xs text-gray-500 gap-3"):
							ui.label(time.strftime(
								"%H:%M:%S", time.localtime(f.ts)))
							ui.label(f"scan: {f.scan}")
							ui.label(f"id: {f.id}")
						ui.label(f.line) \
							.classes("text-xs font-mono break-all whitespace-pre-wrap")
						# Payload action row
						if f.payload_path:
							pname = f.payload_name or os.path.basename(
								f.payload_path)
							with ui.row().classes("w-full items-center gap-2 mt-1"):
								ui.icon("description") \
									.classes("text-cyan-500")
								ui.label(pname) \
									.classes("font-mono text-xs flex-grow truncate")
								ui.button(
									"View", icon="visibility",
									on_click=lambda _=None,
										p=Path(f.payload_path):
										view_payload(p),
								).props("flat dense")
								ui.button(
									"Replay", icon="replay",
									on_click=lambda _=None,
										p=Path(f.payload_path):
										stage_replay(p),
								).props("flat dense")
								ui.button(
									"Copy repro", icon="terminal",
									on_click=lambda _=None,
										p=Path(f.payload_path):
										copy_repro(p),
								).props("flat dense")
						else:
							ui.label("(no payload file paired)") \
								.classes("text-xs text-gray-500 italic")
						# Confirmation playbook
						ui.separator()
						ui.label(
							"Confirmation steps"
							if f.confidence == "potential"
							else "Escalation steps"
						).classes("text-xs font-semibold mt-1")
						steps = confirmation_steps_for(f)
						steps_md = "\n".join(
							f"{i+1}. {s}" for i, s in enumerate(steps))
						ui.html(_md_to_html(steps_md), sanitize=False) \
							.classes("text-xs leading-relaxed")
						with ui.row().classes("w-full justify-end gap-2 mt-1"):
							single_md = render_findings_markdown(
								[f], state.argv)
							ui.button(
								"Copy this finding (MD)",
								icon="content_copy",
								on_click=lambda _=None, md=single_md: (
									ui.run_javascript(
										f"navigator.clipboard.writeText("
										f"{_js_str(md)})"),
									ui.notify("Finding copied as Markdown"),
								),
							).props("flat dense")

		_render_section("Confirmed", "text-red-500", "verified", confirmed)
		_render_section(
			"Needs manual confirmation", "text-amber-500",
			"help_outline", potential)

	def _classify_payload_for_backfill(meta_dict: dict) -> tuple[str, str]:
		"""Given a parsed payload (filename + sidecar), guess scan label
		and confidence. Used when we don't have the original stdout line
		(legacy payloads from before findings-parsing landed, or payloads
		from a previous session).
		"""
		side = meta_dict.get("sidecar_meta") or {}
		# Sidecar wins when present — it carries the actual confidence and
		# gadget_hit signal that smuggler computed at write time.
		if side:
			conf = (side.get("confidence") or "").lower()
			if side.get("gadget_hit") or conf == "confirmed":
				return side.get("kind") or meta_dict.get("scan_type", "?"), "confirmed"
			if conf == "potential":
				return side.get("kind") or meta_dict.get("scan_type", "?"), "potential"
		# No sidecar — infer from the ptype segment encoded in the
		# filename. Advanced scanners only write a payload when their
		# intrinsic oracle fires, so those are "confirmed" by default.
		# Classic CLTE/TECL writes payloads in both confirmed and potential
		# cases — without a sidecar we can't tell, so default to potential.
		scan_raw = (meta_dict.get("scan_type") or "?").upper()
		confirmed_prefixes = {
			"CL0": "CL.0", "TE0": "TE.0", "PAUSE": "Pause",
			"CONNSTATE": "ConnState", "PARSERDISC": "ParserDisc",
			"HOPBYHOP": "HopByHop", "BARECHUNK": "BareLF",
		}
		potential_prefixes = {
			"HDRREMOVAL": "HdrRemoval", "EXPECT": "Expect",
		}
		for pref, label in confirmed_prefixes.items():
			if scan_raw.startswith(pref):
				return label, "confirmed"
		for pref, label in potential_prefixes.items():
			if scan_raw.startswith(pref):
				return label, "potential"
		if scan_raw in ("CLTE", "TECL"):
			return scan_raw, "potential"  # unknown without sidecar
		return scan_raw or "?", "potential"

	def backfill_findings_from_disk() -> None:
		"""Create Finding objects from every payload already in payloads/.

		Useful when:
		- The findings parser was broken (e.g. before the page_client fix
		  landed) and a previous run's payloads exist on disk with no
		  matching panel entries.
		- You're resuming a session and want to see prior findings.

		Dedupes by payload filename so clicking twice is a no-op.
		"""
		try:
			files = sorted(PAYLOADS_DIR.glob("*.txt"),
				key=lambda p: p.stat().st_mtime, reverse=True)
		except OSError:
			files = []
		existing = {f.payload_name for f in findings if f.payload_name}
		added = 0
		for p in files:
			if p.name in existing:
				continue
			meta_dict = _parse_payload_meta(p)
			side = meta_dict.get("sidecar_meta") or {}
			scan, confidence = _classify_payload_for_backfill(meta_dict)
			host = meta_dict.get("host") or "?"
			# Prefer the URL recorded in the sidecar (full path) over the
			# scheme+host we can derive from the filename.
			url = side.get("url") or f"{meta_dict['scheme']}://{host}"
			if side:
				conf_word = "CONFIRMED" if (
					side.get("gadget_hit")
					or (side.get("confidence") or "").lower() == "confirmed"
				) else "Potential"
				gadget = " [gadget=/robots.txt]" if side.get("gadget_hit") else ""
				method = side.get("method", "POST")
				cfg_name = side.get("configfile", "?")
				line = (f"{conf_word} {scan} Issue Found - {method} @ {url} - "
					f"{cfg_name}{gadget}  (backfilled from sidecar)")
			else:
				line = (f"{scan} payload on disk — confidence inferred from "
					f"filename (no sidecar; re-run scan for full data)")
			findings.append(Finding(
				id=uuid.uuid4().hex[:8],
				ts=p.stat().st_mtime,
				confidence=confidence,
				scan=_norm_label(scan),
				line=line,
				url=url,
				payload_path=str(p),
				payload_name=p.name,
			))
			added += 1
		# Newest first so the most recent payloads appear at the top.
		findings.sort(key=lambda x: x.ts, reverse=True)
		rerender_findings()
		if added:
			ui.notify(f"Backfilled {added} finding(s) from payloads/",
				type="positive")
		else:
			ui.notify("No new findings to backfill — payloads/ is empty "
				"or every payload is already in the panel.", type="info")

	def _export_findings_md() -> None:
		if not findings:
			ui.notify("No findings to export yet.", type="warning")
			return
		md = render_findings_markdown(findings, state.argv)
		ui.run_javascript(f"navigator.clipboard.writeText({_js_str(md)})")
		# Also drop it to disk for easy follow-up so the user has a copy
		# even if the clipboard write fails in their browser.
		fname = TMP_DIR / f"findings-{time.strftime('%Y%m%d-%H%M%S')}.md"
		try:
			fname.write_text(md, encoding="utf-8")
			ui.notify(f"Findings copied to clipboard + saved to {fname}",
				type="positive")
		except OSError as e:
			ui.notify(f"Copied (disk write failed: {e})", type="warning")

	# ---- Payloads listing ----
	def refresh_payloads(force: bool = False) -> None:
		"""Rebuild the payloads card.

		Called manually (Refresh button, on_exit) and periodically while a
		scan is running. `force=False` is a no-op when nothing on disk has
		changed since last render, so the 2-second auto-refresh timer
		doesn't churn the DOM on every tick.
		"""
		if not PAYLOADS_DIR.exists():
			payloads_box.clear()
			with payloads_box:
				ui.label("(no payloads/ directory yet)") \
					.classes("text-xs text-gray-500")
			return
		try:
			files = sorted(PAYLOADS_DIR.glob("*.txt"),
				key=lambda p: p.stat().st_mtime, reverse=True)
		except OSError:
			files = []
		signature = (
			len(files),
			max((p.stat().st_mtime for p in files), default=0.0),
		)
		# Detect newly-arrived payloads (relative to the snapshot taken at
		# on_start) so we can flag + announce them.
		current_names = {p.name for p in files}
		known = payload_state["known"]
		fresh = current_names - known
		if fresh and state.is_running():
			for name in sorted(fresh):
				ui.notify(f"New payload: {name}", type="positive")
				payload_state["new"].add(name)
		payload_state["known"] = current_names
		if (not force) and signature == payload_state["last_signature"]:
			return
		payload_state["last_signature"] = signature

		payloads_box.clear()
		if not files:
			with payloads_box:
				ui.label("No payload files yet. Run a scan to populate.") \
					.classes("text-xs text-gray-500")
			return
		with payloads_box:
			for p in files[:200]:
				st = p.stat()
				mtime = time.strftime("%Y-%m-%d %H:%M:%S",
					time.localtime(st.st_mtime))
				is_new = p.name in payload_state["new"]
				with ui.row().classes("w-full items-center no-wrap gap-2"):
					ui.icon("description").classes("text-cyan-500")
					with ui.column().classes("gap-0 flex-grow min-w-0"):
						with ui.row().classes("items-center gap-2 no-wrap"):
							ui.label(p.name).classes(
								"font-mono text-xs truncate")
							if is_new:
								ui.badge("NEW", color="positive") \
									.classes("text-[10px]")
						ui.label(f"{human_size(st.st_size)} • {mtime}") \
							.classes("text-[10px] text-gray-500")
					# Captured-by-default lambdas would all close over the
					# loop variable; use default-arg trick to bind per-row.
					ui.button(icon="visibility",
						on_click=lambda _=None, pp=p: view_payload(pp)) \
						.props("flat dense round").tooltip("View (text + hex)")
					ui.button(icon="replay",
						on_click=lambda _=None, pp=p: stage_replay(pp)) \
						.props("flat dense round") \
						.tooltip("Stage as --replay request")
					ui.button(icon="terminal",
						on_click=lambda _=None, pp=p: copy_repro(pp)) \
						.props("flat dense round") \
						.tooltip("Copy openssl/ncat reproduction command")
					ui.button(icon="download",
						on_click=lambda _=None, n=p.name: ui.run_javascript(
							f"window.open('/payloads/{n}', '_blank')"
						)) \
						.props("flat dense round") \
						.tooltip("Download raw bytes")

	# Poll while a run is in progress so freshly-dumped payloads appear
	# (and get flagged NEW) without waiting for the run to finish.
	def _maybe_refresh_payloads() -> None:
		if state.is_running():
			refresh_payloads(force=False)
	ui.timer(2.0, _maybe_refresh_payloads)

	refresh_payloads(force=True)
	rerender_findings()
	# Auto-backfill the Findings panel once on page load so a user who
	# opens the GUI and already has files in payloads/ (from a previous
	# session, or from a run before parsing was working) sees them
	# immediately without having to click anything.
	if not findings:
		try:
			if any(PAYLOADS_DIR.glob("*.txt")):
				backfill_findings_from_disk()
		except OSError:
			pass


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
