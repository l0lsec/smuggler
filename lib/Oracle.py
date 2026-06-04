"""GadgetOracle: dynamic gadget selection + auto-derived response signatures.

Background
----------
Every smuggling scanner needs a "gadget" -- a request whose response is
recognizable, so when the gadget is smuggled past the front-end and
processed by the back-end, the victim leg of a pipelined connection
surfaces a response we can fingerprint.

Historically each scanner hard-coded ``GET /robots.txt`` + the substring
``"llow:"``. That breaks against:

* targets that don't serve /robots.txt (404)
* targets where the WAF strips the body
* edges that route /robots.txt to a different upstream than the target
* baselines whose normal response *already* contains "llow:" -> FP
* targets with a different vhost-aware backend

GadgetOracle replaces that single hard-coded pair with a per-target probe:

1. Walk a catalogue of candidate gadgets (OPTIONS, GET /random, robots,
   sitemap, favicon, query-reflection probe) and pick the first that
   returns a successful response on a fresh connection.
2. Fetch a *baseline* of the actual target endpoint on a separate fresh
   connection.
3. Auto-derive a ``look_for`` token guaranteed to be present in the
   gadget response but absent in the baseline: status-line first,
   distinctive header name second, body n-grams third. Fall back to the
   candidate's built-in literal only if all three strategies fail.
4. Inject a per-run canary into the gadget URL (where the gadget URL
   supports a query string) so smuggled-response detection becomes
   "victim response contains <random-token>" -- false-positive resistant
   even on noisy edges.

The oracle is constructed once per target and shared across every
scanner; the viability probe runs at most once.
"""

from __future__ import annotations

import random
import re
import string
from typing import List, Optional, Tuple

from lib.EasySSL import EasySSL


_USER_AGENT = (
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36"
)


def _rand_token(n: int = 12) -> str:
	"""Per-run canary: lowercase + digits so it survives most URL-encoders
	and doesn't accidentally collide with templated server responses."""
	return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _filter_response(res) -> str:
	"""Latin-1-safe decode that maps high bytes to '0' -- mirrors the
	helper in ``lib.Scans`` so signature matching stays consistent."""
	if res is None:
		return ""
	if isinstance(res, (bytes, bytearray)):
		out = []
		for b in res:
			out.append('\x30' if b > 0x7F else chr(b))
		return ''.join(out)
	return res


def _split_response(resp: str) -> Tuple[str, str, str]:
	"""Split a raw HTTP response into (status_line, headers_blob, body).
	Missing sections return as empty strings rather than raising."""
	if not resp:
		return "", "", ""
	hdr_end = resp.find("\r\n\r\n")
	if hdr_end < 0:
		first_break = resp.find("\r\n")
		if first_break < 0:
			return resp, "", ""
		return resp[:first_break], resp[first_break + 2:], ""
	head = resp[:hdr_end]
	body = resp[hdr_end + 4:]
	first_break = head.find("\r\n")
	if first_break < 0:
		return head, "", body
	return head[:first_break], head[first_break + 2:], body


def _header_names(headers_blob: str) -> List[str]:
	names = []
	for line in headers_blob.split("\r\n"):
		idx = line.find(":")
		if idx > 0:
			names.append(line[:idx].strip().lower())
	return names


def _status_code(status_line: str) -> str:
	# "HTTP/1.1 200 OK" -> "200"
	parts = status_line.split(" ", 2)
	return parts[1] if len(parts) >= 2 and len(parts[1]) == 3 else ""


class Gadget:
	"""Result of a successful gadget probe.

	The smuggled request line is ``f"{method} {smuggle_path} HTTP/1.1"``;
	``smuggle_path`` already includes the canary query string when the
	gadget supports one. ``look_for`` is the primary signature; matching
	additionally accepts anything in ``look_for_alt`` (canary token,
	gadget-specific 405 status, etc.).
	"""

	__slots__ = (
		"name", "method", "smuggle_path", "look_for", "look_for_alt",
		"header_only", "canary", "rationale",
	)

	def __init__(self, name, method, smuggle_path, look_for, look_for_alt,
			header_only, canary, rationale):
		self.name = name
		self.method = method
		self.smuggle_path = smuggle_path
		self.look_for = look_for
		self.look_for_alt = list(look_for_alt or [])
		self.header_only = header_only
		self.canary = canary
		self.rationale = rationale

	def matches(self, response_str: str) -> bool:
		if not response_str:
			return False
		region = response_str
		if self.header_only:
			hdr_end = response_str.find("\r\n\r\n")
			if hdr_end > 0:
				region = response_str[:hdr_end]
		for token in [self.look_for] + self.look_for_alt:
			if token and token in region:
				return True
		return False

	def __repr__(self):  # pragma: no cover - debug aid only
		return ("Gadget(name=%r, method=%r, path=%r, look_for=%r, "
				"header_only=%r, rationale=%r)" % (
					self.name, self.method, self.smuggle_path,
					self.look_for, self.header_only, self.rationale))


# Candidate gadgets. Each entry describes how to build the *probe* (sent
# to actually verify viability) and provides a fallback ``look_for`` used
# only when auto-derivation fails. ``supports_query=True`` means the
# canary may be appended as ``?{canary}={canary}``; OPTIONS-on-asterisk
# does not accept this.
_CANDIDATES = [
	{
		"name": "options-asterisk",
		"method": "OPTIONS",
		"path": "*",
		"supports_query": False,
		"fallback_look_for": "Allow:",
		"header_only": True,
	},
	{
		"name": "options-root",
		"method": "OPTIONS",
		"path": "/",
		"supports_query": True,
		"fallback_look_for": "Allow:",
		"header_only": True,
	},
	{
		"name": "random-404",
		"method": "GET",
		# Filled in at probe time with a per-run random segment so the
		# response 404 reliably differs from any cached baseline.
		"path": None,
		"supports_query": True,
		"fallback_look_for": "404",
		"header_only": True,
	},
	{
		"name": "robots",
		"method": "GET",
		"path": "/robots.txt",
		"supports_query": True,
		"fallback_look_for": "llow:",
		"header_only": False,
	},
	{
		"name": "favicon",
		"method": "GET",
		"path": "/favicon.ico",
		"supports_query": True,
		"fallback_look_for": "Content-Type: image/",
		"header_only": True,
	},
	{
		"name": "sitemap",
		"method": "GET",
		"path": "/sitemap.xml",
		"supports_query": True,
		"fallback_look_for": "Content-Type: application/xml",
		"header_only": True,
	},
	{
		"name": "query-reflect",
		"method": "GET",
		# Path is built from the canary at probe time to maximize the
		# chance the server reflects it in the response (errors,
		# pagination, search forms).
		"path": None,
		"supports_query": False,
		"fallback_look_for": None,  # canary is the look_for here
		"header_only": False,
	},
]


_RE_PRINTABLE = re.compile(r"[\x21-\x7e]{8,}")


class GadgetOracle:
	"""Per-target gadget selector with cached result.

	The first call to :meth:`select` runs up to 2*N probes (one per
	candidate + one baseline of the actual target endpoint). Every
	subsequent call returns the cached :class:`Gadget`. ``None`` means we
	couldn't find a usable gadget -- callers fall back to whatever local
	default they had before.
	"""

	def __init__(self, host, port, ssl_flag, timeout, vhost, proxy=None,
			baseline_method="GET", baseline_endpoint="/", quiet=True):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.vhost = vhost or host
		self.proxy = proxy
		self.baseline_method = baseline_method
		self.baseline_endpoint = baseline_endpoint
		self.quiet = quiet
		self._chosen: Optional[Gadget] = None
		self._selected = False
		self._baseline_resp: Optional[str] = None

	@property
	def chosen(self) -> Optional[Gadget]:
		return self._chosen

	def _connect(self) -> EasySSL:
		web = EasySSL(self.ssl_flag)
		web.connect(self.host, self.port, self.timeout, self.proxy)
		return web

	def _build_request(self, method: str, path: str, extra_headers: Optional[List[str]] = None) -> str:
		cb = str(random.random()).split('.')[1]
		# OPTIONS * is the only canonical case where the path must not
		# carry a query/cb at all.
		if path == "*":
			req = "%s * HTTP/1.1\r\n" % method
		else:
			sep = '&' if '?' in path else '?'
			req = "%s %s%scb=%s HTTP/1.1\r\n" % (method, path, sep, cb)
		req += "Host: %s\r\n" % self.vhost
		req += "User-Agent: %s\r\n" % _USER_AGENT
		req += "Accept: */*\r\n"
		if extra_headers:
			for h in extra_headers:
				req += h + "\r\n"
		req += "Content-Length: 0\r\n"
		req += "Connection: close\r\n"
		req += "\r\n"
		return req

	def _send(self, request_str: str) -> Optional[str]:
		try:
			web = self._connect()
			web.send(request_str.encode('latin-1'))
			raw = web.recv_all(self.timeout)
			web.close()
			return _filter_response(raw)
		except Exception:
			return None

	def _capture_baseline(self) -> Optional[str]:
		if self._baseline_resp is not None:
			return self._baseline_resp
		req = self._build_request(self.baseline_method, self.baseline_endpoint)
		self._baseline_resp = self._send(req)
		return self._baseline_resp

	def _derive_signature(self, gadget_resp: str, baseline_resp: str,
			canary: str, fallback: Optional[str]) -> Tuple[str, List[str], bool]:
		"""Return ``(look_for, alt_tokens, header_only)`` for this gadget.

		Strategy, in priority order:

		1. Canary reflection in the response (strongest, per-run unique).
		2. Status-code divergence between gadget and baseline.
		3. Header name present in gadget but not baseline.
		4. Distinctive 8-byte body n-gram present in gadget but not
		   baseline (limited to printable ASCII to avoid binary noise).
		5. Caller-supplied fallback literal.
		"""
		g_status, g_headers, g_body = _split_response(gadget_resp)
		b_status, b_headers, b_body = _split_response(baseline_resp or "")

		alts: List[str] = []
		# Always include the smuggled "405 Method Not Allowed" tell that
		# every legacy scanner used: when the smuggled request reaches the
		# backend but gets rejected, that's still proof of desync. We add
		# it as an alternate so callers don't need separate code paths.
		alts.append("HTTP/1.1 405")

		# 1. Canary
		if canary and (canary in gadget_resp) and (canary not in (baseline_resp or "")):
			return canary, alts, False

		# 2. Status-code divergence
		g_code = _status_code(g_status)
		b_code = _status_code(b_status)
		if g_code and g_code != b_code:
			# Header-only match; "HTTP/1.1 200" is broad enough to match
			# common 200 OK / 200 K responses but specific enough to
			# distinguish from a 404/405 baseline.
			return "HTTP/1.1 %s" % g_code, alts, True

		# 3. Distinctive header name
		g_names = set(_header_names(g_headers))
		b_names = set(_header_names(b_headers))
		diff = g_names - b_names
		# Prefer well-known, low-noise headers that are unlikely to be
		# added by a middlebox between probes.
		for preferred in ("allow", "last-modified", "etag", "content-length",
				"content-type", "location"):
			if preferred in diff:
				# Recover the original case from the gadget response so the
				# look_for matches the actual on-wire bytes.
				for line in g_headers.split("\r\n"):
					if line.lower().startswith(preferred + ":"):
						# Use the header NAME + ":" -- value-independent.
						return line.split(":", 1)[0] + ":", alts, True
		# Any other diff header is still better than nothing.
		for line in g_headers.split("\r\n"):
			name = line.split(":", 1)[0].strip().lower()
			if name and name in diff:
				return line.split(":", 1)[0] + ":", alts, True

		# 4. Body n-gram diff
		if g_body and (g_body != b_body):
			b_set = set(_RE_PRINTABLE.findall(b_body))
			# Sort by length descending so we prefer the most-distinctive
			# (longer) tokens first.
			candidates = sorted(set(_RE_PRINTABLE.findall(g_body)),
				key=lambda s: -len(s))
			for tok in candidates:
				if len(tok) > 64:
					tok = tok[:64]
				if tok and tok not in b_set:
					return tok, alts, False

		# 5. Hard fallback to the candidate's built-in literal.
		if fallback:
			return fallback, alts, False
		# Last-resort: canary, even if it didn't reflect -- gives the
		# caller something to look for so we don't return an unusable
		# Gadget.
		return canary, alts, False

	def _probe_candidate(self, cand: dict, canary: str) -> Optional[Gadget]:
		method = cand["method"]
		fallback = cand.get("fallback_look_for")
		header_only_hint = cand.get("header_only", False)

		# Resolve dynamic paths.
		if cand["name"] == "random-404":
			probe_path = "/" + canary + "-" + _rand_token(6)
			smuggle_path = probe_path
		elif cand["name"] == "query-reflect":
			probe_path = "/?%s=%s" % (canary, canary)
			smuggle_path = probe_path
		else:
			base_path = cand["path"]
			probe_path = base_path
			if cand.get("supports_query"):
				sep = '&' if (base_path and '?' in base_path) else '?'
				smuggle_path = base_path + sep + ("smug=%s" % canary)
			else:
				smuggle_path = base_path

		probe_req = self._build_request(method, probe_path)
		probe_resp = self._send(probe_req)
		if not probe_resp:
			return None

		# Drop probes that the server clearly didn't understand (no
		# status line, or 5xx). 4xx is fine -- a 404 with reflected
		# canary is exactly what we want for the random-404 candidate.
		status_line = probe_resp.split("\r\n", 1)[0] if "\r\n" in probe_resp else probe_resp
		code = _status_code(status_line)
		if not code or code.startswith("5"):
			return None
		# Skip candidates whose response is identical to baseline -- we'd
		# have nothing to distinguish the gadget signature with.
		baseline = self._capture_baseline()
		if baseline is not None and probe_resp == baseline:
			return None

		look_for, alts, header_only = self._derive_signature(
			probe_resp, baseline or "", canary, fallback)
		# Reject any marker that also appears in the baseline. The body-ngram
		# path already excludes baseline tokens, but the `fallback`-literal and
		# last-resort `canary` branches do not -- if e.g. the built-in "llow:"
		# literal is present in the target's normal response, the gadget would
		# fire on every victim leg and manufacture false-positive desyncs.
		if look_for and baseline and look_for in baseline:
			return None
		# Honour the candidate's hint when our derivation didn't already
		# settle the question (e.g. status divergence flips header_only).
		if look_for == fallback and header_only_hint:
			header_only = True

		rationale = []
		if look_for == canary:
			rationale.append("canary reflection")
		elif look_for and look_for.startswith("HTTP/1.1 "):
			rationale.append("status divergence")
		elif look_for and look_for.endswith(":"):
			rationale.append("distinctive header")
		else:
			rationale.append("fallback literal" if look_for == fallback else "body n-gram")

		return Gadget(
			name=cand["name"],
			method=method,
			smuggle_path=smuggle_path,
			look_for=look_for,
			look_for_alt=alts,
			header_only=header_only,
			canary=canary,
			rationale=", ".join(rationale),
		)

	def select(self) -> Optional[Gadget]:
		"""Pick the best gadget for this target. Cached after first call."""
		if self._selected:
			return self._chosen
		self._selected = True

		canary = "smglr" + _rand_token(8)
		for cand in _CANDIDATES:
			try:
				gadget = self._probe_candidate(cand, canary)
			except Exception:
				gadget = None
			if gadget is not None:
				self._chosen = gadget
				return gadget
		return None

	# --- Convenience helpers used by scanners ------------------------------

	def smuggled_request_bytes(self, extra_headers: Optional[List[str]] = None) -> Optional[str]:
		"""Build the bytes of the smuggled request to use as the prefix
		inside an outer desync payload. Returns ``None`` if no gadget is
		available -- caller should keep its legacy default in that case.
		"""
		g = self.select()
		if g is None:
			return None
		path = g.smuggle_path
		if path == "*":
			req = "%s * HTTP/1.1\r\n" % g.method
		else:
			req = "%s %s HTTP/1.1\r\n" % (g.method, path)
		req += "Host: %s\r\n" % self.vhost
		if extra_headers:
			for h in extra_headers:
				req += h + "\r\n"
		req += "X-Smug: 1\r\n\r\n"
		return req
