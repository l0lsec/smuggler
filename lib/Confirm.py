"""Self-contained desync confirmation.

Confirms a previously-detected smuggling finding using ONLY the operator's
own traffic, on a single connection per check. It never waits for, reads,
or stores any third party's request. The goal is to reliably reproduce the
desync against the operator's own follow-up so a finding can be shown in a
report -- not to capture anyone else's data.

Different detection families manifest differently, so a finding's ``kind``
(read from the ``.meta.json`` sidecar Smuggler writes, falling back to the
filename tag and content markers) routes to one of five confirm modes:

  prefix       CLTE / TECL / CL0 / TE0 / EXPECT / BARELF / parser-discrepancy
               -- pipeline the POC + an own follow-up on one socket and see
               whether the follow-up slot returns a smuggled response.
  differential HDRREMOVAL(_FP) / HOPBYHOP -- send the operator's own request
               with vs without the trigger header and diff the responses.
  connstate    CONNSTATE(_FP/-REFLECT) -- pipeline [setup, canary] on a
               reused connection vs a direct send of the canary, and diff.
  pause        PAUSE -- timed two-part send (headers, pause, prefix) then an
               own follow-up.
  h2           H2_* -- re-drive the HTTP/2 downgrade probe + an own H1
               follow-up via ScanH2Desync.

Every mode writes a 0600 evidence artifact to payloads/confirmations/ that
contains only the operator's own requests and the responses they produced.
"""

import os
import re
import datetime

from lib.EasySSL import EasySSL
from lib.Fingerprint import baseline_fingerprint
from lib.RequestFile import parse_request_file, RequestFileError
from lib.Scans import (
	_make_connection, _filter_response, _get_status,
	_fp_from_bytes_or_str, _is_structurally_different, _structural_diff,
)


class ConfirmError(Exception):
	"""Raised for refusals that must NOT open a socket (bad path, host
	mismatch, unparseable POC). The CLI turns this into a clean error."""


def _repo_payloads_dir():
	import sys
	if os.path.islink(sys.argv[0]):
		me = os.readlink(sys.argv[0])
	else:
		me = sys.argv[0]
	return os.path.join(os.path.realpath(os.path.dirname(me)), "payloads")


def family_for_kind(kind):
	"""Map a finding kind to a confirm mode. Defaults to the prefix mode,
	which is the safe general case for queue/prefix desyncs."""
	k = (kind or "").upper()
	if k.startswith("H2"):
		return "h2"
	if k.startswith("PAUSE"):
		return "pause"
	if k.startswith("CONNSTATE"):
		return "connstate"
	if k.startswith("HDRREMOVAL") or k.startswith("HOPBYHOP"):
		return "differential"
	return "prefix"


class DesyncConfirmer:
	def __init__(self, host, port, ssl_flag, timeout, proxy=None, vhost="",
			cookies="", method="POST", endpoint="/", payloads_dir=None):
		self.host = host
		self.port = int(port)
		self.ssl_flag = bool(ssl_flag)
		self.timeout = float(timeout)
		self.proxy = proxy
		self.vhost = vhost or host
		self.cookies = cookies or ""
		self.method = method
		self.endpoint = endpoint or "/"
		self.payloads_dir = payloads_dir or _repo_payloads_dir()
		self._summary = "no confirmation run yet"
		self.verdict = None  # True / False / None

	# ---- public API ---------------------------------------------------

	def summarize(self):
		return self._summary

	def confirm(self, payload_path, followup_path=None, scan_kind=None, attempts=None):
		"""Resolve the finding kind, dispatch to a mode, write evidence, and
		return True (CONFIRMED) / False (NOT CONFIRMED). Raises ConfirmError
		for refusals (no socket is opened in that case)."""
		abspath = os.path.realpath(payload_path)
		if not os.path.isfile(abspath):
			raise ConfirmError("payload file not found: %s" % payload_path)
		# Path-safety: only ever replay files that live under payloads/.
		payloads_root = os.path.realpath(self.payloads_dir)
		if os.path.commonpath([abspath, payloads_root]) != payloads_root:
			raise ConfirmError(
				"refusing payload outside payloads/ directory: %s" % payload_path)

		raw = open(abspath, "rb").read()
		kind = scan_kind or self._kind_from_sidecar(abspath) or \
			self._kind_from_name(abspath) or self._kind_from_markers(raw)
		family = family_for_kind(kind)

		dispatch = {
			"prefix": self._confirm_prefix,
			"differential": self._confirm_differential,
			"connstate": self._confirm_connstate,
			"pause": self._confirm_pause,
			"h2": self._confirm_h2,
		}
		mode_fn = dispatch[family]
		result = mode_fn(raw, abspath, followup_path, kind, attempts)

		result.setdefault("kind", kind or "?")
		result.setdefault("mode", family)
		self.verdict = bool(result.get("confirmed"))
		self._evidence_path = self._write_evidence(result)
		verb = "CONFIRMED" if self.verdict else "NOT CONFIRMED"
		self._summary = "%s [%s/%s]: %s" % (
			verb, result.get("kind"), family, result.get("detail", ""))
		result["evidence_path"] = self._evidence_path
		self.last_result = result
		return self.verdict

	# ---- kind resolution ---------------------------------------------

	def _kind_from_sidecar(self, abspath):
		base = abspath[:-4] if abspath.endswith(".txt") else abspath
		try:
			import json
			meta = json.loads(open(base + ".meta.json", encoding="utf-8").read())
			return meta.get("kind")
		except (OSError, ValueError):
			return None

	def _kind_from_name(self, abspath):
		stem = os.path.basename(abspath)
		if stem.endswith(".txt"):
			stem = stem[:-4]
		parts = stem.split("_")
		# <scheme>_<host...>_<KIND>[_<mutation>] -- the kind is an uppercase
		# token; scan from the right for the first all-caps-ish token.
		for tok in reversed(parts):
			if tok and tok.upper() == tok and any(c.isalpha() for c in tok):
				return tok
		return parts[-2] if len(parts) >= 3 else None

	def _kind_from_markers(self, raw):
		text = raw.decode("latin-1", errors="replace")
		if "[PAUSE" in text:
			return "PAUSE"
		if "# Request 1 (setup):" in text:
			return "CONNSTATE"
		if re.search(r"^#\s*h2", text, re.MULTILINE):
			return "H2"
		return None

	# ---- socket helpers ----------------------------------------------

	def _open(self, timeout=None):
		web = EasySSL(self.ssl_flag)
		web.connect(self.host, self.port, timeout or self.timeout, self.proxy)
		return web

	@staticmethod
	def _as_bytes(data):
		return data if isinstance(data, (bytes, bytearray)) else data.encode("latin-1")

	def _send_single(self, data, timeout=None):
		web = self._open(timeout)
		try:
			web.send(self._as_bytes(data))
			raw = web.recv_all(timeout or self.timeout)
		finally:
			web.close()
		return _filter_response(raw)

	def _pipeline(self, parts, count=2, timeout=None):
		web = self._open(timeout)
		try:
			web.pipeline_send([self._as_bytes(p) for p in parts])
			resps = web.recv_multiple(count, timeout or self.timeout)
		finally:
			web.close()
		return resps

	def _control_baseline(self, request_str, n=3):
		"""Sample the operator's own request alone on fresh connections and
		return (consensus_fp, noisy_axes, sample_text)."""
		fp, noisy = baseline_fingerprint(
			self.host, self.port, self.ssl_flag, self.timeout,
			request_str, self.proxy, n=n)
		try:
			sample = self._send_single(request_str)
		except Exception:
			sample = ""
		return fp, noisy, sample

	def _diverged(self, resp_text, control_fp, noisy):
		fp = _fp_from_bytes_or_str(resp_text or "")
		return _is_structurally_different(fp, control_fp, noisy), fp

	# ---- follow-up construction --------------------------------------

	def _build_followup(self, followup_path):
		"""Return (followup_str, label). Operator-supplied file must target
		the same host (refused otherwise, no socket). Otherwise a benign
		canary GET on this target is synthesized."""
		if followup_path:
			try:
				parsed = parse_request_file(followup_path)
			except RequestFileError as e:
				raise ConfirmError(str(e))
			fhost = (parsed.get("host") or "").split(":")[0].strip().lower()
			target = {self.host.lower(), (self.vhost or "").lower()}
			if fhost and fhost not in target:
				raise ConfirmError(
					"follow-up Host %r does not match target %r/%r -- refusing"
					% (fhost, self.host, self.vhost))
			return parsed["raw"], "operator-followup"
		import random
		canary = "smuggler-confirm-%s" % str(random.random()).split(".")[1]
		req = (
			"GET /%s HTTP/1.1\r\nHost: %s\r\n"
			"User-Agent: smuggler-confirm\r\nAccept: */*\r\n"
			"Connection: close\r\n\r\n" % (canary, self.vhost))
		return req, "canary:/%s" % canary

	@staticmethod
	def _slot(resps, idx=1):
		if len(resps) > idx:
			return resps[idx]
		if resps:
			return resps[-1]
		return ""

	# ---- mode: prefix / queue-injection ------------------------------

	def _confirm_prefix(self, raw, abspath, followup_path, kind, attempts):
		attempts = attempts or 3
		followup_str, label = self._build_followup(followup_path)
		control_fp, noisy, control_text = self._control_baseline(followup_str)

		hits = 0
		rounds = []
		for _ in range(attempts):
			try:
				resps = self._pipeline([raw, followup_str], count=2)
			except Exception as e:
				rounds.append("pipeline error: %s" % e)
				continue
			slot = self._slot(resps, 1)
			diverged, _ = self._diverged(slot, control_fp, noisy)
			absorbed = len(resps) < 2 and bool(control_text)
			rounds.append("responses=%d diverged=%s absorbed=%s status=%s" % (
				len(resps), diverged, absorbed, _get_status(slot)))
			if diverged or absorbed:
				hits += 1
		confirmed = hits * 2 > attempts
		return {
			"confirmed": confirmed,
			"detail": "follow-up(%s) slot diverged in %d/%d rounds" % (label, hits, attempts),
			"sent": {"poc": raw.decode("latin-1", "replace"), "followup": followup_str},
			"responses": {"control": control_text, "rounds": rounds},
		}

	# ---- mode: differential ------------------------------------------

	def _confirm_differential(self, raw, abspath, followup_path, kind, attempts):
		attempts = attempts or 4
		attack_str = raw.decode("latin-1", errors="replace")
		twin_str = self._differential_twin(attack_str, kind)
		if twin_str is None:
			raise ConfirmError(
				"cannot derive trigger-off twin for kind %r" % kind)

		twin_fp, noisy, twin_text = self._control_baseline(twin_str)

		hits = 0
		rounds = []
		last_attack = ""
		for _ in range(attempts):
			try:
				attack_text = self._send_single(attack_str)
			except Exception as e:
				rounds.append("attack error: %s" % e)
				continue
			last_attack = attack_text
			diverged, a_fp = self._diverged(attack_text, twin_fp, noisy)
			rounds.append("attack_status=%s twin_status=%s diverged=%s axes=%s" % (
				_get_status(attack_text), twin_fp.status, diverged,
				"+".join(sorted(_structural_diff(a_fp, twin_fp, noisy))) or "-"))
			if diverged:
				hits += 1
		confirmed = hits * 2 > attempts
		return {
			"confirmed": confirmed,
			"detail": "trigger-on vs trigger-off diverged in %d/%d rounds" % (hits, attempts),
			"sent": {"attack": attack_str, "twin": twin_str},
			"responses": {"twin": twin_text, "attack": last_attack, "rounds": rounds},
		}

	def _differential_twin(self, attack_str, kind):
		k = (kind or "").upper()
		if k.startswith("HDRREMOVAL"):
			# Scanner's harmless twin neutralizes the Keep-Alive trigger.
			if "Keep-Alive:" in attack_str:
				return attack_str.replace("Keep-Alive:", "Eat-Alive:")
			return attack_str  # nothing to neutralize; diff will just be empty
		if k.startswith("HOPBYHOP"):
			# Drop the hop-by-hop Connection: <header> line that asks the
			# front-end to strip a header; keep Connection: keep-alive/close.
			out = []
			for line in attack_str.split("\n"):
				s = line.strip().lower()
				if s.startswith("connection:"):
					val = s.split(":", 1)[1].strip()
					if val not in ("keep-alive", "close"):
						continue  # this is the trigger line -> remove it
				out.append(line)
			return "\n".join(out)
		return None

	# ---- mode: connection-state --------------------------------------

	def _confirm_connstate(self, raw, abspath, followup_path, kind, attempts):
		attempts = attempts or 2
		text = raw.decode("latin-1", errors="replace")
		setup_req, canary_req = self._parse_connstate(text)
		if not setup_req or not canary_req:
			raise ConfirmError("could not parse setup/canary requests from CONNSTATE POC")

		direct_fp, noisy, direct_text = self._control_baseline(canary_req)

		hits = 0
		rounds = []
		last_indirect = ""
		for _ in range(attempts + 1):
			try:
				resps = self._pipeline([setup_req, canary_req], count=2)
			except Exception as e:
				rounds.append("pipeline error: %s" % e)
				continue
			indirect = self._slot(resps, 1)
			last_indirect = indirect
			diverged, _ = self._diverged(indirect, direct_fp, noisy)
			rounds.append("indirect_status=%s direct_status=%s diverged=%s" % (
				_get_status(indirect), direct_fp.status, diverged))
			if diverged:
				hits += 1
		confirmed = hits >= 2
		return {
			"confirmed": confirmed,
			"detail": "indirect(reused-conn) vs direct diverged in %d rounds" % hits,
			"sent": {"setup": setup_req, "canary": canary_req},
			"responses": {"direct": direct_text, "indirect": last_indirect, "rounds": rounds},
		}

	@staticmethod
	def _parse_connstate(text):
		m1 = re.search(r"#\s*Request 1 \(setup\):\s*\n", text)
		m2 = re.search(r"#\s*Request 2 \(canary\):\s*\n", text)
		if not m1 or not m2:
			return None, None
		setup = text[m1.end():m2.start()].strip("\r\n")
		canary = text[m2.end():].strip("\r\n")
		# Ensure a header terminator so each is a complete request.
		if "\r\n\r\n" not in setup:
			setup += "\r\n\r\n"
		if "\r\n\r\n" not in canary:
			canary += "\r\n\r\n"
		return setup, canary

	# ---- mode: timed / pause -----------------------------------------

	def _confirm_pause(self, raw, abspath, followup_path, kind, attempts):
		attempts = attempts or 2
		text = raw.decode("latin-1", errors="replace")
		m = re.search(r"\[PAUSE\s+(\d+)s\]", text)
		if not m:
			raise ConfirmError("POC missing [PAUSE Ns] marker")
		pause_n = min(int(m.group(1)), 300)  # cap so the GUI can't hang
		headers_part = text[:m.start()]
		smuggled_prefix = text[m.end():]

		followup_str, label = self._build_followup(followup_path)
		control_fp, noisy, control_text = self._control_baseline(followup_str)

		sock_timeout = max(self.timeout, pause_n + 10)
		hits = 0
		rounds = []
		for _ in range(attempts):
			try:
				web = self._open(sock_timeout)
				try:
					web.send_timed(
						headers_part.encode("latin-1"),
						smuggled_prefix.encode("latin-1"),
						pause_n)
					web.send(self._as_bytes(followup_str))
					resps = web.recv_multiple(2, sock_timeout)
				finally:
					web.close()
			except Exception as e:
				rounds.append("pause error: %s" % e)
				continue
			slot = self._slot(resps, 1)
			diverged, _ = self._diverged(slot, control_fp, noisy)
			absorbed = len(resps) < 2 and bool(control_text)
			rounds.append("responses=%d diverged=%s absorbed=%s" % (
				len(resps), diverged, absorbed))
			if diverged or absorbed:
				hits += 1
		# Majority rule, consistent with the differential/connstate modes
		# (hits*2 > attempts). The old `hits >= 2` demanded 2/2 == 100% for the
		# default attempts=2, an unintentionally stricter bar than every other
		# mode and a source of pause-mode false negatives.
		confirmed = hits * 2 > attempts
		return {
			"confirmed": confirmed,
			"detail": "paused %ds, follow-up(%s) diverged in %d/%d rounds" % (
				pause_n, label, hits, attempts),
			"sent": {"headers": headers_part, "pause_seconds": pause_n,
				"smuggled_prefix": smuggled_prefix, "followup": followup_str},
			"responses": {"control": control_text, "rounds": rounds},
		}

	# ---- mode: h2 downgrade ------------------------------------------

	def _confirm_h2(self, raw, abspath, followup_path, kind, attempts):
		perm_name = re.sub(r"^H2_?", "", kind or "", flags=re.IGNORECASE)
		try:
			from lib.H2Scans import ScanH2Desync
		except Exception as e:
			return {
				"confirmed": False,
				"detail": "HTTP/2 confirm unavailable: %s" % e,
				"sent": {}, "responses": {},
			}
		scanner = ScanH2Desync(
			self.host, self.port, self.ssl_flag, self.timeout,
			self.method, self.endpoint, self.vhost, self.proxy,
			None, True, self.cookies)
		res = scanner.confirm_permutation(perm_name, attempts=attempts or 5)
		return {
			"confirmed": bool(res.get("confirmed")),
			"detail": res.get("detail", ""),
			"sent": {"permutation": perm_name,
				"technique": res.get("technique"),
				"gadget": res.get("gadget")},
			"responses": {"victim_leg": res.get("victim", "")},
		}

	# ---- evidence ----------------------------------------------------

	def _write_evidence(self, result):
		out_dir = os.path.join(self.payloads_dir, "confirmations")
		try:
			os.makedirs(out_dir, exist_ok=True)
		except OSError:
			return None
		scheme = "https" if self.ssl_flag else "http"
		safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", self.host)
		safe_kind = re.sub(r"[^A-Za-z0-9]", "_", str(result.get("kind", "?")))
		ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
		fname = "%s_%s_%d_%s_%s.txt" % (scheme, safe_host, self.port, safe_kind, ts)
		path = os.path.join(out_dir, fname)

		verdict = "CONFIRMED" if result.get("confirmed") else "NOT CONFIRMED"
		lines = [
			"# Smuggler self-contained desync confirmation",
			"# This file contains ONLY the operator's own requests and the",
			"# responses they produced. No third-party traffic is captured.",
			"verdict: %s" % verdict,
			"kind: %s" % result.get("kind"),
			"mode: %s" % result.get("mode"),
			"target: %s://%s:%d (vhost=%s)" % (scheme, self.host, self.port, self.vhost),
			"timestamp: %s" % ts,
			"detail: %s" % result.get("detail", ""),
			"",
			"==== requests sent (own traffic) ====",
		]
		for k, v in (result.get("sent") or {}).items():
			lines.append("---- %s ----" % k)
			lines.append(str(v))
		lines.append("")
		lines.append("==== responses observed (own traffic) ====")
		responses = result.get("responses") or {}
		for k, v in responses.items():
			lines.append("---- %s ----" % k)
			if isinstance(v, list):
				for item in v:
					lines.append(str(item))
			else:
				lines.append(str(v))
		blob = ("\n".join(lines) + "\n").encode("utf-8", errors="replace")

		try:
			fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
			with os.fdopen(fd, "wb") as f:
				f.write(blob)
		except OSError:
			try:
				with open(path, "wb") as f:
					f.write(blob)
			except OSError:
				return None
		return path
