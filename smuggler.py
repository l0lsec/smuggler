#!/usr/bin/python3
# MIT License
# 
# Copyright (c) 2026 Sedric Louissaint
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import re
import time
import sys
import os
import random
import string
import importlib
import hashlib
import signal
import threading
from copy import deepcopy
from time import sleep
from datetime import datetime
from lib.Payload import Payload, Chunked, EndChunk, RawPayload, cache_bust
from lib.EasySSL import EasySSL
from lib.colorama import Fore, Style
from lib.Scans import (
	ALL_SCANS, ScanCL0, ScanPauseDesync, ScanConnectionState,
	ScanParserDiscrepancy, ScanHeaderRemoval, ScanExpectDesync,
	ScanTE0, ScanBareLFChunked, ScanHopByHop,
)
from lib.Oracle import GadgetOracle
from lib.Fingerprint import Fingerprint, baseline_fingerprint, split_pipelined_responses
from lib.RequestFile import parse_request_file, RequestFileError
from lib.Confirm import DesyncConfirmer, ConfirmError, family_for_kind, _repo_payloads_dir
from lib.Timing import TimingBaseline
from urllib.parse import urlparse

try:
	from lib.H2Scans import ScanH2Desync
	H2_SCAN_AVAILABLE = True
except ImportError:
	H2_SCAN_AVAILABLE = False


def _safe_host_slug(host):
	"""Sanitize a host string for use inside a payload filename.

	The host can come from a pasted request's Host header, so it is untrusted:
	stripping only '.' (the old behavior) let path separators, '..', null bytes
	etc. survive into the filename and potentially escape payloads/. Collapse to
	a conservative [A-Za-z0-9_-] slug.
	"""
	slug = re.sub(r'[^A-Za-z0-9_-]', '_', (host or "").replace('.', '_'))
	return slug or "host"


def _payloads_dir():
	"""Absolute path to the repo's payloads/ directory, resolving a symlinked
	argv[0] the same way the original write paths did."""
	if os.path.islink(sys.argv[0]):
		_me = os.readlink(sys.argv[0])
	else:
		_me = sys.argv[0]
	return os.path.join(os.path.realpath(os.path.dirname(_me)), "payloads")


SMUGGLER_VERSION = "1.0"


def findings_to_json(findings, target=None):
	"""Aggregate run report. Pure function -- easy to unit test."""
	import datetime as _dt
	return {
		"tool": "smuggler",
		"version": SMUGGLER_VERSION,
		"target": target,
		"generated_at": _dt.datetime.utcnow().isoformat() + "Z",
		"finding_count": len(findings),
		"findings": findings,
	}


def findings_to_sarif(findings, target=None):
	"""Minimal SARIF 2.1.0 log. Each finding becomes a result whose ruleId is
	its desync type and whose location points at the payload artifact. Pure
	function so it can be asserted on in tests."""
	rule_ids = []
	seen = set()
	for f in findings:
		rid = f.get("type") or "desync"
		if rid not in seen:
			seen.add(rid)
			rule_ids.append(rid)
	results = []
	for f in findings:
		msg = "%s desync detected" % (f.get("type") or "Unknown")
		if f.get("mutation"):
			msg += " (mutation=%s)" % f["mutation"]
		result = {
			"ruleId": f.get("type") or "desync",
			"level": "error",
			"message": {"text": msg},
		}
		pf = f.get("payload_file")
		if pf:
			result["locations"] = [{
				"physicalLocation": {
					"artifactLocation": {"uri": pf}
				}
			}]
		props = {k: f[k] for k in (
			"host", "url", "method", "status_label", "gadget_hit",
			"confidence", "timing_s", "configfile") if f.get(k) is not None}
		if props:
			result["properties"] = props
		results.append(result)
	return {
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "smuggler",
				"version": SMUGGLER_VERSION,
				"rules": [{"id": rid} for rid in rule_ids],
			}},
			"results": results,
		}],
	}


def write_findings_report(findings, path, fmt="json", target=None):
	"""Serialize findings to `path` in the requested format. Returns the number
	of findings written. Raises OSError on write failure (caller decides)."""
	import json as _json
	if fmt == "sarif":
		doc = findings_to_sarif(findings, target)
	else:
		doc = findings_to_json(findings, target)
	with open(path, "w", encoding="utf-8") as f:
		_json.dump(doc, f, indent=2)
	return len(findings)


class Desyncr():
	def __init__(self, configfile, smhost, smport=443, url="", method="POST", endpoint="/",
			SSLFlag=False, logh=None, custom_request=None,
			vhost="", timeout=5.0, quiet=False, exit_early=False,
			proxy=None, cookies_str=None, persistent_connection=False):
		self._configfile = configfile
		self._host = smhost
		self._port = smport
		self._method = method
		self._endpoint = endpoint
		self._vhost = vhost or ""
		self._url = url
		self._timeout = float(timeout)
		self.ssl_flag = SSLFlag
		self._logh = logh
		self._quiet = quiet
		self._exit_early = exit_early
		self._cookies = []
		self._headers = []
		self._findings = []
		self._proxy = proxy
		self._custom_request = custom_request
		self._persistent_connection = persistent_connection
		self._web_connection = None

		if custom_request and 'cookies' in custom_request and custom_request['cookies']:
			self._cookies.extend(custom_request['cookies'])
			info = ((Fore.CYAN + str(len(custom_request['cookies']))+ Fore.MAGENTA), self._logh)
			print_info("Cookies from request file: %s" % (info[0]))

		if custom_request and custom_request.get('extra_headers'):
			self._headers.extend(custom_request['extra_headers'])
			info = ((Fore.CYAN + str(len(custom_request['extra_headers']))+ Fore.MAGENTA), self._logh)
			print_info("Headers from request file: %s" % (info[0]))

		if cookies_str:
			self._parse_custom_cookies(cookies_str)

	@classmethod
	def from_args(cls, configfile, host, port, url, method, endpoint, ssl_flag,
			logh, args, custom_request=None):
		"""Build a Desyncr from an argparse.Namespace -- keeps __main__ tidy
		while preserving the explicit-arg constructor for testing."""
		return cls(
			configfile=configfile,
			smhost=host,
			smport=port,
			url=url,
			method=method,
			endpoint=endpoint,
			SSLFlag=ssl_flag,
			logh=logh,
			custom_request=custom_request,
			vhost=getattr(args, 'vhost', '') or '',
			timeout=getattr(args, 'timeout', 5.0),
			quiet=getattr(args, 'quiet', False),
			exit_early=getattr(args, 'exit_early', False),
			proxy=getattr(args, 'proxy', None),
			cookies_str=getattr(args, 'cookies', None),
			persistent_connection=getattr(args, 'persistent_connection', False),
		)

	def _parse_custom_cookies(self, cookie_string):
		"""Parse custom cookies from command line argument and add to self._cookies"""
		try:
			# Split by semicolon and clean up each cookie
			cookies = [cookie.strip() for cookie in cookie_string.split(';') if cookie.strip()]
			# Add semicolon to each cookie if not present
			for cookie in cookies:
				if not cookie.endswith(';'):
					cookie += ';'
				self._cookies.append(cookie)
		except Exception as e:
			error = ((Fore.CYAN + "Error parsing cookies: " + str(e) + Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))

	def _apply_extra_headers(self, header_str):
		"""Append the custom request headers (Authorization, X-Dtc, ...) to a
		CRLF header block. Any existing line whose header name collides with a
		custom header is dropped first so the user's value wins -- this avoids a
		duplicate User-Agent/Content-Type when the pasted request supplied one.
		Lines without a colon (e.g. the request line) are always preserved."""
		if not self._headers:
			return header_str
		custom_names = {h.split(':', 1)[0].strip().lower() for h in self._headers}
		kept = []
		for line in header_str.split("\r\n"):
			if ':' in line and line.split(':', 1)[0].strip().lower() in custom_names:
				continue
			kept.append(line)
		header_str = "\r\n".join(kept)
		if header_str and not header_str.endswith("\r\n"):
			header_str += "\r\n"
		header_str += ''.join(h + "\r\n" for h in self._headers)
		return header_str

	def _record_finding(self, ptype, host=None, payload_file=None, mutation=None,
			status_label=None, gadget_hit=False, confidence=None, timing=None,
			configfile=None, scan=None, attack_status=None,
			baseline_status=None, fp_axes=None, label=None):
		"""Append a normalized finding record to the in-memory registry that
		feeds --output-json / --output-sarif. Both scan paths call this; the
		advanced path supplies only what it knows and leaves the rest null."""
		self._findings.append({
			"type": ptype,
			"scan": scan,
			"mutation": mutation,
			"host": host,
			"url": self._url,
			"method": self._method,
			"payload_file": payload_file,
			"status_label": status_label,
			"label": label,
			"attack_status": attack_status,
			"baseline_status": baseline_status,
			"fp_axes": fp_axes,
			"gadget_hit": bool(gadget_hit),
			"confidence": confidence,
			"timing_s": timing,
			"configfile": configfile,
		})

	@staticmethod
	def _resp_to_bytes(x):
		"""Normalize a response/baseline (None | bytes | latin-1 str from
		_filter_response) to bytes for sidecar storage. Scanner responses are
		ASCII-flattened latin-1 strings, so latin-1 is a faithful 1:1 mapping."""
		if x is None:
			return b""
		if isinstance(x, (bytes, bytearray)):
			return bytes(x)
		return str(x).encode('latin-1', errors='replace')

	def _write_finding_artifacts(self, base, response=None, baseline=None, meta=None):
		"""Write the response/baseline/meta sidecars next to a finding's request
		.txt (which already lives at ``base + '.txt'``). Shared by the classic
		``write_payload`` and the advanced ``adv_write`` paths so the GUI viewer
		can surface what came back. Best-effort; never raises.

		``<base>.response.txt`` is ALWAYS written (even empty) so the GUI can tell
		"captured nothing back -- the hang is the signal" from "never recorded".
		``<base>.baseline.txt`` is written only when a baseline is supplied.
		"""
		try:
			with open(base + ".response.txt", 'wb') as f:
				f.write(self._resp_to_bytes(response))
		except OSError:
			pass
		if baseline is not None:
			try:
				with open(base + ".baseline.txt", 'wb') as f:
					f.write(self._resp_to_bytes(baseline))
			except OSError:
				pass
		if meta is not None:
			try:
				import json as _json
				with open(base + ".meta.json", 'w') as f:
					_json.dump(meta, f, indent=2)
			except OSError:
				pass

	def _establish_persistent_connection(self):
		"""Establish a persistent connection if enabled"""
		if self._persistent_connection and not self._web_connection:
			try:
				self._web_connection = EasySSL(self.ssl_flag)
				self._web_connection.connect(self._host, self._port, self._timeout, self._proxy, persistent=True)
				info = ((Fore.CYAN + "Persistent connection established"+ Fore.MAGENTA), self._logh)
				print_info("Connection : %s" % (info[0]))
			except Exception as e:
				error = ((Fore.CYAN + "Failed to establish persistent connection: " + str(e) + Fore.MAGENTA), self._logh)
				print_info("Error      : %s" % (error[0]))
				self._web_connection = None

	def _close_persistent_connection(self):
		"""Close the persistent connection if it exists"""
		if self._web_connection:
			try:
				self._web_connection.close()
				self._web_connection = None
			except Exception as e:
				error = ((Fore.CYAN + "Error closing persistent connection: " + str(e) + Fore.MAGENTA), self._logh)
				print_info("Error      : %s" % (error[0]))

	# Translation table to flatten any byte > 0x7F to '0' (0x30). Faster than
	# building a string char-by-char in Python.
	_HIGHBIT_TO_ZERO = bytes(
		[(b if b <= 0x7F else 0x30) for b in range(256)]
	)

	def _test(self, payload_obj):
		using_persistent = self._persistent_connection and self._web_connection is not None
		try:
			if using_persistent:
				web = self._web_connection
			else:
				web = EasySSL(self.ssl_flag)
				web.connect(self._host, self._port, self._timeout, self._proxy)

			web.send(str(payload_obj).encode())
			start_time = datetime.now()
			res = web.recv_nb(self._timeout)
			end_time = datetime.now()

			# Persistent connection contract: any non-clean response
			# (timeout, disconnect, malformed) can leave undrained bytes that
			# poison the *next* mutation. Force-reset on anything other than
			# a clean response to stop cascading false positives.
			anomalous = res is None
			if not self._persistent_connection:
				web.close()
			elif anomalous:
				try:
					web.close()
				except Exception:
					pass
				self._web_connection = None
				self._establish_persistent_connection()

			if res is None:
				delta_seconds = (end_time - start_time).total_seconds()
				if delta_seconds < (self._timeout - 1):
					return (2, res, payload_obj)  # disconnected before timeout
				return (1, res, payload_obj)  # connection timed out
			res = res.translate(self._HIGHBIT_TO_ZERO).decode('latin-1', errors='replace')
			return (0, res, payload_obj)  # normal response
		except Exception:
			if self._persistent_connection and self._web_connection is not None:
				try:
					self._web_connection.close()
				except Exception:
					pass
				self._web_connection = None
				self._establish_persistent_connection()
			return (-1, None, payload_obj)
		
	def _get_cookies(self):
		RN = "\r\n"
		
		# If cookies were provided via custom request file, skip automatic cookie fetching
		if self._custom_request and 'cookies' in self._custom_request and self._custom_request['cookies']:
			info = ((Fore.CYAN + "Using cookies from request file"+ Fore.MAGENTA), self._logh)
			print_info("Cookies    : %s" % (info[0]))
			return True
		
		try:
			cookies = []
			web = EasySSL(self.ssl_flag)
			web.connect(self._host, self._port, 2.0, self._proxy)
			
			# Use default request for cookie retrieval
			p = Payload()
			p.host = self._host
			p.method = "GET"
			p.endpoint = self._endpoint
			p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
			p.header += "Host: __HOST__" + RN
			p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
			p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
			p.header += "Content-Length: 0" + RN
			p.header = self._apply_extra_headers(p.header)
			p.body = ""
			#print (str(p))
			web.send(str(p).encode())
			
			sleep(0.5)
			res = web.recv_nb(2.0)
			web.close()
			if (res is not None):
				# Decode permissively; servers occasionally send latin-1 cookies.
				try:
					res_lines = res.decode().split("\r\n")
				except UnicodeDecodeError:
					res_lines = res.decode('latin-1', errors='replace').split("\r\n")
				for elem in res_lines:
					if len(elem) <= len("set-cookie:"):
						continue
					# Only the *header name* comparison is case-insensitive.
					# Preserve original cookie body so values like JWTs that
					# rely on case survive intact.
					name_part, _, value_part = elem.partition(":")
					if name_part.strip().lower() != "set-cookie":
						continue
					cookie = value_part.strip()
					if not cookie:
						continue
					cookie = cookie.split(";")[0].strip() + ';'
					cookies += [cookie]
				info = ((Fore.CYAN + str(len(cookies))+ Fore.MAGENTA), self._logh)
				print_info("Cookies    : %s (Appending to the attack)" % (info[0]))
				self._cookies += cookies
			return True
		except Exception as exception_data:
			error = ((Fore.CYAN + "Unable to connect to host"+ Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))
			return False

	def run(self):
		RN = "\r\n"
		mutations = {}
		
		# Establish persistent connection if enabled
		if self._persistent_connection:
			self._establish_persistent_connection()
		
		if not self._get_cookies():
			return
			
		if (self._configfile[1] != '/'):
			self._configfile = os.path.dirname(os.path.realpath(__file__)) + "/configs/" + self._configfile

		try:
			f = open(self._configfile)
		except:
			error = ((Fore.CYAN + "Cannot find config file"+ Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))
			exit(1)
			
		script = f.read()
		f.close()

		# NOTE: config files are arbitrary Python evaluated in this scope so
		# they can construct Payload() objects directly. Only ever load
		# configs you trust -- they have full process privileges.
		exec(script)
			
		for mutation_name in mutations.keys():
			if self._create_exec_test(mutation_name, mutations[mutation_name]) and self._exit_early:
				break
		
		if self._quiet:
			sys.stdout.write("\r"+" "*100+"\r")
		
		# Close persistent connection if it was established
		if self._persistent_connection:
			self._close_persistent_connection()

	def run_advanced_scans(self, scan_types, pause_timeout=61):
		def adv_print(name, msg):
			spacing = 13
			sys.stdout.write("\r"+" "*100+"\r")
			full_msg = Style.BRIGHT + Fore.MAGENTA + "[%s]%s: %s" % \
				(Fore.CYAN + name + Fore.MAGENTA, " "*(spacing-len(name)),
				 Fore.YELLOW + msg)
			sys.stdout.write(CF(full_msg + Style.RESET_ALL))
			sys.stdout.flush()
			print()
			if self._logh is not None:
				ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
				plaintext = ansi_escape.sub('', full_msg)
				self._logh.write(plaintext + "\n")
				self._logh.flush()

		def adv_write(smhost, payload, ptype, response=None, baseline=None,
				details=None):
			details = details or {}
			scheme = "https" if self.ssl_flag else "http"
			furl = "%s_%s" % (scheme, _safe_host_slug(smhost))
			fname = os.path.join(_payloads_dir(), "%s_%s.txt" % (furl, ptype))
			adv_print("CRITICAL", "%s Payload: %s URL: %s" % \
				(Fore.MAGENTA + ptype, Fore.CYAN + fname + Fore.MAGENTA, Fore.CYAN + self._url))
			if isinstance(payload, RawPayload):
				req_bytes = payload.to_bytes()
			else:
				req_bytes = bytes(str(payload), 'utf-8')
			with open(fname, 'wb') as file:
				file.write(req_bytes)

			# Sidecars so the GUI viewer can show the attack response (and the
			# baseline it was compared against) instead of "not captured".
			import datetime as _dt
			base = fname[:-4]
			status_label = details.get("status_label") or "normal"
			meta = {
				"kind": ptype,
				"scan": details.get("scan"),
				"mutation": details.get("mutation"),
				"url": self._url,
				"method": self._method,
				"configfile": None,
				"confidence": details.get("confidence"),
				"gadget_hit": bool(details.get("gadget_hit")),
				"status_label": status_label,
				"label": details.get("label"),
				"attack_status": details.get("attack_status"),
				"baseline_status": details.get("baseline_status"),
				"fp_axes": details.get("fp_axes"),
				"timing_s": details.get("timing_s"),
				"request_bytes": len(req_bytes),
				"response_bytes": len(self._resp_to_bytes(response)),
				"baseline_bytes": (len(self._resp_to_bytes(baseline))
					if baseline is not None else None),
				"timestamp": _dt.datetime.utcnow().isoformat() + "Z",
			}
			self._write_finding_artifacts(base, response=response,
				baseline=baseline, meta=meta)

			self._record_finding(
				ptype, host=smhost, payload_file=fname,
				scan=details.get("scan"), mutation=details.get("mutation"),
				status_label=status_label, label=details.get("label"),
				attack_status=details.get("attack_status"),
				baseline_status=details.get("baseline_status"),
				fp_axes=details.get("fp_axes"),
				gadget_hit=bool(details.get("gadget_hit")),
				confidence=details.get("confidence"),
				timing=details.get("timing_s"))

		if not self._get_cookies():
			return

		vhost = self._vhost if self._vhost else self._host

		# Build a single per-target gadget oracle and share it across every
		# scanner. The first scanner that calls oracle.select() pays the
		# probe cost (typically 4-6 small requests); every other scanner
		# in this run reuses the cached gadget.
		oracle = self._get_oracle()
		try:
			chosen = oracle.select()
			if chosen is not None:
				adv_print("Oracle", "Gadget=%s path=%r look_for=%r (%s)" % (
					chosen.name, chosen.smuggle_path, chosen.look_for, chosen.rationale))
			else:
				adv_print("Oracle", "No viable gadget; scanners will use legacy /robots.txt + 'llow:' fallback")
		except Exception as e:
			adv_print("Oracle", "Probe failed (%s); falling back to legacy gadget" % str(e))

		scan_map = {
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

		for scan_name in scan_types:
			if scan_name == "h2":
				if H2_SCAN_AVAILABLE:
					scanner = ScanH2Desync(
						self._host, self._port, self.ssl_flag, self._timeout,
						self._method, self._endpoint, vhost, self._proxy,
						self._logh, self._quiet, self._cookies,
						extra_headers=self._headers,
					)
					scanner.run(adv_print, adv_write)
				else:
					adv_print("H2", "HTTP/2 scanning requires the h2 library (pip install h2)")
				continue

			if scan_name not in scan_map:
				adv_print("Error", "Unknown scan type: %s" % scan_name)
				continue

			scan_cls = scan_map[scan_name]
			if scan_name == "pause":
				scanner = scan_cls(
					self._host, self._port, self.ssl_flag, self._timeout,
					self._method, self._endpoint, vhost, self._proxy,
					self._logh, self._quiet, self._cookies, pause_timeout,
					oracle=oracle, extra_headers=self._headers,
				)
			else:
				scanner = scan_cls(
					self._host, self._port, self.ssl_flag, self._timeout,
					self._method, self._endpoint, vhost, self._proxy,
					self._logh, self._quiet, self._cookies, oracle=oracle,
					extra_headers=self._headers,
				)
			scanner.run(adv_print, adv_write)

	# ptype == 0 (Attack payload, timeout could mean potential TECL desync)
	# ptype == 1 (Edgecase payload, expected to work)
	def _check_tecl(self, payload, ptype=0):
		te_payload = deepcopy(payload)
		if (self._vhost == ""):
			te_payload.host = self._host
		else:
			te_payload.host = self._vhost
		te_payload.method = self._method
		te_payload.endpoint = self._endpoint
		
		if len(self._cookies) > 0:
			te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
		te_payload.header = self._apply_extra_headers(te_payload.header)

		if not ptype:
			te_payload.cl = 6 # timeout val == 6, good value == 5
		else:
			te_payload.cl = 5 # timeout val == 6, good value == 5
		te_payload.body = EndChunk+"X"
		return self._test(te_payload)

	# ptype == 0 (timeout payload, timeout could mean potential CLTE desync)
	# ptype == 1 (Edgecase payload, expected to work)
	def _check_clte(self, payload, ptype=0):
		te_payload = deepcopy(payload)
		if (self._vhost == ""):
			te_payload.host = self._host
		else:
			te_payload.host = self._vhost
		te_payload.method = self._method
		te_payload.endpoint = self._endpoint
		
		if len(self._cookies) > 0:
			te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
		te_payload.header = self._apply_extra_headers(te_payload.header)

		if not ptype:
			te_payload.cl = 4 # timeout val == 4, good value == 11
		else:
			te_payload.cl = 11 # timeout val == 4, good value == 11
		te_payload.body = Chunked("Z")+EndChunk
		return self._test(te_payload)

	def _confirm_timeout_anomaly(self, check_fn, payload, tries=3):
		"""Iterative replacement for the old recursive _attempts dance.

		Returns True when the timeout (anomaly) payload reliably times out and
		the edge-case payload (ptype=1) reliably succeeds across `tries`
		attempts. This is purely a timing oracle, prone to false positives on
		slow upstreams; pair it with `_smuggle_gadget_probe` for confirmation.
		"""
		for _ in range(tries):
			anomaly_res = check_fn(payload, 0)
			if anomaly_res[0] != 1:
				return False
			edge_res = check_fn(payload, 1)
			if edge_res[0] != 0:
				return False
		return True

	def _get_oracle(self):
		"""Lazily construct and cache a per-target gadget oracle. The
		first call probes the catalogue (a handful of small requests);
		every subsequent call returns the cached selection."""
		oracle = getattr(self, "_oracle", None)
		if oracle is None:
			oracle = GadgetOracle(
				host=self._host,
				port=self._port,
				ssl_flag=self.ssl_flag,
				timeout=self._timeout,
				vhost=self._vhost or self._host,
				proxy=self._proxy,
				baseline_method=self._method,
				baseline_endpoint=self._endpoint,
				quiet=self._quiet,
			)
			self._oracle = oracle
		return oracle

	def _victim_request_str(self):
		"""Canonical victim request used by both the baseline fingerprint
		and the post-attack pipelined victim leg. Kept identical so
		any diff between the two is structural, not request-driven."""
		return (
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (
				self._endpoint, self._vhost or self._host
			)
		)

	def _get_victim_baseline(self):
		"""(Fingerprint, noisy_axes) for a clean victim request. Sampled
		once per scan; populates self._victim_fp / self._victim_noisy."""
		fp = getattr(self, "_victim_fp", None)
		if fp is None:
			fp, noisy = baseline_fingerprint(
				self._host, self._port, self.ssl_flag, self._timeout,
				self._victim_request_str(), self._proxy, n=3,
			)
			self._victim_fp = fp
			self._victim_noisy = noisy
		return self._victim_fp, getattr(self, "_victim_noisy", set())

	def _get_timing_baseline(self):
		"""Cached RTT distribution for a benign victim request. Used by
		_confirm_timeout_anomaly to flag mutations whose RTT is
		statistically far above the median, even when they don't trip
		the binary timeout deadline."""
		tb = getattr(self, "_timing_baseline", None)
		if tb is None:
			tb = TimingBaseline.sample(
				self._host, self._port, self.ssl_flag, self._timeout,
				self._victim_request_str(), self._proxy, n=5,
			)
			self._timing_baseline = tb
		return tb

	def _smuggle_gadget_probe_full(self, payload, mode):
		"""Run the gadget-smuggle probe and return a dict with all
		corroborating diff signals. The caller decides how to combine
		them with the timing signal to produce a confidence tier.

		Result keys:
		  ``gadget_hit``        - bool, did the gadget signature appear?
		  ``victim_fp_diverges`` - bool, did the victim response leg
		                          structurally differ from a clean
		                          baseline?
		  ``axes``              - set[str], which fingerprint axes
		                          differed (empty when no baseline or
		                          no divergence)
		  ``victim_resp``       - bytes/None, raw victim leg for sidecar
		                          dumping by ``write_payload``
		"""
		empty = {"gadget_hit": False, "victim_fp_diverges": False,
				"axes": set(), "victim_resp": None}

		oracle = self._get_oracle()
		og = None
		try:
			og = oracle.select()
		except Exception:
			og = None

		vhost = self._vhost or self._host
		if og is not None:
			path = og.smuggle_path
			method = og.method
			if path == "*":
				smuggled = "%s * HTTP/1.1\r\nHost: %s\r\nX-Smug: 1\r\n\r\n" % (method, vhost)
			else:
				smuggled = "%s %s HTTP/1.1\r\nHost: %s\r\nX-Smug: 1\r\n\r\n" % (method, path, vhost)

			def _matches(text):
				return og.matches(text)
		else:
			smuggled = "GET /robots.txt HTTP/1.1\r\nHost: %s\r\nX-Smug: 1\r\n\r\n" % vhost

			def _matches(text):
				return "llow:" in text

		attack = deepcopy(payload)
		attack.host = self._vhost or self._host
		attack.method = self._method
		attack.endpoint = self._endpoint
		if len(self._cookies) > 0:
			attack.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
		attack.header = self._apply_extra_headers(attack.header)

		if mode == "clte":
			# CL.TE: front-end uses Content-Length, reads only what fits;
			# backend processes chunked, sees the smuggled prefix after the
			# zero-chunk terminator.
			body = "0\r\n\r\n" + smuggled
			attack.cl = len("0\r\n\r\n")  # front-end sees the terminator and stops
			attack.body = body
		elif mode == "tecl":
			# TE.CL: front-end uses Transfer-Encoding (sees full chunked body
			# then leftover smuggled bytes that the backend reads as the next
			# request via its honored Content-Length).
			payload_size_hex = "%x" % len(smuggled)
			body = payload_size_hex + "\r\n" + smuggled + "\r\n" + "0\r\n\r\n"
			attack.cl = len(body)
			attack.body = body
		else:
			return empty

		victim = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (
			cache_bust(self._endpoint, random.randint(1, 1 << 30), name="vcb"),
			self._vhost or self._host
		)

		try:
			web = EasySSL(self.ssl_flag)
			web.connect(self._host, self._port, self._timeout, self._proxy)
			web.pipeline_send([str(attack).encode(), victim.encode()])
			raw = web.recv_all(self._timeout)
			web.close()
		except Exception:
			return empty
		if not raw:
			return empty

		try:
			text = raw.decode('latin-1', errors='replace')
		except Exception:
			return empty

		gadget_hit = _matches(text)

		# Victim-leg fingerprint diff. The recv_multiple parser knows how
		# to split pipelined responses; we use it so a CL/TE-framed gadget
		# response doesn't bleed into the victim leg's bytes.
		victim_fp_diverges = False
		axes = set()
		victim_leg_bytes = None
		try:
			parts = split_pipelined_responses(raw, expected=2)
			if len(parts) >= 2:
				victim_leg_bytes = parts[1].encode('latin-1', errors='replace')
				baseline_fp, noisy = self._get_victim_baseline()
				if baseline_fp.status:  # only diff against a real baseline
					victim_fp = Fingerprint.from_response(victim_leg_bytes)
					axes = victim_fp.diff(baseline_fp) - noisy
					# Require >=2 axes to flip OR a status change to count
					# as a real structural divergence -- single-axis flips
					# (e.g. body_tail on a date stamp the noisy_axes set
					# missed) are too easy to false-positive on.
					if "status" in axes or len(axes) >= 2:
						victim_fp_diverges = True
		except Exception:
			pass

		return {
			"gadget_hit": gadget_hit,
			"victim_fp_diverges": victim_fp_diverges,
			"axes": axes,
			"victim_resp": victim_leg_bytes,
		}

	def _smuggle_gadget_probe(self, payload, mode):
		"""Thin wrapper preserving the legacy ``-> bool`` contract for any
		external caller. Production callers should prefer
		``_smuggle_gadget_probe_full`` so they see the corroborating
		fingerprint signals."""
		res = self._smuggle_gadget_probe_full(payload, mode)
		return res["gadget_hit"] or res["victim_fp_diverges"]


	def _create_exec_test(self, name, te_payload):
		def pretty_print(name, dismsg):
			spacing = 13
			sys.stdout.write("\r"+" "*100+"\r")
			msg = Style.BRIGHT + Fore.MAGENTA + "[%s]%s: %s" % \
			(Fore.CYAN + name + Fore.MAGENTA, " "*(spacing-len(name)), dismsg)
			sys.stdout.write(CF(msg + Style.RESET_ALL))
			sys.stdout.flush()

			if dismsg[-1] == "\n":
				ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
				plaintext = ansi_escape.sub('', msg)
				if self._logh is not None:
					self._logh.write(plaintext)
					self._logh.flush()


		def write_payload(smhost, payload, ptype, response=None,
				status_code=None, timing=None, confidence=None,
				gadget_hit=False):
			scheme = "https" if self.ssl_flag else "http"
			furl = "%s_%s" % (scheme, _safe_host_slug(smhost))
			fname = os.path.join(_payloads_dir(), "%s_%s_%s.txt" % (furl, ptype, name))
			pretty_print("CRITICAL", "%s Payload: %s URL: %s\n" % \
			(Fore.MAGENTA+ptype, Fore.CYAN+fname+Fore.MAGENTA, Fore.CYAN+self._url))
			with open(fname, 'wb') as file:
				file.write(bytes(str(payload),'utf-8'))

			# ---- Sidecars for the web GUI's View dialog -------------------
			# The .txt above is only the REQUEST bytes. The sidecars (written by
			# the shared _write_finding_artifacts helper) let the GUI surface
			# what came back, the timing window, and whether the gadget fired.
			# The status_label tells the GUI how to interpret an empty response
			# (timeout / disconnect / error / normal).
			import datetime as _dt
			base = fname[:-4]  # strip ".txt"
			status_label = {0: "normal", 1: "timeout",
				2: "disconnect", -1: "error"}.get(status_code, "unknown")
			meta = {
				"kind": ptype,
				"mutation": name,
				"url": self._url,
				"method": self._method,
				"configfile": self._configfile.split('/')[-1],
				"confidence": confidence,
				"gadget_hit": bool(gadget_hit),
				"status_code": status_code,
				"status_label": status_label,
				"timing_s": round(timing, 3) if timing is not None else None,
				"request_bytes": len(str(payload).encode('utf-8', errors='replace')),
				"response_bytes": len(self._resp_to_bytes(response)),
				"timestamp": _dt.datetime.utcnow().isoformat() + "Z",
			}
			self._write_finding_artifacts(base, response=response, meta=meta)

			self._record_finding(
				ptype, host=smhost, payload_file=fname, mutation=name,
				status_label=status_label, gadget_hit=bool(gadget_hit),
				confidence=confidence,
				timing=round(timing, 3) if timing is not None else None,
				configfile=self._configfile.split('/')[-1])

		# Initial probe pair
		pretty_print(name, "Checking TECL...")
		start_time = time.time()
		tecl_res = self._check_tecl(te_payload, 0)
		tecl_time = time.time() - start_time

		pretty_print(name, "Checking CLTE...")
		start_time = time.time()
		clte_res = self._check_clte(te_payload, 0)
		clte_time = time.time() - start_time

		# CLTE takes precedence over TECL when both timeouts fire (matches
		# original tool behavior).
		def report(kind, kind_res):
			# Iterative confirmation (replaces the recursive _attempts dance).
			check_fn = self._check_clte if kind == "CLTE" else self._check_tecl
			pretty_print(name, "Confirming %s (timing)..." % kind)
			if not self._confirm_timeout_anomaly(check_fn, te_payload, tries=2):
				dismsg = Fore.YELLOW + ("%s TIMING NOT REPRODUCIBLE" % kind) + ["\n", ""][self._quiet]
				pretty_print(name, dismsg)
				return False

			# Positive smuggling oracle: try to actually surface the gadget
			# AND structurally fingerprint the victim leg against a clean
			# baseline. Either signal corroborates the timing anomaly --
			# we don't require both because edge cases exist where the
			# gadget body is swallowed but the victim leg is empty /
			# status-flipped, and vice versa.
			pretty_print(name, "Confirming %s (gadget + fingerprint)..." % kind)
			probe = {"gadget_hit": False, "victim_fp_diverges": False, "axes": set(), "victim_resp": None}
			try:
				probe = self._smuggle_gadget_probe_full(te_payload, kind.lower())
			except Exception:
				pass

			# Statistical timing corroboration on top of the binary
			# timeout signal. Uses the cached per-target baseline; the
			# anomaly RTT here is the kind_res original timing window
			# (clte_time / tecl_time) -- it already fired the timeout
			# (kind_res[0] == 1), but we still consult is_anomalous() so
			# the confidence tier reflects whether the spike was
			# statistically significant beyond just "exceeded our
			# arbitrary 5s deadline".
			rtt_anomalous = False
			try:
				tb = self._get_timing_baseline()
				anomaly_rtt = clte_time if kind == "CLTE" else tecl_time
				rtt_anomalous = tb.is_anomalous(anomaly_rtt, k=3.0)
			except Exception:
				rtt_anomalous = False

			# Signal tally: timing-reproducible is already a given (we
			# returned False above otherwise). The other three are
			# corroborators.
			signals = {
				"gadget": probe["gadget_hit"],
				"fingerprint": probe["victim_fp_diverges"],
				"rtt": rtt_anomalous,
			}
			vote_count = sum(1 for v in signals.values() if v)

			# Tiered confidence:
			#   STRONG    - timing-reproducible + 2 or 3 corroborators
			#   CONFIRMED - timing-reproducible + exactly 1 corroborator
			#   Potential - timing-reproducible only, no corroborator
			if vote_count >= 2:
				confidence = "STRONG"
			elif vote_count == 1:
				confidence = "CONFIRMED"
			else:
				confidence = "Potential"

			# Build a compact signal annotation for the operator: which
			# corroborators fired and (for the fingerprint signal) which
			# axes diverged.
			annot_parts = []
			if signals["gadget"]:
				annot_parts.append("gadget")
			if signals["fingerprint"]:
				if probe["axes"]:
					annot_parts.append("fp=" + "+".join(sorted(probe["axes"])))
				else:
					annot_parts.append("fp")
			if signals["rtt"]:
				annot_parts.append("rtt")
			annot = ("[" + ",".join(annot_parts) + "]") if annot_parts else ""

			scheme = ["http://", "https://"][self.ssl_flag]
			dismsg = (
				Fore.RED + ("%s %s Issue Found" % (confidence, kind))
				+ Fore.MAGENTA + " - " + Fore.CYAN + self._method
				+ Fore.MAGENTA + " @ " + Fore.CYAN + scheme + self._host + self._endpoint
				+ Fore.MAGENTA + " - " + Fore.CYAN + self._configfile.split('/')[-1]
				+ ((Fore.MAGENTA + " " + annot) if annot else "")
				+ "\n"
			)
			pretty_print(name, dismsg)
			write_payload(
				self._host, kind_res[2], kind,
				response=kind_res[1],
				status_code=kind_res[0],
				timing=clte_time if kind == "CLTE" else tecl_time,
				confidence=confidence,
				gadget_hit=probe["gadget_hit"],
			)
			return True

		if clte_res[0] == 1:
			if report("CLTE", clte_res):
				return True
		elif tecl_res[0] == 1:
			if report("TECL", tecl_res):
				return True
		elif (tecl_res[0] == -1) or (clte_res[0] == -1):
			dismsg = Fore.YELLOW + "SOCKET ERROR" + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)
		elif (tecl_res[0] == 0) and (clte_res[0] == 0):
			tecl_msg = (Fore.MAGENTA + " (TECL: " + Fore.CYAN + "%.2f" + Fore.MAGENTA + " - " +
				Fore.CYAN + "%s" + Fore.MAGENTA + ")") % (tecl_time, tecl_res[1][9:9+3])
			clte_msg = (Fore.MAGENTA + " (CLTE: " + Fore.CYAN + "%.2f" + Fore.MAGENTA + " - " +
				Fore.CYAN + "%s" + Fore.MAGENTA + ")") % (clte_time, clte_res[1][9:9+3])
			dismsg = Fore.GREEN + "OK" + tecl_msg + clte_msg + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)
		elif (tecl_res[0] == 2) or (clte_res[0] == 2):
			dismsg = Fore.YELLOW + "DISCONNECTED" + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)

		return False

class ReplayManager():
	def __init__(self, custom_request, host, port, ssl_flag, timeout, proxy=None, logh=None, baseline_request=None, persistent_connection=False):
		self.custom_request = custom_request
		self.baseline_request = baseline_request
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.proxy = proxy
		self.logh = logh
		self.persistent_connection = persistent_connection
		self.web_connection = None
		self.stats = {
			'total_requests': 0,
			'successful_requests': 0,
			'failed_requests': 0,
			'timeout_requests': 0,
			'error_requests': 0,
			'baseline_requests': 0,
			'baseline_successful': 0,
			'baseline_failed': 0,
			'baseline_timeout': 0,
			'baseline_error': 0,
			'start_time': None,
			'last_request_time': None
		}
		self.running = False
		self.request_id = 0
		self.baseline_response = None
		
	def generate_request_id(self):
		"""Generate a unique identifier for each request"""
		self.request_id += 1
		timestamp = int(time.time() * 1000)  # milliseconds
		return f"REQ-{timestamp}-{self.request_id:06d}"
	
	def establish_persistent_connection(self):
		"""Establish a persistent connection if enabled"""
		if self.persistent_connection and not self.web_connection:
			try:
				self.web_connection = EasySSL(self.ssl_flag)
				self.web_connection.connect(self.host, self.port, self.timeout, self.proxy, persistent=True)
				print_info("Persistent connection established for replay mode")
			except Exception as e:
				print_info(f"Failed to establish persistent connection: {e}")
				self.web_connection = None
				# Disable persistent connection if it fails
				self.persistent_connection = False

	def close_persistent_connection(self):
		"""Close the persistent connection if it exists"""
		if self.web_connection:
			try:
				self.web_connection.close()
				self.web_connection = None
			except Exception as e:
				print_info(f"Error closing persistent connection: {e}")
	
	# stat key -> (total_key, success_key, fail_key, timeout_key, error_key)
	_STAT_BUCKETS = {
		'attack': ('total_requests', 'successful_requests', 'failed_requests', 'timeout_requests', 'error_requests'),
		'baseline': ('baseline_requests', 'baseline_successful', 'baseline_failed', 'baseline_timeout', 'baseline_error'),
	}

	def _send_with_id(self, request_id, build_fn, bucket):
		"""Generic send: builds the request via `build_fn(request_id)`, sends
		it on the persistent or per-request socket, classifies the outcome,
		and bumps the appropriate stat bucket. Replaces the previous
		near-duplicate send_request / send_baseline_request pair."""
		total_k, ok_k, fail_k, timeout_k, error_k = self._STAT_BUCKETS[bucket]
		try:
			if self.persistent_connection and self.web_connection and getattr(self.web_connection, 'connected', False):
				web = self.web_connection
			elif self.persistent_connection:
				self.establish_persistent_connection()
				web = self.web_connection
				if web is None:
					web = EasySSL(self.ssl_flag)
					web.connect(self.host, self.port, self.timeout, self.proxy)
			else:
				web = EasySSL(self.ssl_flag)
				web.connect(self.host, self.port, self.timeout, self.proxy)

			request_data = build_fn(request_id)
			web.send(request_data.encode())

			start_time = datetime.now()
			res = web.recv_nb(self.timeout)
			end_time = datetime.now()

			if not self.persistent_connection:
				web.close()

			self.stats[total_k] += 1
			if bucket == 'attack':
				self.stats['last_request_time'] = end_time

			if res is None:
				delta_seconds = (end_time - start_time).total_seconds()
				if delta_seconds < (self.timeout - 1):
					self.stats[fail_k] += 1
					self._reset_persistent_on_anomaly()
					return (2, res, request_id)
				self.stats[timeout_k] += 1
				self._reset_persistent_on_anomaly()
				return (1, res, request_id)
			self.stats[ok_k] += 1
			return (0, res, request_id)
		except Exception:
			self.stats[error_k] += 1
			self._reset_persistent_on_anomaly()
			return (-1, None, request_id)

	def _reset_persistent_on_anomaly(self):
		"""Tear down and re-establish the persistent connection. Any anomaly
		may have left undrained bytes that would poison subsequent reads."""
		if not self.persistent_connection or self.web_connection is None:
			return
		try:
			self.web_connection.close()
		except Exception:
			pass
		self.web_connection = None
		self.establish_persistent_connection()

	def send_request(self, request_id):
		return self._send_with_id(request_id, self.build_request_with_id, 'attack')

	def send_baseline_request(self, request_id):
		if not self.baseline_request:
			return None
		return self._send_with_id(request_id, self.build_baseline_request_with_id, 'baseline')
	
	_HTTP_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE')

	def _build_request_with_id(self, request_blob, request_id, id_param_name):
		"""Inject an id+timestamp query string into the first request line and
		rebuild the request. Critically: when the request has a body, we
		recompute Content-Length so a strict backend doesn't reject the
		request (or worse, desync the connection and be misreported as a
		finding)."""
		raw = request_blob.get('raw', '')
		# Preserve raw CRLF/LF boundary then normalize at the end.
		lines = raw.split('\n')

		first_idx = 0
		for i, line in enumerate(lines):
			line_stripped = line.strip()
			if line_stripped and ' ' in line_stripped:
				parts = line_stripped.split(' ')
				if len(parts) >= 2 and parts[0] in self._HTTP_METHODS:
					first_idx = i
					break

		request_line = lines[first_idx].strip()
		request_parts = request_line.split(' ')
		method = request_parts[0]
		endpoint = request_parts[1]
		http_version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"

		timestamp = int(time.time() * 1000)
		separator = '&' if '?' in endpoint else '?'
		modified_endpoint = "%s%s%s=%s&timestamp=%d" % (
			endpoint, separator, id_param_name, request_id, timestamp
		)
		lines[first_idx] = "%s %s %s" % (method, modified_endpoint, http_version)

		# Locate header/body boundary so we can recompute Content-Length on
		# the actual body bytes (handles both LF-only and CRLF-LF files).
		body_idx = None
		for j in range(first_idx + 1, len(lines)):
			if lines[j].strip() == "":
				body_idx = j
				break

		if body_idx is not None:
			body_bytes = '\n'.join(lines[body_idx + 1:])
			# Re-normalize body to CRLF for the wire so length accounting is
			# consistent with what the server will see.
			body_crlf = body_bytes.replace('\r\n', '\n').replace('\n', '\r\n')
			cl = len(body_crlf.encode('latin-1', errors='replace'))
			for k in range(first_idx + 1, body_idx):
				name_part = lines[k].split(':', 1)[0].strip().lower()
				if name_part == 'content-length':
					lines[k] = 'Content-Length: %d' % cl
					break

		modified_request = '\n'.join(lines)
		# Normalize to CRLF for the wire.
		modified_request = modified_request.replace('\r\n', '\n').replace('\n', '\r\n')
		return modified_request

	def build_request_with_id(self, request_id):
		return self._build_request_with_id(self.custom_request, request_id, 'request_id')

	def build_baseline_request_with_id(self, request_id):
		return self._build_request_with_id(self.baseline_request, request_id, 'baseline_id')
	
	def compare_responses(self, smuggled_response, baseline_response):
		"""Compare smuggled response with baseline response and return differences"""
		if not baseline_response or not smuggled_response:
			return "No baseline response to compare"
		
		# Filter out problematic characters from both responses
		def filter_response(res):
			if res is None:
				return ""
			filtered = ""
			for single in res:
				if single > 0x7F:
					filtered += '\x30'
				else:
					filtered += chr(single)
			return filtered
		
		smuggled_filtered = filter_response(smuggled_response)
		baseline_filtered = filter_response(baseline_response)
		
		# Compare status codes
		smuggled_status = smuggled_filtered[9:12] if len(smuggled_filtered) > 12 else "N/A"
		baseline_status = baseline_filtered[9:12] if len(baseline_filtered) > 12 else "N/A"
		
		# Compare response lengths
		smuggled_length = len(smuggled_filtered)
		baseline_length = len(baseline_filtered)
		
		differences = []
		if smuggled_status != baseline_status:
			differences.append(f"Status: {baseline_status} -> {smuggled_status}")
		if smuggled_length != baseline_length:
			differences.append(f"Length: {baseline_length} -> {smuggled_length}")
		
		# Check for content differences (simplified comparison)
		if smuggled_filtered != baseline_filtered:
			differences.append("Content differs")
		
		return "; ".join(differences) if differences else "Responses match"
	
	def display_stats(self):
		"""Display current statistics"""
		if self.stats['start_time']:
			elapsed = datetime.now() - self.stats['start_time']
			elapsed_seconds = elapsed.total_seconds()
			requests_per_second = self.stats['total_requests'] / elapsed_seconds if elapsed_seconds > 0 else 0
		else:
			elapsed_seconds = 0
			requests_per_second = 0
		
		# Clear line and display stats
		sys.stdout.write("\r" + " " * 100 + "\r")
		stats_msg = (Style.BRIGHT + Fore.CYAN + "[REPLAY] " + 
					Fore.MAGENTA + "Total: " + Fore.GREEN + str(self.stats['total_requests']) + 
					Fore.MAGENTA + " | Success: " + Fore.GREEN + str(self.stats['successful_requests']) +
					Fore.MAGENTA + " | Failed: " + Fore.RED + str(self.stats['failed_requests']) +
					Fore.MAGENTA + " | Timeout: " + Fore.YELLOW + str(self.stats['timeout_requests']) +
					Fore.MAGENTA + " | Error: " + Fore.RED + str(self.stats['error_requests']))
		
		# Add baseline stats if baseline requests are being sent
		if self.baseline_request:
			stats_msg += (Fore.MAGENTA + " | Baseline: " + Fore.GREEN + str(self.stats['baseline_successful']) +
						Fore.MAGENTA + "/" + Fore.RED + str(self.stats['baseline_requests']))
		
		stats_msg += (Fore.MAGENTA + " | RPS: " + Fore.CYAN + f"{requests_per_second:.2f}" +
					Fore.MAGENTA + " | ID: " + Fore.CYAN + f"REQ-{self.request_id:06d}" + Style.RESET_ALL)
		
		sys.stdout.write(CF(stats_msg))
		sys.stdout.flush()
	
	def run_replay(self):
		"""Run the continuous replay loop"""
		if not self.custom_request:
			print_info("Error: No request file provided for replay mode")
			return
		
		# Establish persistent connection if enabled
		if self.persistent_connection:
			self.establish_persistent_connection()
		
		self.running = True
		self.stats['start_time'] = datetime.now()
		
		print_info("Starting continuous replay mode... Press Ctrl+C to stop")
		print_info("Target: %s" % (Fore.CYAN + f"{'https' if self.ssl_flag else 'http'}://{self.host}:{self.port}"))
		print_info("Request: %s" % (Fore.CYAN + f"{self.custom_request['method']} {self.custom_request['endpoint']}"))
		if self.baseline_request:
			print_info("Baseline: %s" % (Fore.CYAN + f"{self.baseline_request['method']} {self.baseline_request['endpoint']}"))
		
		try:
			while self.running:
				request_id = self.generate_request_id()
				
				# Send the smuggling POC request
				result = self.send_request(request_id)
				
				# Send baseline request after smuggling request if baseline is configured
				baseline_result = None
				if self.baseline_request:
					# Add a small delay between requests when using persistent connection
					if self.persistent_connection:
						time.sleep(0.01)  # 10ms delay between requests
					baseline_result = self.send_baseline_request(request_id)
					
					# Compare responses if both were successful
					if result[0] == 0 and baseline_result and baseline_result[0] == 0:
						comparison = self.compare_responses(result[1], baseline_result[1])
						if "differs" in comparison or "->" in comparison:
							# Log significant differences
							print_info("Response difference detected: %s" % (Fore.YELLOW + comparison))
				
				# Display stats every request
				self.display_stats()
				
				# Small delay to prevent overwhelming the server
				time.sleep(0.1)
				
		except KeyboardInterrupt:
			self.running = False
			print_info("\nReplay stopped by user")
			self.display_final_stats()
		except Exception as e:
			self.running = False
			print_info(f"\nReplay stopped due to error: {e}")
			self.display_final_stats()
		finally:
			# Close persistent connection if it was established
			if self.persistent_connection:
				self.close_persistent_connection()
	
	def display_final_stats(self):
		"""Display final statistics when replay stops"""
		if self.stats['start_time']:
			elapsed = datetime.now() - self.stats['start_time']
			elapsed_seconds = elapsed.total_seconds()
			requests_per_second = self.stats['total_requests'] / elapsed_seconds if elapsed_seconds > 0 else 0
		else:
			elapsed_seconds = 0
			requests_per_second = 0
		
		print_info("=" * 60)
		print_info("REPLAY STATISTICS")
		print_info("=" * 60)
		print_info("Total Requests    : %s" % (Fore.CYAN + str(self.stats['total_requests'])))
		print_info("Successful        : %s" % (Fore.GREEN + str(self.stats['successful_requests'])))
		print_info("Failed            : %s" % (Fore.RED + str(self.stats['failed_requests'])))
		print_info("Timeouts          : %s" % (Fore.YELLOW + str(self.stats['timeout_requests'])))
		print_info("Errors            : %s" % (Fore.RED + str(self.stats['error_requests'])))
		
		# Add baseline statistics if baseline requests were sent
		if self.baseline_request and self.stats['baseline_requests'] > 0:
			print_info("")
			print_info("Baseline Requests : %s" % (Fore.CYAN + str(self.stats['baseline_requests'])))
			print_info("Baseline Success  : %s" % (Fore.GREEN + str(self.stats['baseline_successful'])))
			print_info("Baseline Failed   : %s" % (Fore.RED + str(self.stats['baseline_failed'])))
			print_info("Baseline Timeouts : %s" % (Fore.YELLOW + str(self.stats['baseline_timeout'])))
			print_info("Baseline Errors   : %s" % (Fore.RED + str(self.stats['baseline_error'])))
		
		print_info("Duration          : %s" % (Fore.CYAN + f"{elapsed_seconds:.2f} seconds"))
		print_info("Requests/Second   : %s" % (Fore.CYAN + f"{requests_per_second:.2f}"))
		if self.stats['last_request_time']:
			print_info("Last Request      : %s" % (Fore.CYAN + self.stats['last_request_time'].strftime("%Y-%m-%d %H:%M:%S")))
		print_info("=" * 60)

def warn_if_request_unsafe_for_scan_mode(parsed, filepath):
	"""Emit warnings when a -r/--request file looks like a smuggling POC.

	In scan mode (no --replay) Smuggler only consumes the request file as a
	template -- it pulls method/endpoint/host/cookies and synthesizes its
	own smuggling payloads from the chosen config. Anything else in the
	file (body, additional request lines, header CRLF injection) is
	silently ignored. Users who pasted a Burp POC sometimes expect those
	bytes to be sent on the wire and get confused when they aren't.

	This is a no-op in replay mode (`--replay` sends the file verbatim).
	"""
	raw = parsed.get('raw', '') or ''
	body = parsed.get('body', '') or ''
	headers_section = parsed.get('headers', '') or ''
	warnings = []

	method_verbs = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE')

	# Body present at all -> ignored in scan mode. Pre-empt the "where did
	# my payload go?" confusion.
	if body.strip():
		warnings.append("body bytes (%d) will be ignored -- scan mode synthesizes its own payload bodies" % len(body))

	# Heuristic: body contains an HTTP method + " HTTP/" within the first
	# few lines -> smuggled-prefix POC (chunked POCs typically have a
	# `0\r\n\r\n` zero-chunk before the request line). Surface explicitly.
	for body_line in body.lstrip().split('\n', 10)[:10]:
		body_line = body_line.strip()
		if not body_line:
			continue
		toks = body_line.split(' ', 2)
		if len(toks) >= 3 and toks[0] in method_verbs and toks[2].startswith('HTTP/'):
			warnings.append("body contains an embedded request line (%r) -- this is a smuggling POC, use --replay to send verbatim" % body_line[:80])
			break

	# Heuristic: a second request line *inside* the headers section (not the
	# body) is almost always an attempted smuggle that won't survive
	# template extraction.
	header_lines = headers_section.split('\n')[1:]  # skip the real request line
	for line in header_lines:
		token = line.strip().split(' ', 1)
		if token and token[0] in method_verbs:
			warnings.append("looks like an embedded second request line (%r) -- pass with --replay if you intended to send it verbatim" % line.strip()[:80])
			break

	# Heuristic: header VALUE containing what looks like a request line
	# (Bearer-token-style POC where the value embeds another GET/POST).
	for line in header_lines:
		if ':' not in line:
			continue
		_, _, value = line.partition(':')
		v = value.strip()
		for verb in ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS '):
			if verb in v and ' HTTP/' in v:
				warnings.append("header value contains an embedded request line (%r) -- this is a POC-shaped file, scan mode will not send it" % line.strip()[:80])
				break

	if '\r\n\r\n' in raw and raw.split('\r\n\r\n', 1)[1].strip():
		# Body is present and non-empty; already warned above, but if we
		# DIDN'T warn (body was whitespace) skip.
		pass

	if not warnings:
		return

	print_info("Notice: %s contains content that will NOT be used in scan mode:" % (Fore.CYAN + filepath))
	for w in warnings:
		print_info("        - " + Fore.YELLOW + w)
	print_info("        Use " + Fore.CYAN + "--replay" + Fore.MAGENTA + " to send the request verbatim, or " + Fore.CYAN + "--baseline-request" + Fore.MAGENTA + " for a control sample.")


def _confirm_payload_kind(payload_path):
	"""Best-effort kind label for a payload file, for the picker display."""
	base = payload_path[:-4] if payload_path.endswith(".txt") else payload_path
	try:
		import json as _json
		meta = _json.loads(open(base + ".meta.json", encoding="utf-8").read())
		if meta.get("kind"):
			return meta["kind"]
	except (OSError, ValueError):
		pass
	stem = os.path.basename(base).split("_")
	return stem[-2] if len(stem) >= 3 else "?"


def _strip_cache_buster(path):
	"""Drop the cache-buster (cb=/vcb=) parameter we bake into saved request
	lines so a recovered endpoint starts clean."""
	if "?" not in path:
		return path
	head, _, query = path.partition("?")
	kept = [tok for tok in query.split("&")
		if tok and not tok.startswith(("cb=", "vcb="))]
	return head + ("?" + "&".join(kept) if kept else "")


def _target_from_request_file(payload_path):
	"""Recover (url, method) from a finding's saved request bytes when no
	.meta.json url is available. The request line yields the method and
	endpoint, the first Host header yields the authority, and the scheme is
	read from the payload filename prefix (adv_write names files
	'<scheme>_<host>_...'). Returns None if the file can't be parsed into a
	usable target."""
	try:
		with open(payload_path, "rb") as f:
			raw = f.read()
	except OSError:
		return None
	lines = raw.decode("latin-1", errors="replace").replace("\r\n", "\n").split("\n")
	request_line = next((ln for ln in lines if ln.strip()), "")
	parts = request_line.split(" ")
	if len(parts) < 2 or not parts[1].startswith("/"):
		return None
	method, path = parts[0], _strip_cache_buster(parts[1])
	# The first Host header holds the real authority; later duplicate Host
	# lines are part of the smuggling mutation itself.
	host = None
	for ln in lines[1:]:
		if ln.strip() == "":
			break  # end of headers
		if ln.lower().startswith("host:"):
			host = ln.split(":", 1)[1].strip()
			break
	if not host:
		return None
	scheme = "http" if os.path.basename(payload_path).startswith("http_") else "https"
	return "%s://%s%s" % (scheme, host, path), method


def _derive_confirm_target(payload_path, args):
	"""Resolve (host, port, endpoint, ssl_flag, method) for a confirmation
	run, preferring the payload's .meta.json url, then -u/--url, and finally
	falling back to the target recovered from the saved request bytes (so a
	finding with a missing/urlless sidecar is still confirmable)."""
	base = payload_path[:-4] if payload_path.endswith(".txt") else payload_path
	url = None
	meta_method = None
	try:
		import json as _json
		meta = _json.loads(open(base + ".meta.json", encoding="utf-8").read())
		url = meta.get("url")
		meta_method = meta.get("method")
	except (OSError, ValueError):
		pass
	method = meta_method or "POST"
	if not url:
		url = args.url
	if not url:
		recovered = _target_from_request_file(payload_path)
		if recovered:
			url, req_method = recovered
			if not meta_method and req_method:
				method = req_method
	if not url:
		return None
	host, port, endpoint, ssl_flag = process_uri(url)
	return host, port, endpoint, ssl_flag, method


def run_confirmation(args):
	"""Drive a single self-contained confirmation. Returns a process exit
	code: 0 = CONFIRMED, 1 = NOT CONFIRMED, 2 = refused / setup error."""
	payloads_dir = _repo_payloads_dir()
	payload = args.confirm_payload

	if not payload:
		if args.quiet:
			print_info("Error: --confirm in --quiet mode requires --confirm-payload")
			return 2
		import glob
		candidates = sorted(
			f for f in glob.glob(os.path.join(payloads_dir, "*.txt"))
			if not f.endswith(".response.txt"))
		if not candidates:
			print_info("No payload files found in %s -- run a scan first." % (Fore.CYAN + payloads_dir))
			return 2
		print_info("Select a finding to confirm:")
		for i, f in enumerate(candidates):
			print_info("  [%d] %s (%s)" % (
				i, Fore.CYAN + os.path.basename(f) + Fore.MAGENTA,
				Fore.YELLOW + _confirm_payload_kind(f)))
		try:
			choice = input("Pick a finding number (or blank to cancel): ").strip()
		except (EOFError, KeyboardInterrupt):
			print_info("\nConfirmation cancelled.")
			return 2
		if not choice:
			print_info("Confirmation cancelled.")
			return 2
		try:
			payload = candidates[int(choice)]
		except (ValueError, IndexError):
			print_info("Invalid selection.")
			return 2

	target = _derive_confirm_target(payload, args)
	if not target:
		print_info("Error: cannot determine target from the .meta.json url or the saved request; pass -u/--url.")
		return 2
	host, port, endpoint, ssl_flag, method = target

	cookies = ""
	if args.cookies:
		cookies = args.cookies

	print_info("Confirming  : %s" % (Fore.CYAN + os.path.basename(payload)))
	print_info("Target      : %s://%s:%d" % ("https" if ssl_flag else "http", host, port))
	print_info("Mode        : %s" % (Fore.CYAN + family_for_kind(_confirm_payload_kind(payload))))
	print_info("Note        : single-connection, your own requests only; no third-party traffic is captured.")

	confirmer = DesyncConfirmer(
		host, port, ssl_flag, float(args.timeout), proxy=args.proxy,
		vhost=args.vhost, cookies=cookies, method=method, endpoint=endpoint,
		payloads_dir=payloads_dir)
	try:
		ok = confirmer.confirm(payload, followup_path=args.confirm_followup)
	except ConfirmError as e:
		print_info("Confirmation refused: %s" % (Fore.YELLOW + str(e)))
		return 2
	except Exception as e:
		print_info("Confirmation error: %s" % (Fore.RED + str(e)))
		return 2

	colour = Fore.GREEN if ok else Fore.YELLOW
	print_info(colour + confirmer.summarize())
	evidence = getattr(confirmer, "_evidence_path", None)
	if evidence:
		print_info("Evidence    : %s" % (Fore.CYAN + evidence))
	return 0 if ok else 1


def process_uri(uri):
	u = urlparse(uri)

	if u.scheme == "https":
		ssl_flag = True
		std_port = 443
	elif u.scheme == "http":
		ssl_flag = False
		std_port = 80
	else:
		print_info("Error malformed URL not supported: %s" % (Fore.CYAN + uri))
		exit(1)

	path = u.path or "/"
	# Preserve query string + fragment so endpoints like
	# `/foo?action=bar&id=1` aren't silently truncated to `/foo` before
	# being fed to the smuggling payloads.
	if u.query:
		path += "?" + u.query
	if u.fragment:
		path += "#" + u.fragment
	if u.port:
		return (u.hostname, u.port, path, ssl_flag)
	else:
		return (u.hostname, std_port, path, ssl_flag)

# Module-level default so importers (tests, other tools) can call CF()
# before __main__ has a chance to populate the global.
NOCOLOR = False

def CF(text):
	global NOCOLOR
	if NOCOLOR:
		ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
		text = ansi_escape.sub('', text)
	return text

def banner(sm_version):
	print(CF(Fore.CYAN))
	print(CF(r"  ______                         _              "))
	print(CF(r" / _____)                       | |             "))
	print(CF(r"( (____  ____  _   _  ____  ____| | _____  ____ "))
	print(CF(r" \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)"))
	print(CF(r" _____) ) | | | |_| ( (_| ( (_| | || ____| |    "))
	print(CF(r"(______/|_|_|_|____/ \___ |\___ |\_)_____)_|    "))
	print(CF(r"                    (_____(_____|               "))
	print(CF(r""))
	print(CF(r"     @l0lsec                           %s"%(sm_version)))
	print(CF(Style.RESET_ALL))

def print_info(msg, file_handle=None):
	ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
	msg = Style.BRIGHT + Fore.MAGENTA + "[%s] %s"%(Fore.CYAN+'+'+Fore.MAGENTA, msg) + Style.RESET_ALL
	plaintext = ansi_escape.sub('', msg)
	print(CF(msg))
	if file_handle is not None:
		file_handle.write(plaintext+"\n")

if __name__ == "__main__":
	if sys.version_info < (3, 0):
		print("Error: Smuggler requires Python 3.x")
		sys.exit(1)

	Parser = argparse.ArgumentParser()
	Parser.add_argument('-u', '--url', help="Target URL with Endpoint")
	Parser.add_argument('-v', '--vhost', default="", help="Specify a virtual host")
	Parser.add_argument('-x', '--exit_early', action='store_true',help="Exit scan on first finding")
	Parser.add_argument('-m', '--method', default="POST", help="HTTP method to use (e.g GET, POST) Default: POST")
	Parser.add_argument('-l', '--log', help="Specify a log file")
	Parser.add_argument('-q', '--quiet', action='store_true', help="Quiet mode will only log issues found")
	Parser.add_argument('-t', '--timeout', default=5.0, help="Socket timeout value Default: 5")
	Parser.add_argument('--no-color', action='store_true', help="Suppress color codes")
	Parser.add_argument('-c', '--configfile', default="default.py", help="Filepath to the configuration file of payloads")
	Parser.add_argument('--proxy', help="Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)")
	Parser.add_argument('--cookies', help="Custom cookies to include in all requests (e.g., 'sessionid=abc123; csrftoken=xyz789')")
	Parser.add_argument('-r', '--request', help="File containing raw HTTP request to use as template")
	Parser.add_argument('--replay', action='store_true', help="Replay the request file continuously until stopped (Ctrl+C)")
	Parser.add_argument('--baseline-request', help="File containing normal HTTP request for baseline comparison in replay mode (sent immediately after smuggling POC)")
	Parser.add_argument('--persistent-connection', action='store_true', help="Use a single persistent TCP connection for all requests instead of creating new connections")
	Parser.add_argument('--scan-type', default="tecl,clte", help="Comma-separated scan types: tecl,clte,cl0,pause,connection-state,parser-discrepancy,header-removal,expect,te0,bare-lf,hop-by-hop,h2,all (default: tecl,clte)")
	Parser.add_argument('--http2', action='store_true', help="Enable HTTP/2 downgrade scans")
	Parser.add_argument('--pause-timeout', type=int, default=61, help="Timeout in seconds for pause-based desync (default: 61)")
	Parser.add_argument('--output-json', metavar="PATH", help="Write an aggregate machine-readable findings report to PATH at the end of the run")
	Parser.add_argument('--output-format', choices=("json", "sarif"), default="json", help="Format for --output-json: json (default) or sarif (SARIF 2.1.0)")
	Parser.add_argument('--confirm', action='store_true', help="Self-contained confirmation: replay a finding from payloads/ on a single connection using only your own requests (no third-party traffic)")
	Parser.add_argument('--confirm-payload', help="Path to the payloads/*.txt finding to confirm (skips the interactive picker)")
	Parser.add_argument('--confirm-followup', help="Optional file with your own follow-up request (prefix/pause modes); a benign canary GET is synthesized if omitted")
	Args = Parser.parse_args()  # returns data from the options specified (echo)

	NOCOLOR = Args.no_color
	if os.name == 'nt':
		NOCOLOR = True

	Version = "v2.0"
	banner(Version)

	if sys.version_info < (3, 0):
		print_info("Error: Smuggler requires Python 3.x")
		sys.exit(1)

	# Parse request file if provided
	custom_request = None
	if Args.request:
		try:
			custom_request = parse_request_file(Args.request)
		except RequestFileError as e:
			print_info("Error: %s" % (Fore.CYAN + str(e)))
			exit(1)
		print_info("Request File: %s"%(Fore.CYAN + Args.request))
		# In scan mode the request file is only a template for
		# method/endpoint/host/cookies -- warn the user if their file
		# contains body bytes or smuggling POC content that scan mode
		# would silently ignore.
		if not Args.replay:
			warn_if_request_unsafe_for_scan_mode(custom_request, Args.request)
	
	# Parse baseline request file if provided
	baseline_request = None
	if Args.baseline_request:
		try:
			baseline_request = parse_request_file(Args.baseline_request)
		except RequestFileError as e:
			print_info("Error: %s" % (Fore.CYAN + str(e)))
			exit(1)
		print_info("Baseline Request File: %s"%(Fore.CYAN + Args.baseline_request))
		# Baseline is always sent verbatim alongside the smuggle request
		# for comparison -- if THIS one looks POC-shaped the comparison is
		# meaningless, so always warn regardless of mode.
		warn_if_request_unsafe_for_scan_mode(baseline_request, Args.baseline_request)
	
	# Handle replay mode
	if Args.replay:
		if not Args.request:
			print_info("Error: Replay mode requires a request file (-r/--request)")
			Parser.print_help()
			exit(1)
		
		if not custom_request['host']:
			print_info("Error: Request file must contain a Host header for replay mode")
			exit(1)
		
		# Extract host and port from the request
		host = custom_request['host']
		port = 443  # Default HTTPS port
		ssl_flag = True  # Default to HTTPS
		
		# Check if host contains a port. Handle bracketed IPv6 literals
		# ("[::1]:8080") specially -- a naive split(':') would mangle them.
		if host.startswith('['):
			# IPv6 literal, optionally followed by :port outside the brackets.
			close = host.find(']')
			if close != -1:
				port_part = host[close + 1:]
				host = host[1:close]
				if port_part.startswith(':'):
					port = int(port_part[1:])
					ssl_flag = port != 80
		elif ':' in host:
			host, port_str = host.split(':', 1)
			port = int(port_str)
			ssl_flag = port != 80  # Assume HTTPS unless port 80
		
		# Initialize FileHandle for replay mode
		FileHandle = None
		if Args.log is not None:
			try:
				FileHandle = open(Args.log, "w")
			except:
				print_info("Error: Issue with log file destination")
				exit(1)
		
		# Create and run replay manager
		replay_manager = ReplayManager(
			custom_request=custom_request,
			host=host,
			port=port,
			ssl_flag=ssl_flag,
			timeout=float(Args.timeout),
			proxy=Args.proxy,
			logh=FileHandle,
			baseline_request=baseline_request,
			persistent_connection=Args.persistent_connection
		)
		replay_manager.run_replay()
		if FileHandle is not None:
			FileHandle.close()
		exit(0)

	# Self-contained confirmation mode. Handled before the scan-target
	# requirement because it derives its target from the chosen payload's
	# sidecar metadata (falling back to -u). Replays only our own requests.
	if Args.confirm:
		exit(run_confirmation(Args))

	# If the URL argument is not specified then check stdin or request file
	if Args.url is None and Args.request is None:
		if sys.stdin.isatty():
			print_info("Error: no direct URL, request file, or piped URL specified\n")
			Parser.print_help()
			exit(1)
		Servers = sys.stdin.read().split("\n")
	elif Args.request:
		# If request file is provided, use it to determine the target
		if custom_request['host']:
			# Build URL from request file
			# Assume HTTPS by default unless the host contains a port or URL is specified
			target_url = "https://" + custom_request['host'] + custom_request['endpoint']
			Servers = [target_url + " " + custom_request['method']]
		else:
			print_info("Error: Request file must contain a Host header")
			exit(1)
	else:
		Servers = [Args.url + " " + Args.method]

	FileHandle = None
	if Args.log is not None:
		try:
			FileHandle = open(Args.log, "w")
		except:
			print_info("Error: Issue with log file destination")
			print(Parser.print_help())
			sys.exit(1)

	all_findings = []
	for server in Servers:
		# If the next on the list is blank, continue
		if server == "":
			continue
		# Tokenize
		server = server.split(" ")

		# This is for the stdin case, if no method was specified default to GET
		if len(server) == 1:
			server += [Args.method]

		# If a protocol is not specified then default to https
		if server[0].lower().strip()[0:4] != "http":
			server[0] = "https://" + server[0]


		host, port, endpoint, SSLFlagval = process_uri(server[0])
		method = server[1].upper()
		configfile = Args.configfile
		
		# Override with values from custom request if provided
		if custom_request:
			method = custom_request['method']
			endpoint = custom_request['endpoint']

		print_info("URL        : %s"%(Fore.CYAN + server[0]), FileHandle)
		print_info("Method     : %s"%(Fore.CYAN + method), FileHandle)
		print_info("Endpoint   : %s"%(Fore.CYAN + endpoint), FileHandle)
		print_info("Configfile : %s"%(Fore.CYAN + configfile), FileHandle)
		print_info("Timeout    : %s"%(Fore.CYAN + str(float(Args.timeout)) + Fore.MAGENTA + " seconds"), FileHandle)
		if Args.proxy:
			print_info("Proxy      : %s"%(Fore.CYAN + Args.proxy), FileHandle)
		if Args.cookies:
			print_info("Cookies    : %s"%(Fore.CYAN + Args.cookies), FileHandle)
		if Args.request:
			print_info("Request    : %s"%(Fore.CYAN + Args.request), FileHandle)
		print_info("Scan Types : %s"%(Fore.CYAN + Args.scan_type), FileHandle)

		scan_types_str = Args.scan_type
		if Args.http2 and "h2" not in scan_types_str:
			scan_types_str += ",h2"

		requested_scans = [s.strip() for s in scan_types_str.split(",") if s.strip()]
		if "all" in requested_scans:
			requested_scans = ["tecl", "clte", "cl0", "pause", "connection-state",
				"parser-discrepancy", "header-removal", "expect",
				"te0", "bare-lf", "hop-by-hop", "h2"]

		classic_scans = [s for s in requested_scans if s in ("tecl", "clte")]
		advanced_scans = [s for s in requested_scans if s not in ("tecl", "clte")]

		if classic_scans:
			sm = Desyncr.from_args(configfile, host, port, server[0], method, endpoint,
				SSLFlagval, FileHandle, Args, custom_request=custom_request)
			sm.run()
			all_findings.extend(sm._findings)

		if advanced_scans:
			print_info("Advanced   : %s"%(Fore.CYAN + ", ".join(advanced_scans)), FileHandle)
			sm_adv = Desyncr.from_args(configfile, host, port, server[0], method, endpoint,
				SSLFlagval, FileHandle, Args, custom_request=custom_request)
			sm_adv.run_advanced_scans(advanced_scans, pause_timeout=Args.pause_timeout)
			all_findings.extend(sm_adv._findings)


	if getattr(Args, 'output_json', None):
		try:
			n = write_findings_report(all_findings, Args.output_json,
				fmt=Args.output_format, target=getattr(Args, 'url', None) or None)
			print_info("Report     : %s (%d findings, %s)" % (
				Fore.CYAN + Args.output_json + Fore.MAGENTA, n, Args.output_format),
				FileHandle)
		except OSError as e:
			print_info("Error: could not write report to %s: %s" % (Args.output_json, e), FileHandle)

	if FileHandle is not None:
		FileHandle.close()
