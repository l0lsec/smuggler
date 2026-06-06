"""Positive + negative tests for every advanced scanner.

Each scanner is pointed at the mock_server.start() listener configured for
either a known-vulnerable behavior (expect detection True) or a compliant
behavior (expect detection False / no payload file written).

Tests deliberately use very short timeouts so the suite stays fast; this is
fine because mock_server runs in-process.
"""

import os
import sys
import time

import pytest

import tests.mock_server as mock_server
from lib.Scans import (
	ScanCL0, ScanHeaderRemoval, ScanParserDiscrepancy, ScanHopByHop,
	_inject_extra_headers, _build_raw_request,
)


def _print_capture(records):
	def _fn(name, msg):
		records.append((name, msg))
	return _fn


def _write_capture(records):
	# Absorbs the response/baseline/details kwargs the scanners now pass, but
	# keeps the 3-tuple shape so existing assertions stay unchanged.
	def _fn(host, payload, ptype, response=None, baseline=None, details=None):
		records.append((host, ptype, payload))
	return _fn


def _write_capture_detailed(records):
	"""Like _write_capture but records the captured response/baseline/details so
	tests can assert the advanced scanners thread them through."""
	def _fn(host, payload, ptype, response=None, baseline=None, details=None):
		records.append({
			"host": host, "ptype": ptype, "payload": payload,
			"response": response, "baseline": baseline,
			"details": details or {},
		})
	return _fn


@pytest.fixture
def server_factory():
	srvs = []

	def factory(behavior):
		srv, _t, port = mock_server.start(behavior)
		srvs.append(srv)
		return port

	yield factory

	for s in srvs:
		mock_server.stop(s)


def _common_kwargs(port):
	return dict(
		host="127.0.0.1",
		port=port,
		ssl_flag=False,
		timeout=2.0,
		method="POST",
		endpoint="/",
		vhost="127.0.0.1",
		proxy=None,
		logh=None,
		quiet=True,
		cookies=[],
	)


# ----- ScanCL0 ------------------------------------------------------------

def test_scan_cl0_positive(server_factory):
	port = server_factory("cl0")
	prints, writes = [], []
	scanner = ScanCL0(**_common_kwargs(port))
	# Skip the gadget-discovery step (mock doesn't serve /robots.txt
	# distinctly from /) by injecting a known-good gadget directly.
	scanner._gadget = {"path": "/robots.txt", "look_for": "llow:", "header_only": False}
	# Patch _select_gadget so run() picks our pre-seeded gadget without
	# re-probing.
	scanner._select_gadget = lambda: scanner._gadget

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	assert any(ptype.startswith("CL0") or ptype.startswith("0CL") for _h, ptype, _p in writes)


def test_scan_cl0_negative(server_factory):
	port = server_factory("compliant")
	prints, writes = [], []
	scanner = ScanCL0(**_common_kwargs(port))
	scanner._gadget = {"path": "/robots.txt", "look_for": "llow:", "header_only": False}
	scanner._select_gadget = lambda: scanner._gadget

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is False
	assert writes == []


# ----- ScanHeaderRemoval --------------------------------------------------

def test_scan_header_removal_positive(server_factory):
	port = server_factory("header_removal")
	prints, writes = [], []
	scanner = ScanHeaderRemoval(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	assert any(ptype == "HDRREMOVAL" for _h, ptype, _p in writes)


def test_scan_header_removal_negative(server_factory):
	port = server_factory("compliant")
	prints, writes = [], []
	scanner = ScanHeaderRemoval(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is False
	assert writes == []


# ----- ScanParserDiscrepancy ----------------------------------------------

def test_scan_parser_disc_positive(server_factory):
	port = server_factory("parser_disc_space")
	prints, writes = [], []
	scanner = ScanParserDiscrepancy(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	# The "space" hide technique combined with the Host-invalid canary
	# should be one of the recorded payloads.
	assert any("PARSERDISC_space" in ptype for _h, ptype, _p in writes)


def test_scan_parser_disc_negative(server_factory):
	port = server_factory("compliant")
	prints, writes = [], []
	scanner = ScanParserDiscrepancy(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is False
	assert writes == []


# ----- ScanHopByHop -------------------------------------------------------

def test_scan_hopbyhop_positive(server_factory):
	port = server_factory("hopbyhop_strip")
	prints, writes = [], []
	kwargs = _common_kwargs(port)
	# Send a valid auth header in the baseline so the negative-strip case
	# diverges from the attack case.
	scanner = ScanHopByHop(**kwargs)
	# Inject auth via cookies path -- ScanHopByHop only reads cookies, but
	# our mock keys off the Authorization header. We monkey-patch _request
	# to include the auth header for both legs.
	orig = scanner._request
	def _wrapped(extra):
		return orig(["Authorization: Bearer good"] + extra)
	scanner._request = _wrapped

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	assert any(ptype.startswith("HOPBYHOP_") for _h, ptype, _p in writes)


def test_scan_hopbyhop_negative(server_factory):
	port = server_factory("compliant")
	prints, writes = [], []
	scanner = ScanHopByHop(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is False
	assert writes == []


# ----- Fingerprint-only detection paths ----------------------------------

def test_scan_hopbyhop_fp_only_detection(server_factory):
	# Server returns 200 either way -- old status-only oracle missed
	# this. New code must catch the Set-Cookie / body-length flip via
	# the fingerprint corroborator.
	port = server_factory("hopbyhop_fp_only")
	prints, writes = [], []
	scanner = ScanHopByHop(**_common_kwargs(port))
	# Inject Authorization into baseline so subsequent strip is observable.
	orig = scanner._request
	def _wrapped(extra):
		return orig(["Authorization: Bearer good"] + extra)
	scanner._request = _wrapped

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	# Subtle-strip path emits the HOPBYHOP_FP_* payload tag.
	assert any(ptype.startswith("HOPBYHOP_FP_") for _h, ptype, _p in writes), \
		"expected HOPBYHOP_FP_* payload, got: %r" % [t for _h, t, _p in writes]


def test_scan_header_removal_fp_only_detection(server_factory):
	# Server returns 200 + canary in both legs; old code's
	# status-and-canary oracle would have flagged nothing. New code's
	# fp-only path detects the extra X-Edge header + body-length flip.
	port = server_factory("header_removal_fp")
	prints, writes = [], []
	scanner = ScanHeaderRemoval(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture(writes))
	assert found is True
	assert any(ptype == "HDRREMOVAL_FP" for _h, ptype, _p in writes), \
		"expected HDRREMOVAL_FP payload, got: %r" % [t for _h, t, _p in writes]


# ----- Response capture (sidecars) ---------------------------------------

def test_parser_disc_threads_response_and_baseline(server_factory):
	# The ParserDiscrepancy finding must now carry the attack response (400)
	# AND the baseline response (200) so the GUI can show both.
	port = server_factory("parser_disc_space")
	prints, writes = [], []
	scanner = ScanParserDiscrepancy(**_common_kwargs(port))

	found = scanner.run(_print_capture(prints), _write_capture_detailed(writes))
	assert found is True
	rec = next(w for w in writes if "PARSERDISC" in w["ptype"])
	assert rec["response"], "attack response should be captured"
	assert rec["baseline"], "baseline response should be captured"
	assert rec["details"].get("scan") == "parser-discrepancy"
	assert rec["details"].get("attack_status")
	assert rec["details"].get("baseline_status")


def test_hopbyhop_threads_response_and_baseline(server_factory):
	port = server_factory("hopbyhop_strip")
	prints, writes = [], []
	scanner = ScanHopByHop(**_common_kwargs(port))
	# Seed an Authorization header so the strip is observable, mirroring the
	# fp-only detection test's pattern.
	orig = scanner._request
	scanner._request = lambda extra: orig(["Authorization: Bearer good"] + extra)

	found = scanner.run(_print_capture(prints), _write_capture_detailed(writes))
	assert found is True
	rec = next(w for w in writes if "HOPBYHOP" in w["ptype"])
	assert rec["response"] is not None
	assert rec["baseline"] is not None
	assert rec["details"].get("scan") == "hop-by-hop"


# ----- Custom-header injection -------------------------------------------

def test_inject_extra_headers_appends_and_dedups():
	# A request whose hardcoded block already has a User-Agent; the custom
	# User-Agent must replace it (no duplicate) while Authorization is added.
	raw = (
		"POST /x HTTP/1.1\r\n"
		"Host: h\r\n"
		"User-Agent: scanner-default\r\n"
		"Content-Length: 3\r\n"
		"\r\n"
		"abc"
	)
	out = _inject_extra_headers(raw, [
		"Authorization: Bearer tok",
		"User-Agent: my-agent",
	])
	# Custom values present.
	assert "Authorization: Bearer tok\r\n" in out
	assert "User-Agent: my-agent\r\n" in out
	# Hardcoded default removed -> exactly one User-Agent line.
	assert out.count("User-Agent:") == 1
	assert "scanner-default" not in out
	# Body and framing preserved untouched.
	assert out.endswith("\r\n\r\nabc")
	assert "Content-Length: 3\r\n" in out


def test_inject_extra_headers_noop_when_empty():
	raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
	assert _inject_extra_headers(raw, []) == raw
	assert _inject_extra_headers(raw, None) == raw


def test_build_raw_request_carries_extra_headers():
	req = _build_raw_request("GET", "/", "h",
		extra_headers=["Authorization: Bearer tok", "X-Dtc: v=1"])
	assert "Authorization: Bearer tok\r\n" in req
	assert "X-Dtc: v=1\r\n" in req


def test_scan_cl0_attack_carries_authorization():
	# The CL.0 attack request must carry the pasted Authorization header
	# exactly once, positioned before the framing Content-Length line.
	scanner = ScanCL0(**_common_kwargs(0),
		extra_headers=["Authorization: Bearer tok"])
	gadget = {"path": "/robots.txt", "look_for": "llow:", "header_only": False}
	req = scanner._build_cl0_attack("GET", gadget, cookie_hdr="")
	assert req.count("Authorization: Bearer tok") == 1
	# Must live in the header block, not leak into the smuggled body prefix.
	head = req.split("\r\n\r\n", 1)[0]
	assert "Authorization: Bearer tok" in head
