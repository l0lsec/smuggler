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
)


def _print_capture(records):
	def _fn(name, msg):
		records.append((name, msg))
	return _fn


def _write_capture(records):
	def _fn(host, payload, ptype):
		records.append((host, ptype, payload))
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
