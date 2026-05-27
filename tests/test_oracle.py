"""Tests for lib.Oracle.GadgetOracle.

Covers:
- candidate viability probing picks a usable gadget
- auto-derived look_for distinguishes gadget from baseline
- canary injection appears in smuggle_path when supported
- caching: select() probes once and returns cached result thereafter
- graceful fallback when no candidate is viable (server down)
- integration: scanners accept oracle= and still detect a positive case
"""

import socket
import threading
import time

import pytest

import tests.mock_server as mock_server
from lib.Oracle import GadgetOracle, Gadget
from lib.Scans import ScanCL0, ScanHopByHop


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


def _build_oracle(port, baseline_endpoint="/"):
	return GadgetOracle(
		host="127.0.0.1",
		port=port,
		ssl_flag=False,
		timeout=2.0,
		vhost="127.0.0.1",
		proxy=None,
		baseline_method="GET",
		baseline_endpoint=baseline_endpoint,
		quiet=True,
	)


def test_oracle_selects_a_gadget_on_compliant_server(server_factory):
	port = server_factory("compliant")
	oracle = _build_oracle(port)

	gadget = oracle.select()

	assert gadget is not None
	assert isinstance(gadget, Gadget)
	assert gadget.smuggle_path
	assert gadget.look_for
	# Either status divergence ("HTTP/1.1 ###"), a distinctive header
	# (ends in ':'), a body n-gram, or the canary itself.
	assert (
		gadget.look_for.startswith("HTTP/1.1 ")
		or gadget.look_for.endswith(":")
		or gadget.look_for == gadget.canary
		or len(gadget.look_for) >= 4
	)


def test_oracle_select_is_cached(server_factory):
	port = server_factory("compliant")
	oracle = _build_oracle(port)

	first = oracle.select()
	second = oracle.select()

	# Same object reference (cached, not re-probed).
	assert first is second
	assert oracle.chosen is first


def test_oracle_returns_none_when_target_unreachable():
	# Bind a socket just to claim a port then immediately release it so
	# the oracle gets ECONNREFUSED on every probe.
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(("127.0.0.1", 0))
	port = s.getsockname()[1]
	s.close()

	oracle = _build_oracle(port)
	gadget = oracle.select()

	assert gadget is None
	assert oracle.chosen is None


def test_oracle_canary_appears_in_smuggle_path_when_supported(server_factory):
	port = server_factory("compliant")
	oracle = _build_oracle(port)

	gadget = oracle.select()
	assert gadget is not None

	# Every candidate except OPTIONS * supports a canary query string;
	# if our gadget supports queries the canary must be embedded.
	if gadget.name not in ("options-asterisk",):
		# random-404 and query-reflect embed it directly in the path;
		# others append ?smug=<canary>.
		assert (gadget.canary in gadget.smuggle_path)


def test_gadget_matches_handles_header_only_correctly():
	# Direct unit test of Gadget.matches without going through the wire.
	g = Gadget(
		name="t",
		method="GET",
		smuggle_path="/",
		look_for="Allow:",
		look_for_alt=[],
		header_only=True,
		canary="abc",
		rationale="test",
	)
	resp_with_header = "HTTP/1.1 200 OK\r\nAllow: GET, POST\r\n\r\nhello"
	resp_with_in_body = "HTTP/1.1 200 OK\r\nServer: x\r\n\r\nAllow: from body"

	assert g.matches(resp_with_header) is True
	# header_only=True must NOT match when the token only lives in body.
	assert g.matches(resp_with_in_body) is False


def test_gadget_matches_accepts_405_alternate():
	# The oracle always seeds "HTTP/1.1 405" into look_for_alt so the
	# legacy method-not-allowed tell continues to fire.
	g = Gadget(
		name="t",
		method="GET",
		smuggle_path="/",
		look_for="something-else",
		look_for_alt=["HTTP/1.1 405"],
		header_only=False,
		canary="abc",
		rationale="test",
	)
	resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
	assert g.matches(resp) is True


def test_oracle_smuggled_request_bytes_builds_terminated_request(server_factory):
	port = server_factory("compliant")
	oracle = _build_oracle(port)

	req = oracle.smuggled_request_bytes()
	assert req is not None
	assert req.endswith("\r\n\r\n")
	assert "Host: 127.0.0.1\r\n" in req
	assert "X-Smug: 1\r\n" in req


def test_scan_cl0_accepts_oracle_kwarg(server_factory):
	# Backwards-compatibility check: oracle=None still works (covered by
	# existing tests) AND passing a real oracle does not break detection.
	port = server_factory("cl0")
	oracle = _build_oracle(port)
	scanner = ScanCL0(
		host="127.0.0.1", port=port, ssl_flag=False, timeout=2.0,
		method="POST", endpoint="/", vhost="127.0.0.1", proxy=None,
		logh=None, quiet=True, cookies=[], oracle=oracle,
	)

	prints, writes = [], []
	found = scanner.run(
		lambda n, m: prints.append((n, m)),
		lambda h, p, t: writes.append((h, t, p)),
	)
	assert found is True
	assert any(ptype.startswith("CL0") or ptype.startswith("0CL") for _h, ptype, _p in writes)


def test_scan_hopbyhop_accepts_oracle_kwarg(server_factory):
	# ScanHopByHop doesn't use a gadget but must accept oracle=
	# for uniform construction in run_advanced_scans.
	port = server_factory("compliant")
	oracle = _build_oracle(port)
	scanner = ScanHopByHop(
		host="127.0.0.1", port=port, ssl_flag=False, timeout=2.0,
		method="GET", endpoint="/", vhost="127.0.0.1", proxy=None,
		logh=None, quiet=True, cookies=[], oracle=oracle,
	)
	prints, writes = [], []
	found = scanner.run(
		lambda n, m: prints.append((n, m)),
		lambda h, p, t: writes.append((h, t, p)),
	)
	# Compliant server should produce no finding -- but the call must
	# not raise on the oracle= kwarg.
	assert found is False
