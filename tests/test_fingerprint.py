"""Tests for lib.Fingerprint.

Covers Fingerprint.from_response parsing of CL / chunked / connection-
close framing, the per-axis diff(), and baseline_fingerprint consensus
behavior including the noisy-axis detection that makes diff() useful
against real targets that flip Date / X-Request-Id between calls.
"""

import pytest

import tests.mock_server as mock_server
from lib.Fingerprint import Fingerprint, baseline_fingerprint


CL_RESPONSE = (
	b"HTTP/1.1 200 OK\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: 11\r\n"
	b"Connection: close\r\n"
	b"\r\n"
	b"hello world"
)

CHUNKED_RESPONSE = (
	b"HTTP/1.1 200 OK\r\n"
	b"Content-Type: text/plain\r\n"
	b"Transfer-Encoding: chunked\r\n"
	b"\r\n"
	b"5\r\nhello\r\n0\r\n\r\n"
)

NO_FRAMING_RESPONSE = (
	b"HTTP/1.0 200 OK\r\n"
	b"Connection: close\r\n"
	b"\r\n"
	b"trailing-bytes"
)

ALT_STATUS_RESPONSE = (
	b"HTTP/1.1 404 Not Found\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: 9\r\n"
	b"\r\n"
	b"not found"
)


def test_from_response_parses_content_length():
	fp = Fingerprint.from_response(CL_RESPONSE)
	assert fp.status == "200"
	assert fp.framing == "cl:11"
	assert "content-type" in fp.header_set
	assert "content-length" in fp.header_set
	assert "connection" in fp.header_set
	assert fp.body_len == 11


def test_from_response_parses_chunked():
	fp = Fingerprint.from_response(CHUNKED_RESPONSE)
	assert fp.status == "200"
	assert fp.framing == "chunked"
	assert "transfer-encoding" in fp.header_set
	# We don't re-walk chunks; body_len is the raw bytes after \r\n\r\n.
	assert fp.body_len == len(b"5\r\nhello\r\n0\r\n\r\n")


def test_from_response_parses_no_framing():
	fp = Fingerprint.from_response(NO_FRAMING_RESPONSE)
	assert fp.status == "200"
	assert fp.framing == "none"
	assert fp.body_len == len(b"trailing-bytes")


def test_from_response_handles_empty_input():
	fp = Fingerprint.from_response(None)
	assert fp.status == ""
	assert fp.framing == "none"
	assert fp.header_set == frozenset()
	assert fp.body_len == 0


def test_from_response_handles_truncated_headers():
	# No \r\n\r\n terminator -- treat as headers-only, empty body.
	fp = Fingerprint.from_response(b"HTTP/1.1 200 OK\r\nServer: x")
	assert fp.status == "200"
	assert fp.body_len == 0


def test_diff_empty_when_identical():
	a = Fingerprint.from_response(CL_RESPONSE)
	b = Fingerprint.from_response(CL_RESPONSE)
	assert a.diff(b) == set()
	assert a.is_similar_to(b) is True


def test_diff_detects_status_axis():
	a = Fingerprint.from_response(CL_RESPONSE)
	b = Fingerprint.from_response(ALT_STATUS_RESPONSE)
	diff = a.diff(b)
	assert "status" in diff
	# 200 OK body "hello world" -> 404 body "not found" differs in length and content too.
	assert "body_len" in diff
	assert "body_head" in diff


def test_diff_detects_framing_axis():
	a = Fingerprint.from_response(CL_RESPONSE)
	b = Fingerprint.from_response(CHUNKED_RESPONSE)
	assert "framing" in a.diff(b)


def test_diff_detects_header_set_axis():
	base = (
		b"HTTP/1.1 200 OK\r\n"
		b"Content-Type: text/plain\r\n"
		b"Content-Length: 0\r\n"
		b"\r\n"
	)
	with_cookie = (
		b"HTTP/1.1 200 OK\r\n"
		b"Content-Type: text/plain\r\n"
		b"Set-Cookie: a=1\r\n"
		b"Content-Length: 0\r\n"
		b"\r\n"
	)
	a = Fingerprint.from_response(base)
	b = Fingerprint.from_response(with_cookie)
	diff = a.diff(b)
	# Status / framing / body axes match -- only header_set should flip.
	assert diff == {"header_set"}


def test_diff_body_tail_separate_from_body_head():
	# Two 200-byte responses: first 64 bytes are "A"*64 (identical), last
	# 64 bytes are "B"*64 vs "C"*64. body_head should match, body_tail
	# should diverge -- proves the two axes are independent.
	a = (
		b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n"
		+ b"A" * 100 + b"B" * 100
	)
	b = (
		b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n"
		+ b"A" * 100 + b"C" * 100
	)
	fa = Fingerprint.from_response(a)
	fb = Fingerprint.from_response(b)
	diff = fa.diff(fb)
	assert "body_head" not in diff
	assert "body_tail" in diff
	assert "body_len" not in diff


def test_is_similar_to_with_tolerate_set():
	a = Fingerprint.from_response(CL_RESPONSE)
	b = Fingerprint.from_response(ALT_STATUS_RESPONSE)
	# Full diff includes status + body axes.
	assert not a.is_similar_to(b)
	# Tolerating every axis that actually differs flips to similar.
	assert a.is_similar_to(b, tolerate=a.diff(b))


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


def test_baseline_fingerprint_consensus_on_stable_server(server_factory):
	port = server_factory("compliant")
	req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	fp, noisy = baseline_fingerprint("127.0.0.1", port, False, 2.0, req, n=3)
	# Mock server emits identical responses -- no noisy axes.
	assert fp.status == "200"
	assert noisy == set()


def test_baseline_fingerprint_marks_all_noisy_when_unreachable():
	# Port 1 is reserved -- no server. baseline_fingerprint must return an
	# empty fingerprint with every axis marked noisy.
	fp, noisy = baseline_fingerprint("127.0.0.1", 1, False, 0.5,
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", n=2)
	assert fp.status == ""
	assert "status" in noisy
	assert "header_set" in noisy
