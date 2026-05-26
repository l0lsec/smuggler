"""Regression tests for ReplayManager request rewriting.

Bug history: build_request_with_id appended `?request_id=...&timestamp=...`
to the request line but never recomputed Content-Length, leaving bodies
ambiguous and causing strict backends to either 400 or desync.
"""

import argparse
import smuggler


class _DummyArgs(argparse.Namespace):
	pass


def _make_replay_manager(raw):
	# We never start the loop -- only build_request_with_id is exercised.
	custom = {
		'method': 'POST',
		'endpoint': '/api',
		'host': 'example.com',
		'cookies': [],
		'headers': '',
		'body': '',
		'raw': raw,
	}
	return smuggler.ReplayManager(
		custom_request=custom,
		host='example.com',
		port=443,
		ssl_flag=True,
		timeout=2.0,
	)


def test_replay_appends_id_and_timestamp_to_query():
	raw = (
		"POST /api HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"abcde"
	)
	mgr = _make_replay_manager(raw)
	out = mgr.build_request_with_id("REQ-X-001")
	first_line = out.split("\r\n", 1)[0]
	assert "request_id=REQ-X-001" in first_line
	assert "timestamp=" in first_line
	# Endpoint should still be /api (with appended query).
	assert first_line.startswith("POST /api?")


def test_replay_recomputes_content_length_on_body_change():
	# The CL we feed in is intentionally WRONG (10 vs body of 5). The
	# rebuild must replace it with the true length so a strict server
	# doesn't get confused.
	raw = (
		"POST /api HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 10\r\n"
		"\r\n"
		"abcde"
	)
	mgr = _make_replay_manager(raw)
	out = mgr.build_request_with_id("R-1")
	lines = out.split("\r\n")
	cl_lines = [l for l in lines if l.lower().startswith("content-length:")]
	assert len(cl_lines) == 1
	_, _, val = cl_lines[0].partition(":")
	assert int(val.strip()) == 5  # actual body length


def test_replay_appends_question_mark_when_no_query():
	raw = (
		"POST /foo HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	)
	mgr = _make_replay_manager(raw)
	out = mgr.build_request_with_id("R-2")
	first = out.split("\r\n", 1)[0]
	assert "/foo?request_id=R-2" in first
	assert " HTTP/1.1" in first


def test_replay_appends_ampersand_when_query_present():
	raw = (
		"POST /foo?a=b HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	)
	mgr = _make_replay_manager(raw)
	out = mgr.build_request_with_id("R-3")
	first = out.split("\r\n", 1)[0]
	assert "/foo?a=b&request_id=R-3" in first


def test_replay_baseline_request_uses_baseline_id_param():
	raw = (
		"GET /v HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n"
	)
	mgr = _make_replay_manager(raw)
	mgr.baseline_request = mgr.custom_request
	out = mgr.build_baseline_request_with_id("BL-1")
	assert "baseline_id=BL-1" in out.split("\r\n", 1)[0]
