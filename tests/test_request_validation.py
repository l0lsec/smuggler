"""Tests for the scan-mode request file validator.

The validator emits notice + warning lines via print_info when a request
file passed to `-r/--request` looks like a smuggling POC that scan mode
would silently ignore. We capture stdout to verify the right warnings
fire (or don't fire) for each example file.
"""

import io
import os
from contextlib import redirect_stdout

import smuggler


HERE = os.path.dirname(__file__)


def _validate_and_capture(path):
	parsed = smuggler.parse_request_file(path)
	buf = io.StringIO()
	with redirect_stdout(buf):
		smuggler.warn_if_request_unsafe_for_scan_mode(parsed, path)
	return buf.getvalue()


def test_clean_request_emits_no_warnings():
	# req_clean.txt is a vanilla GET with no body and no extras.
	out = _validate_and_capture(os.path.join(HERE, "req_clean.txt"))
	assert "Notice:" not in out
	assert "body bytes" not in out
	assert "embedded" not in out


def test_poc_smuggle_request_is_warned():
	# req_poc.txt is a deliberate smuggling POC -- both the body-prefix
	# and embedded-request-line detectors should fire.
	out = _validate_and_capture(os.path.join(HERE, "req_poc.txt"))
	assert "Notice:" in out
	assert "embedded request line" in out


def test_existing_legacy_examples_are_warned():
	# The pre-existing req1.txt / req2.txt / req3.txt sample files are
	# *also* POC-shaped (body begins with a smuggled request line). We
	# want the validator to flag them rather than silently use them as
	# templates.
	for name in ("req1.txt", "req2.txt", "req3.txt"):
		out = _validate_and_capture(os.path.join(HERE, name))
		assert "Notice:" in out, "expected warning for %s" % name
		assert "embedded request line" in out


def test_poc_in_header_value_is_warned():
	# baseline_test.txt embeds GET/POST inside an Authorization header value.
	out = _validate_and_capture(os.path.join(HERE, "baseline_test.txt"))
	assert "Notice:" in out


def test_body_bytes_are_warned(tmp_path):
	# Synthesize a request file with a body so we exercise the body branch.
	req = (
		"POST /submit HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"hello"
	)
	p = tmp_path / "with_body.txt"
	p.write_text(req)
	out = _validate_and_capture(str(p))
	assert "body bytes" in out


def test_warning_message_directs_user_to_replay_mode(tmp_path):
	req = (
		"POST /submit HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 3\r\n"
		"\r\n"
		"abc"
	)
	p = tmp_path / "with_body.txt"
	p.write_text(req)
	out = _validate_and_capture(str(p))
	assert "--replay" in out
	assert "--baseline-request" in out
