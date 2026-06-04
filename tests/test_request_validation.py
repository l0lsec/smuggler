"""Tests for the scan-mode request file validator.

The validator emits notice + warning lines via print_info when a request
file passed to `-r/--request` looks like a smuggling POC that scan mode
would silently ignore. We capture stdout to verify the right warnings
fire (or don't fire) for each example file.
"""

import io
from contextlib import redirect_stdout

import smuggler


def _validate_and_capture(path):
	parsed = smuggler.parse_request_file(path)
	buf = io.StringIO()
	with redirect_stdout(buf):
		smuggler.warn_if_request_unsafe_for_scan_mode(parsed, path)
	return buf.getvalue()


def _write(tmp_path, text, name="req.txt"):
	# Fixtures are synthesized inline with synthetic hosts/tokens. We
	# deliberately do NOT ship real captured requests as files: prior sample
	# fixtures embedded real engagement hosts and a live Bearer JWT, which must
	# never land in the repo.
	p = tmp_path / name
	p.write_text(text)
	return str(p)


def test_clean_request_emits_no_warnings(tmp_path):
	# A vanilla GET with no body and no extras must not trip any detector.
	req = (
		"GET /app HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Accept: application/json\r\n"
		"\r\n"
	)
	out = _validate_and_capture(_write(tmp_path, req))
	assert "Notice:" not in out
	assert "body bytes" not in out
	assert "embedded" not in out


def test_poc_smuggle_request_is_warned(tmp_path):
	# A deliberate smuggling POC: chunked body whose terminator is followed by
	# a smuggled request line. Both the body-bytes and embedded-request-line
	# detectors should fire.
	req = (
		"POST /submit HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: 6\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"0\r\n"
		"\r\n"
		"GET /admin HTTP/1.1\r\n"
		"X: "
	)
	out = _validate_and_capture(_write(tmp_path, req))
	assert "Notice:" in out
	assert "embedded request line" in out


def test_body_request_line_pocs_are_warned(tmp_path):
	# POC-shaped files whose body is itself a second request line. The
	# validator should flag them rather than silently use them as templates.
	for i, smuggled in enumerate(("GET /other HTTP/1.1", "POST /admin HTTP/1.1")):
		req = (
			"GET /app HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n"
			+ smuggled + "\r\n"
			"X: "
		)
		out = _validate_and_capture(_write(tmp_path, req, name="poc%d.txt" % i))
		assert "Notice:" in out, "expected warning for %r" % smuggled
		assert "embedded request line" in out


def test_poc_in_header_value_is_warned(tmp_path):
	# A request line embedded inside an Authorization header value (the
	# Bearer-token-style POC). Token is synthetic.
	req = (
		"GET /404 HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Authorization: Bearer GET /x?a=1 HTTP/1.1\r\n"
		"Accept: application/json\r\n"
		"\r\n"
	)
	out = _validate_and_capture(_write(tmp_path, req))
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
