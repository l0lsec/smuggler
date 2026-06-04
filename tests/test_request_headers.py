"""Tests for custom-header extraction in parse_request_file.

A pasted request carries headers the scanner must preserve into its attack
requests (Authorization, X-Dtc, ...) and framing headers it must own itself
(Host, Content-Length, Transfer-Encoding, ...). The parser is the single
chokepoint that decides which is which; these tests pin that contract.
"""

from lib.RequestFile import parse_request_file


def _write(tmp_path, text):
	p = tmp_path / "req.txt"
	p.write_text(text)
	return str(p)


def test_extra_headers_preserved_and_framing_excluded(tmp_path):
	raw = (
		"GET /cip/base/ HTTP/1.1\r\n"
		"Host: api.example.com\r\n"
		"X-Dtc: sn=\"v_4\", pc=\"10$abc-0e0\", v=\"123\"\r\n"
		"Authorization: Bearer eyJ0.eyJh.DqBm\r\n"
		"Cookie: a=1; b=2\r\n"
		"Content-Length: 0\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Connection: keep-alive\r\n"
		"Accept: application/json\r\n"
		"\r\n"
	)
	parsed = parse_request_file(_write(tmp_path, raw))

	# Non-framing headers survive verbatim (commas / quotes / $ intact).
	assert "Authorization: Bearer eyJ0.eyJh.DqBm" in parsed["extra_headers"]
	assert "X-Dtc: sn=\"v_4\", pc=\"10$abc-0e0\", v=\"123\"" in parsed["extra_headers"]
	assert "Accept: application/json" in parsed["extra_headers"]

	# Framing / separately-handled headers are NOT in extra_headers.
	joined = "\n".join(parsed["extra_headers"]).lower()
	for framing in ("host:", "content-length:", "transfer-encoding:",
			"connection:", "cookie:"):
		assert framing not in joined

	# Host and Cookie still routed to their dedicated fields.
	assert parsed["host"] == "api.example.com"
	assert parsed["cookies"] == ["a=1;", "b=2;"]


def test_no_extra_headers_when_only_framing(tmp_path):
	raw = (
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	)
	parsed = parse_request_file(_write(tmp_path, raw))
	assert parsed["extra_headers"] == []


def test_header_name_match_is_case_insensitive(tmp_path):
	raw = (
		"GET / HTTP/1.1\r\n"
		"HOST: example.com\r\n"
		"transfer-encoding: chunked\r\n"
		"authorization: Bearer xyz\r\n"
		"\r\n"
	)
	parsed = parse_request_file(_write(tmp_path, raw))
	assert parsed["host"] == "example.com"
	assert parsed["extra_headers"] == ["authorization: Bearer xyz"]
