"""Raw HTTP request-file parsing, shared by the scanner CLI and the
self-contained desync confirmer.

This was previously inlined in ``smuggler.py`` where parse failures called
``exit(1)`` directly. That made it impossible to reuse from a library
context (the confirmer, the tests) without killing the whole process. The
logic is unchanged; the only difference is that failures now raise
``RequestFileError`` and the caller decides what to do (the CLI catches it
and exits, library callers handle it).
"""


class RequestFileError(ValueError):
	"""Raised when a request file is missing or cannot be parsed."""


# Headers the scanner must own itself: framing/hop-by-hop headers that, if
# carried over from the pasted request, would corrupt the CL/TE smuggling
# logic or the per-scan connection handling. Everything NOT in this set (e.g.
# Authorization, X-Dtc, User-Agent, Content-Type, Origin, Referer, Accept,
# Sec-*) is preserved verbatim into the outgoing attack requests. Cookie is
# excluded here because it is threaded separately via ``cookies``.
_FRAMING_HEADERS = {
	'host', 'content-length', 'transfer-encoding', 'connection', 'expect',
	'cookie', 'keep-alive', 'proxy-connection', 'upgrade', 'te',
}


def parse_request_file(filepath):
	"""Parse an HTTP request from a file and return its components.

	Returns a dict with ``method``, ``endpoint``, ``host``, ``cookies``,
	``extra_headers``, ``headers``, ``body``, ``raw``. ``extra_headers`` is a
	list of ``"Name: value"`` strings (no trailing CRLF) for every header that
	is not framing-critical (see ``_FRAMING_HEADERS``) -- these are carried into
	the outgoing attack requests. Raises ``RequestFileError`` on a missing file
	or a malformed request line.
	"""
	try:
		with open(filepath, 'r') as f:
			content = f.read()
	except FileNotFoundError:
		raise RequestFileError("Request file not found: %s" % filepath)
	except OSError as e:
		raise RequestFileError("Could not read request file %s: %s" % (filepath, e))

	# Split headers and body.
	parts = content.split('\r\n\r\n', 1)
	if len(parts) == 1:
		# Try with just \n\n
		parts = content.split('\n\n', 1)

	headers_section = parts[0]
	body = parts[1] if len(parts) > 1 else ""

	# Parse request line.
	lines = headers_section.split('\n')
	request_line = lines[0].strip()
	request_parts = request_line.split(' ')

	if len(request_parts) < 3:
		raise RequestFileError("Invalid request line format: %r" % request_line)

	method = request_parts[0]
	endpoint = request_parts[1]

	# Parse headers: extract Host and Cookie for special handling, and collect
	# every other non-framing header so it survives into the attack requests.
	host = None
	cookies = []
	extra_headers = []
	for line in lines[1:]:
		line_stripped = line.strip()
		if ':' not in line_stripped:
			continue
		name = line_stripped.split(':', 1)[0].strip().lower()
		if name == 'host':
			host = line_stripped.split(':', 1)[1].strip()
		elif name == 'cookie':
			cookie_value = line_stripped.split(':', 1)[1].strip()
			if cookie_value:
				cookie_parts = [c.strip() for c in cookie_value.split(';') if c.strip()]
				for cookie in cookie_parts:
					if cookie and not cookie.endswith(';'):
						cookies.append(cookie + ';')
					elif cookie:
						cookies.append(cookie)
		elif name not in _FRAMING_HEADERS:
			extra_headers.append(line_stripped)

	return {
		'method': method,
		'endpoint': endpoint,
		'host': host,
		'cookies': cookies,
		'extra_headers': extra_headers,
		'headers': headers_section,
		'body': body,
		'raw': content,
	}
