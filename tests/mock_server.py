"""Pluggable mock HTTP/1.1 server for HRS detection tests.

The mock listens on an ephemeral port and serves a deterministic response
for any valid request, while deliberately mishandling specific edge cases
to simulate front-end / back-end parser disagreement. Each test selects a
`behavior` string that toggles one (and only one) class of vulnerability.

Behaviors:
  compliant            - well-behaved server, no findings expected
  cl0                  - ignores body on POST + emits gadget response for
                         pipelined GET /robots.txt (CL.0 oracle)
  expect_cl0           - same as cl0 but only when Expect: 100-continue is set
  header_removal       - drops body when Keep-Alive header is present (canary
                         absent -> response status differs from baseline)
  parser_disc_space    - treats " Header: x" (leading space) as a separate
                         visible header that affects routing
  hopbyhop_strip       - strips Authorization when Connection lists it
"""

import socketserver
import socket
import threading
import time


ROBOTS_RESPONSE = (
	b"HTTP/1.1 200 OK\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: 30\r\n"
	b"Connection: keep-alive\r\n"
	b"\r\n"
	b"User-agent: *\r\nDisallow: /\r\n"
)

DEFAULT_BODY = b"hello\n"
DEFAULT_RESPONSE = (
	b"HTTP/1.1 200 OK\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: %d\r\n"
	b"Connection: keep-alive\r\n"
	b"\r\n" % len(DEFAULT_BODY)
) + DEFAULT_BODY

UNAUTH_BODY = b"forbidden\n"
UNAUTH_RESPONSE = (
	b"HTTP/1.1 401 Unauthorized\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: %d\r\n"
	b"Connection: keep-alive\r\n"
	b"\r\n" % len(UNAUTH_BODY)
) + UNAUTH_BODY

ERROR_BODY = b"bad request\n"
ERROR_RESPONSE = (
	b"HTTP/1.1 400 Bad Request\r\n"
	b"Content-Type: text/plain\r\n"
	b"Content-Length: %d\r\n"
	b"Connection: close\r\n"
	b"\r\n" % len(ERROR_BODY)
) + ERROR_BODY


def _split_request_line(buf):
	"""Return (method, path, version, header_end_offset) or None."""
	hdr_end = buf.find(b"\r\n\r\n")
	if hdr_end < 0:
		return None
	first_line = buf.split(b"\r\n", 1)[0]
	parts = first_line.split(b" ", 2)
	if len(parts) < 3:
		return None
	return parts[0], parts[1], parts[2], hdr_end


def _parse_headers(buf):
	headers = {}
	# Use the section before \r\n\r\n
	hdr_blob = buf.split(b"\r\n\r\n", 1)[0]
	lines = hdr_blob.split(b"\r\n")[1:]
	for line in lines:
		if b":" not in line:
			continue
		k, _, v = line.partition(b":")
		headers.setdefault(k.strip().lower(), []).append(v.strip())
	return headers


class _Handler(socketserver.BaseRequestHandler):
	def handle(self):
		buf = b""
		conn = self.request
		conn.settimeout(2.0)
		try:
			while True:
				# Read headers.
				while b"\r\n\r\n" not in buf:
					try:
						chunk = conn.recv(4096)
					except socket.timeout:
						return
					if not chunk:
						return
					buf += chunk

				parsed = _split_request_line(buf)
				if not parsed:
					conn.sendall(ERROR_RESPONSE)
					return
				method, path, version, hdr_end = parsed
				headers = _parse_headers(buf)
				body_start = hdr_end + 4

				# Read body per Content-Length if framing is well-formed.
				cl_values = headers.get(b"content-length", [])
				try:
					cl = int(cl_values[0]) if cl_values else 0
				except ValueError:
					cl = 0

				while len(buf) - body_start < cl:
					try:
						chunk = conn.recv(4096)
					except socket.timeout:
						break
					if not chunk:
						break
					buf += chunk

				body = buf[body_start:body_start + cl]
				next_buf = buf[body_start + cl:]

				# Behavior dispatch.
				behavior = self.server.behavior
				gadget_path = b"/robots.txt"

				if behavior == "compliant":
					# A truly compliant server visibly rejects malformed
					# Host / CL headers so that parser-discrepancy probes
					# see status changes (-> VISIBLE outcome -> no finding).
					raw_hdr = buf[:hdr_end]
					host_vals = headers.get(b"host", [])
					if not host_vals:
						conn.sendall(ERROR_RESPONSE); return
					# Reject malformed Host values (slashes, spaces) but
					# tolerate duplicate Host headers when all values match
					# -- RFC 7230 leaves this server's choice.
					if any(b"/" in v or b" " in v for v in host_vals):
						conn.sendall(ERROR_RESPONSE); return
					if len(set(host_vals)) > 1:
						conn.sendall(ERROR_RESPONSE); return
					# Same vigilance for Content-Length: duplicates and bad
					# values are both rejected.
					if len(cl_values) > 1:
						conn.sendall(ERROR_RESPONSE); return
					if cl_values:
						try:
							int(cl_values[0])
						except ValueError:
							conn.sendall(ERROR_RESPONSE); return
					# Same for Transfer-Encoding: any joint-value canary or
					# duplicate gets a hard 400.
					te_vals = headers.get(b"transfer-encoding", [])
					if len(te_vals) > 1:
						conn.sendall(ERROR_RESPONSE); return
					if te_vals and b"," in te_vals[0]:
						conn.sendall(ERROR_RESPONSE); return
					# Reject obvious header-smuggling tells (line folding,
					# Connection-listed hop-by-hop poisoning).
					if b"\r\n " in raw_hdr or b"\r\n\t" in raw_hdr or b"\r " in raw_hdr or b"\n " in raw_hdr:
						conn.sendall(ERROR_RESPONSE); return
					# Note: we intentionally do NOT reject `Connection: <hdr>`
					# requests -- a compliant server is allowed to honor or
					# ignore hop-by-hop strip requests; either way it should
					# still respond 200 when the actual request is valid.
					# Reject pathologically-large header names (compliant
					# servers usually 431).
					for line in raw_hdr.split(b"\r\n")[1:]:
						name = line.split(b":", 1)[0]
						if len(name) > 200:
							resp = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n"
							conn.sendall(resp); return
					if path.startswith(gadget_path):
						conn.sendall(ROBOTS_RESPONSE)
					else:
						conn.sendall(DEFAULT_RESPONSE)

				elif behavior == "cl0":
					# Server ignores Content-Length on POST entirely. Body
					# bytes are read by the *backend* as a follow-up
					# request -- so we treat anything in `body` that begins
					# with a method token as a second pipelined request.
					if path.startswith(gadget_path):
						conn.sendall(ROBOTS_RESPONSE)
					else:
						conn.sendall(DEFAULT_RESPONSE)
					# If body contained a smuggled request, splice it back
					# into the read buffer so the next loop iteration sees
					# it.
					if body[:4] in (b"GET ", b"POST", b"HEAD") or body[:3] == b"GET":
						next_buf = body + next_buf

				elif behavior == "expect_cl0":
					expect = headers.get(b"expect", [b""])[0]
					if expect.lower() == b"100-continue":
						if path.startswith(gadget_path):
							conn.sendall(ROBOTS_RESPONSE)
						else:
							conn.sendall(DEFAULT_RESPONSE)
						if body[:3] == b"GET" or body[:4] == b"POST":
							next_buf = body + next_buf
					else:
						conn.sendall(DEFAULT_RESPONSE)

				elif behavior == "header_removal":
					# When Keep-Alive header (not just Connection: keep-alive)
					# is present, server treats body as discarded -> canary
					# never reflected back AND status drops to 418.
					if b"keep-alive" in headers:
						body_resp = b"i discard your body\n"
						resp = (
							b"HTTP/1.1 418 I'm a Teapot\r\n"
							b"Content-Type: text/plain\r\n"
							b"Content-Length: %d\r\n"
							b"Connection: close\r\n"
							b"\r\n" % len(body_resp)
						) + body_resp
						conn.sendall(resp)
						return
					# Otherwise echo back so harmless probe sees canary.
					resp_body = body or b"empty\n"
					resp = (
						b"HTTP/1.1 200 OK\r\n"
						b"Content-Type: text/plain\r\n"
						b"Content-Length: %d\r\n"
						b"Connection: keep-alive\r\n"
						b"\r\n" % len(resp_body)
					) + resp_body
					conn.sendall(resp)

				elif behavior == "parser_disc_space":
					# Treat " Host: foo/bar" (leading space) as a real
					# header that triggers a 400.
					raw_header_blob = buf[:hdr_end]
					if b"\r\n " in raw_header_blob and b"foo/bar" in raw_header_blob:
						conn.sendall(ERROR_RESPONSE)
						return
					conn.sendall(DEFAULT_RESPONSE)

				elif behavior == "hopbyhop_strip":
					conn_hdr = headers.get(b"connection", [b""])[0].lower()
					auth = headers.get(b"authorization", [b""])[0]
					# If client said "Connection: Authorization", strip auth
					# before checking it.
					if b"authorization" in conn_hdr:
						auth = b""
					if auth == b"Bearer good":
						conn.sendall(DEFAULT_RESPONSE)
					else:
						conn.sendall(UNAUTH_RESPONSE)

				else:
					conn.sendall(ERROR_RESPONSE)
					return

				# Pipeline support: loop on any leftover bytes.
				buf = next_buf
				if not buf:
					# Wait briefly for the next request, exit if none.
					try:
						conn.settimeout(0.2)
						chunk = conn.recv(4096)
						conn.settimeout(2.0)
					except socket.timeout:
						return
					if not chunk:
						return
					buf = chunk
		except Exception:
			return
		finally:
			try:
				conn.close()
			except Exception:
				pass


class _ThreadedServer(socketserver.ThreadingTCPServer):
	allow_reuse_address = True
	daemon_threads = True

	def __init__(self, addr, handler_cls, behavior):
		super().__init__(addr, handler_cls)
		self.behavior = behavior


def start(behavior, host="127.0.0.1", port=0):
	"""Start a mock server with `behavior` on an ephemeral port.

	Returns (server, thread, port). Caller is responsible for calling
	server.shutdown() / server.server_close() to tear down.
	"""
	srv = _ThreadedServer((host, port), _Handler, behavior)
	bound_port = srv.server_address[1]
	t = threading.Thread(target=srv.serve_forever, daemon=True)
	t.start()
	# Give the OS a moment so the first connection attempt doesn't race.
	time.sleep(0.05)
	return srv, t, bound_port


def stop(srv):
	try:
		srv.shutdown()
	except Exception:
		pass
	try:
		srv.server_close()
	except Exception:
		pass
