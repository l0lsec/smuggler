"""Regression tests for the recv_multiple response splitter.

Bug history: the old implementation `raw.split("HTTP/")` corrupted boundary
detection whenever a body (or even a header value) contained the literal
substring "HTTP/". The new walker uses real Content-Length / chunked
framing.
"""

import socket
import threading
import time

import pytest

from lib.EasySSL import EasySSL


class _Echo:
	"""Tiny TCP listener that, on accept, writes a fixed byte blob and closes."""

	def __init__(self, blob):
		self.blob = blob
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(("127.0.0.1", 0))
		self.sock.listen(4)
		self.port = self.sock.getsockname()[1]
		self.t = threading.Thread(target=self._serve, daemon=True)
		self.t.start()

	def _serve(self):
		while True:
			try:
				conn, _ = self.sock.accept()
			except OSError:
				return
			try:
				# Drain the request so the client doesn't get RST.
				conn.settimeout(0.3)
				try:
					conn.recv(8192)
				except Exception:
					pass
				conn.sendall(self.blob)
			finally:
				try:
					conn.close()
				except Exception:
					pass

	def close(self):
		try:
			self.sock.close()
		except Exception:
			pass


def _client_recv_multiple(port, count=2):
	web = EasySSL(False)
	web.connect("127.0.0.1", port, 1.0)
	web.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	parts = web.recv_multiple(count, 1.0)
	web.close()
	return parts


def test_recv_multiple_with_http_literal_in_body():
	# Two pipelined responses: first body is HTML that mentions "HTTP/".
	body1 = b"see RFC for HTTP/1.1 framing rules"
	body2 = b"second"
	resp1 = (
		b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body1), body1)
	)
	resp2 = (
		b"HTTP/1.1 404 NF\r\nContent-Length: %d\r\n\r\n%s" % (len(body2), body2)
	)
	srv = _Echo(resp1 + resp2)
	try:
		parts = _client_recv_multiple(srv.port, count=2)
		assert len(parts) == 2
		assert "200 OK" in parts[0]
		assert "404 NF" in parts[1]
		# Crucially: the body of part 1 still contains "HTTP/" -- the old
		# splitter would have produced THREE parts here.
		assert "HTTP/1.1 framing" in parts[0]
	finally:
		srv.close()


def test_recv_multiple_chunked():
	body1 = b"5\r\nhello\r\n0\r\n\r\n"
	body2 = b"5\r\nworld\r\n0\r\n\r\n"
	resp1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body1
	resp2 = b"HTTP/1.1 201 Cr\r\nTransfer-Encoding: chunked\r\n\r\n" + body2
	srv = _Echo(resp1 + resp2)
	try:
		parts = _client_recv_multiple(srv.port, count=2)
		assert len(parts) == 2
		assert "200 OK" in parts[0]
		assert "201 Cr" in parts[1]
	finally:
		srv.close()
