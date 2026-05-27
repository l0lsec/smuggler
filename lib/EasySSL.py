#!/usr/bin/python
# MIT License
# 
# Copyright (c) 2026 Sedric Louissaint
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import socket, ssl
import time
from urllib.parse import urlparse

try:
	import h2.connection
	import h2.config
	import h2.events
	H2_AVAILABLE = True
except ImportError:
	H2_AVAILABLE = False

# EasySSL: A simple module to perform SSL Queries
class EasySSL():
	# constructor: we can specify recv bufsize
	def __init__(self, SSLFlag = True, bufsize=8192):
		self.bufsize = bufsize
		self.SSLFlag = SSLFlag
		self.connected = False
		self.s = None
		self.ssl = None
		self.context = None
		
	# connect() - Simply provide webserver address and optional port (default 443)
	def connect(self,host,port=443,timeout=None,proxy=None,persistent=False):
		# If already connected and persistent mode, don't reconnect
		if persistent and self.connected:
			return
		
		# Close existing connection if any
		if self.connected:
			self.close()
		
		# 1) Create an SSL context to wrap our socket
		# 2) Create our socket
		# 3) Wrap our socket
		# 4) Connect
		
		# Handle proxy configuration
		if proxy:
			proxy_url = urlparse(proxy)
			proxy_host = proxy_url.hostname
			proxy_port = proxy_url.port or 8080
			
			if proxy_url.scheme == 'http':
				# HTTP proxy using CONNECT method
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.s.settimeout(timeout)
				self.s.connect((proxy_host, proxy_port))
				
				# Send CONNECT request
				connect_request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)
				self.s.send(connect_request.encode())
				
				# Read response
				response = self.s.recv(4096).decode()
				if not response.startswith("HTTP/1.1 200"):
					raise Exception("Proxy CONNECT failed: %s" % response.split('\r\n')[0])
			else:
				# For SOCKS or other proxy types, fall back to direct connection
				# and print a warning
				print("Warning: Only HTTP proxies are supported. Using direct connection.")
				self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.s.settimeout(timeout)
				self.s.connect((host, port))
		else:
			# Direct connection
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.s.settimeout(timeout)
			self.s.connect((host, port))
		
		if (self.SSLFlag):
			self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
			self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
			self.ssl.settimeout(timeout)
		
		self.connected = True

			
	def close(self):
		if (self.SSLFlag):
			if hasattr(self, 'ssl'):
				self.ssl.close()
				del self.ssl
			if hasattr(self, 'context'):
				del self.context
		if hasattr(self, 's'):
			self.s.close()
			del self.s
		self.connected = False
		
	# send() - Sends data through the socket
	def send(self, data):
		if (self.SSLFlag and hasattr(self, 'ssl')):
			return self.ssl.send(data)
		else:
			return self.s.send(data)
		
	def recv(self):
		try:
			if (self.SSLFlag and hasattr(self, 'ssl')):
				self.ssl.settimeout(None)
				buffer = self.ssl.recv(self.bufsize)
			else:
				self.s.settimeout(None)
				buffer = self.s.recv(self.bufsize)

		except Exception as e:
			buffer = None
			#print (e)
		return buffer
		
	def recv_nb(self,timeout=0.0):
		try:
			
			if (self.SSLFlag and hasattr(self, 'ssl')):
				self.ssl.settimeout(timeout)
				buffer = self.ssl.recv(self.bufsize)
			else:
				self.s.settimeout(timeout)
				buffer = self.s.recv(self.bufsize)

		except Exception as e:
			buffer = None
			#print (e)
		return buffer

	def send_raw(self, data):
		if isinstance(data, str):
			data = data.encode('latin-1')
		return self.send(data)

	def send_timed(self, first_part, second_part, pause_seconds):
		if isinstance(first_part, str):
			first_part = first_part.encode('latin-1')
		if isinstance(second_part, str):
			second_part = second_part.encode('latin-1')
		self.send(first_part)
		time.sleep(pause_seconds)
		self.send(second_part)

	def pipeline_send(self, requests):
		combined = b""
		for req in requests:
			if isinstance(req, str):
				req = req.encode('latin-1')
			combined += req
		return self.send(combined)

	def recv_all(self, timeout=5.0, max_size=65536):
		data = b""
		sock = self.ssl if (self.SSLFlag and hasattr(self, 'ssl')) else self.s
		sock.settimeout(timeout)
		try:
			while len(data) < max_size:
				chunk = sock.recv(self.bufsize)
				if not chunk:
					break
				data += chunk
				sock.settimeout(0.5)
		except Exception:
			pass
		return data if data else None

	def recv_multiple(self, count, timeout=5.0):
		"""Receive `count` HTTP/1.x responses framed by Content-Length or
		Transfer-Encoding: chunked. We walk the byte stream rather than
		string-splitting on "HTTP/" -- bodies and chunked fragments routinely
		contain that literal, which caused false splits in the previous
		implementation."""
		responses = []
		raw = self.recv_all(timeout)
		if raw is None:
			return responses
		offset = 0
		total = len(raw)
		for _ in range(count):
			if offset >= total:
				break
			hdr_end = raw.find(b"\r\n\r\n", offset)
			if hdr_end < 0:
				# Trailing partial; treat the remainder as one response.
				responses.append(raw[offset:].decode('latin-1', errors='replace'))
				offset = total
				break
			headers_blob = raw[offset:hdr_end]
			body_start = hdr_end + 4

			# Default framing: read to end of buffer.
			body_end = total

			# Lowercase header copy for matching only.
			hdr_lower = headers_blob.lower()
			cl_idx = hdr_lower.find(b"content-length:")
			te_chunked = b"transfer-encoding:" in hdr_lower and b"chunked" in hdr_lower

			if te_chunked:
				# Walk chunks: <size-hex>\r\n<data>\r\n ... 0\r\n\r\n
				cur = body_start
				while cur < total:
					line_end = raw.find(b"\r\n", cur)
					if line_end < 0:
						break
					size_token = raw[cur:line_end].split(b";", 1)[0].strip()
					try:
						chunk_size = int(size_token, 16)
					except ValueError:
						break
					cur = line_end + 2
					if chunk_size == 0:
						# Skip optional trailers up to final CRLF.
						trail_end = raw.find(b"\r\n\r\n", cur - 2)
						if trail_end >= 0:
							cur = trail_end + 4
						else:
							cur = total
						break
					cur += chunk_size + 2  # data + trailing CRLF
				body_end = min(cur, total)
			elif cl_idx >= 0:
				cl_line_end = hdr_lower.find(b"\r\n", cl_idx)
				if cl_line_end < 0:
					# Content-Length is the final header in headers_blob, so
					# there's no trailing \r\n inside the slice -- read to
					# the end. (The old `[a:-1]` slice silently dropped the
					# last digit, e.g. parsing "34" as "3".)
					cl_line_end = len(hdr_lower)
				cl_value = hdr_lower[cl_idx + len(b"content-length:"):cl_line_end].strip()
				try:
					cl = int(cl_value)
					body_end = min(body_start + cl, total)
				except ValueError:
					body_end = total
			else:
				# No framing info: assume single response fills the rest.
				body_end = total

			responses.append(raw[offset:body_end].decode('latin-1', errors='replace'))
			offset = body_end
		return responses

	# recv_web is an HTTP response parser. This parser has been hacked together and probably doesn't conform to RFC
	# please do not use this for any serious HTTP response parsing. Only meant for security research
	def recv_web(self):
		ST_PROCESS_HEADERS = 0
		ST_PROCESS_BODY_CL = 1
		ST_PROCESS_BODY_TE = 2
		ST_PROCESS_BODY_NODATA = 3
	
		state = ST_PROCESS_HEADERS
		dat_raw = b""
		CL_TE = -1
		size = 0
		k = 0
		cls = False
		http_ver = "1.1" # assume 1.1, this will get overwritten
		while(1):
			#time.sleep(0.01)
			#k += 1
			#print ("loop %d" %(k))
			#print ("state = %d"%(state))
			retry = 0
			while (1):
				
				sample = self.recv_nb(1)
				if ((sample == None) or (sample == b"")):
					if (retry == 5):
						if len(dat_raw) == 0:
							cls = True
						return (cls, dat_raw.decode("UTF-8",'ignore'))
					retry += 1
				else:
					dat_raw += sample
					break
					
			dat_dec = dat_raw.decode("UTF-8",'ignore')
			dat_split = dat_dec.split("\r\n")
			
			if (state == ST_PROCESS_HEADERS):
				if dat_split[0][0:4] == "HTTP":
					#print("Found HTTP")
					http_ver = dat_split[0][5:8]
					if (http_ver == "1.0"):
						cls = True
					state = ST_PROCESS_HEADERS
					for line in dat_split:
						if (len(line) >= len("Transfer-Encoding:")) and (line[0:18].lower() == "transfer-encoding:"):
							#print ("Found TE Header")
							CL_TE = 1
						elif (len(line) >= len("Content-Length:")) and (line[0:15].lower() == "content-length:"):
							size = int(line[15:].strip())
							#print ("Found CL Header: Size %d" % (size))
							CL_TE = 0
						elif (len(line) >= len("Connection: close")) and (line[0:17].lower() == "connection: close"):
							cls = True
						elif (len(line) >= len("Connection: keep-alive")) and (line[0:22] == "connection: keep-alive"):
							cls = False
						elif (line == ""):
							#print ("Found end of headers")
							if (CL_TE == 0):
								state = ST_PROCESS_BODY_CL
							elif (CL_TE == 1):
								state = ST_PROCESS_BODY_TE
							else:
								state = ST_PROCESS_NODATA
								return (cls, dat_dec)
							break
						
			if (state == ST_PROCESS_BODY_CL):
				start = dat_dec.find("\r\n\r\n")+4
				#print ("%d %d " % (len(dat_raw)-start,size))
				if (len(dat_raw)-start) == size:
					return (cls, dat_dec)
			
			if (state == ST_PROCESS_BODY_TE):
				# FIXME: This is a terrible hack and can easily break
				# replace with an implementation that tracks the chunked lengths
				if dat_dec[-5:] == "0\r\n\r\n": 
					return (cls, dat_dec)


class EasyH2():
	def __init__(self, bufsize=65535):
		if not H2_AVAILABLE:
			raise ImportError("h2 library required for HTTP/2 support: pip install h2")
		self.bufsize = bufsize
		self.connected = False
		self.s = None
		self.ssl_sock = None
		self.h2_conn = None

	def connect(self, host, port=443, timeout=None, proxy=None):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(timeout)

		if proxy:
			proxy_url = urlparse(proxy)
			proxy_host = proxy_url.hostname
			proxy_port = proxy_url.port or 8080
			if proxy_url.scheme == 'http':
				self.s.connect((proxy_host, proxy_port))
				connect_request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)
				self.s.send(connect_request.encode())
				response = self.s.recv(4096).decode()
				if not response.startswith("HTTP/1.1 200"):
					raise Exception("Proxy CONNECT failed: %s" % response.split('\r\n')[0])
			else:
				self.s.connect((host, port))
		else:
			self.s.connect((host, port))

		ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		ctx.set_alpn_protocols(['h2'])
		self.ssl_sock = ctx.wrap_socket(self.s, server_hostname=host)
		self.ssl_sock.settimeout(timeout)

		negotiated = self.ssl_sock.selected_alpn_protocol()
		if negotiated != 'h2':
			raise Exception("Server does not support HTTP/2 (negotiated: %s)" % negotiated)

		config = h2.config.H2Configuration(client_side=True)
		self.h2_conn = h2.connection.H2Connection(config=config)
		self.h2_conn.initiate_connection()
		self.ssl_sock.sendall(self.h2_conn.data_to_send())
		self.connected = True
		self.host = host

	def send_request(self, method, path, headers=None, body=None, extra_pseudo_headers=None):
		hdrs = [
			(':method', method),
			(':path', path),
			(':authority', self.host),
			(':scheme', 'https'),
		]

		if extra_pseudo_headers:
			for k, v in extra_pseudo_headers:
				hdrs.append((k, v))

		if headers:
			for k, v in headers:
				hdrs.append((k.lower(), v))

		if 'user-agent' not in [h[0] for h in hdrs]:
			hdrs.append(('user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36'))

		stream_id = self.h2_conn.get_next_available_stream_id()
		self.h2_conn.send_headers(stream_id, hdrs, end_stream=(body is None))
		self.ssl_sock.sendall(self.h2_conn.data_to_send())

		if body is not None:
			if isinstance(body, str):
				body = body.encode()
			self.h2_conn.send_data(stream_id, body, end_stream=True)
			self.ssl_sock.sendall(self.h2_conn.data_to_send())

		return stream_id

	def send_raw_headers(self, headers_list, body=None):
		stream_id = self.h2_conn.get_next_available_stream_id()
		self.h2_conn.send_headers(stream_id, headers_list, end_stream=(body is None))
		self.ssl_sock.sendall(self.h2_conn.data_to_send())

		if body is not None:
			if isinstance(body, str):
				body = body.encode()
			self.h2_conn.send_data(stream_id, body, end_stream=True)
			self.ssl_sock.sendall(self.h2_conn.data_to_send())

		return stream_id

	def recv_response(self, stream_id, timeout=5.0):
		self.ssl_sock.settimeout(timeout)
		response_headers = {}
		response_data = b""
		stream_ended = False

		while not stream_ended:
			try:
				data = self.ssl_sock.recv(self.bufsize)
				if not data:
					break
				events = self.h2_conn.receive_data(data)
				self.ssl_sock.sendall(self.h2_conn.data_to_send())

				for event in events:
					if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
						for k, v in event.headers:
							if isinstance(k, bytes):
								k = k.decode()
							if isinstance(v, bytes):
								v = v.decode()
							response_headers[k] = v
					elif isinstance(event, h2.events.DataReceived) and event.stream_id == stream_id:
						response_data += event.data
						self.h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
						self.ssl_sock.sendall(self.h2_conn.data_to_send())
					elif isinstance(event, h2.events.StreamEnded) and event.stream_id == stream_id:
						stream_ended = True
					elif isinstance(event, h2.events.StreamReset) and event.stream_id == stream_id:
						stream_ended = True
			except Exception:
				break

		return response_headers, response_data

	def close(self):
		try:
			if self.h2_conn:
				self.h2_conn.close_connection()
				if self.ssl_sock:
					self.ssl_sock.sendall(self.h2_conn.data_to_send())
		except Exception:
			pass
		try:
			if self.ssl_sock:
				self.ssl_sock.close()
		except Exception:
			pass
		try:
			if self.s:
				self.s.close()
		except Exception:
			pass
		self.connected = False

		