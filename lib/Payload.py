#!/usr/bin/python
# MIT License
# 
# Copyright (c) 2020 Evan Custodio
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
import random
import re

RN = "\r\n"
EndChunk = "0\r\n\r\n"

def cache_bust_sep(endpoint):
	"""Return the query separator to use when appending a cache-busting
	parameter to `endpoint`: '?' when the endpoint has no query string yet,
	'&' when it already contains one (so we don't emit a second '?')."""
	return '&' if '?' in endpoint else '?'

def cache_bust(endpoint, cb, name="cb"):
	"""Append a cache-busting `name=cb` parameter to `endpoint`, choosing the
	correct separator so an endpoint that already carries query parameters
	gets '&name=...' instead of a malformed second '?name=...'."""
	return "%s%s%s=%s" % (endpoint, cache_bust_sep(endpoint), name, cb)

def Chunked(data):
	return hex(len(data))[2:]+RN+data+RN

def ChunkedExt(data, ext=""):
	return hex(len(data))[2:]+ext+RN+data+RN

def EndChunkExt(ext=""):
	return "0"+ext+RN+RN

def EndChunkBareLF():
	return "0\n\n"

def ChunkedBareLF(data):
	return hex(len(data))[2:]+"\n"+data+"\n"

def EndChunkBareCR():
	return "0\r\r"

class RawPayload():
	def __init__(self):
		self.data = b""

	def __str__(self):
		if isinstance(self.data, bytes):
			return self.data.decode('latin-1')
		return self.data

	def to_bytes(self):
		if isinstance(self.data, str):
			return self.data.encode('latin-1')
		return self.data

class Payload():
	def __init__(self, host=None):
		self.header = None
		self.body = None
		self.method = "GET"
		self.endpoint = "/"
		self.host = host
		self.cl = -1

	def __str__(self):
		def replace_random(match):
			return str(random.random()).split('.')[1]
		
		
		if (self.header == None):
			raise AttributeError("No header data specified in Payload instance")
		if (self.body == None):
			raise AttributeError("No body data specified in Payload instance")
		if (self.host == None):
			raise AttributeError("No host specified in Payload instance")
			
		result = self.header + RN + self.body
		result = re.sub("__RANDOM__",replace_random,result)
		
		if (self.cl < 0):
			result = re.sub("__REPLACE_CL__",str(len(self.body)),result)
		else:
			result = re.sub("__REPLACE_CL__",str(self.cl),result)
			
		result = re.sub("__METHOD__",self.method,result)
		# Templates hardcode the cache-buster as `__ENDPOINT__?cb=...`. When the
		# endpoint already carries a query string, rewrite that literal '?' to
		# '&' so we don't produce a malformed request line with two '?'.
		if '?' in self.endpoint:
			result = result.replace("__ENDPOINT__?cb=", "__ENDPOINT__&cb=")
		result = re.sub("__ENDPOINT__",self.endpoint,result)
		result = re.sub("__HOST__",self.host,result)
			
		return (result)
		
	def __setattr__(self, name, value):
		if name in ("body", "header", "host") and value is not None and not isinstance(value, str):
			raise AttributeError("Only string types allowed for %s" % name)
		self.__dict__[name] = value
