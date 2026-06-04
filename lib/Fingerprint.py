"""Structural response fingerprinting for diff-based detection.

Purpose
-------
Many HRS / desync findings manifest as a response whose status code is
unchanged but whose framing, header set, or body shape diverges from a
clean baseline. The status-code-only comparisons sprinkled across the
existing scanners miss those entirely. ``Fingerprint`` captures six
orthogonal axes so a scanner can ask "did this response *structurally*
differ from baseline?" rather than "did the status code change?".

Axes
----

``status``      First 3-digit status code from the response.
``framing``     ``"cl:<n>"`` | ``"chunked"`` | ``"none"`` -- the framing
                strategy the response declares (not what was actually
                received).
``header_set``  ``frozenset`` of lowercased header names. Order- and
                value-independent so trivial header reordering by a load
                balancer doesn't poison the diff.
``body_len``    Length of the body bytes that followed the headers.
``body_head``   md5 of the first 64 body bytes (cheap content stability).
``body_tail``   md5 of the last 64 body bytes.

Each axis is collected on a fresh connection. ``baseline_fingerprint``
samples N times and returns ``(consensus_fp, noisy_axes)``: any axis
that wasn't identical across all samples is considered noisy and should
be excluded from subsequent diff() comparisons. This is what handles
``Date:``, ``X-Request-Id:``, dynamic cache tags, and other
per-response wobble.

Why MD5 (not e.g. SHA-256)
--------------------------
Speed matters here (every scanner runs O(n) fingerprints) and we are
NOT using these hashes for any security property -- they are just
collision-resistant labels for "are these 64 bytes the same?". MD5 is
the smallest stdlib hash with low enough collision probability for this
use case.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Optional, Set, Tuple

from lib.EasySSL import EasySSL


_FP_AXES = ("status", "framing", "header_set", "body_len", "body_head", "body_tail")


def _md5_hex(b: bytes) -> str:
	return hashlib.md5(b or b"").hexdigest()


def _to_bytes(raw) -> bytes:
	if raw is None:
		return b""
	if isinstance(raw, (bytes, bytearray)):
		return bytes(raw)
	return raw.encode('latin-1', errors='replace')


_RE_STATUS = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})")


def _parse_status(head: bytes) -> str:
	m = _RE_STATUS.match(head)
	return m.group(1).decode('ascii') if m else ""


class Fingerprint:
	"""Immutable structural snapshot of one HTTP response."""

	__slots__ = ("status", "framing", "header_set", "body_len", "body_head", "body_tail")

	def __init__(self, status: str, framing: str, header_set: frozenset,
			body_len: int, body_head: str, body_tail: str):
		self.status = status
		self.framing = framing
		self.header_set = header_set
		self.body_len = body_len
		self.body_head = body_head
		self.body_tail = body_tail

	@classmethod
	def from_response(cls, raw) -> "Fingerprint":
		"""Parse a raw HTTP response (bytes or str) into a fingerprint.

		Handles three framing modes:
		- ``Content-Length: N``  -> body_len = N (truncated to actual)
		- ``Transfer-Encoding: chunked`` -> framing="chunked", body_len
		  is the raw chunked-bytes length (we don't re-walk the chunks
		  here; ``EasySSL.recv_multiple`` already does that splitting
		  for pipelined responses).
		- neither -> framing="none", body_len = remaining bytes.

		Missing / malformed responses produce a fingerprint with empty
		status -- still safe to diff(), all axes will simply look empty.
		"""
		data = _to_bytes(raw)
		if not data:
			return cls("", "none", frozenset(), 0, _md5_hex(b""), _md5_hex(b""))

		hdr_end = data.find(b"\r\n\r\n")
		if hdr_end < 0:
			# Headers never terminated -- treat whole blob as headers,
			# empty body. Still produces a usable fingerprint.
			head_blob = data
			body = b""
		else:
			head_blob = data[:hdr_end]
			body = data[hdr_end + 4:]

		lines = head_blob.split(b"\r\n")
		status = _parse_status(lines[0]) if lines else ""

		header_names = []
		framing = "none"
		cl = -1
		for line in lines[1:]:
			idx = line.find(b":")
			if idx <= 0:
				continue
			name = line[:idx].strip().lower()
			value = line[idx + 1:].strip()
			if not name:
				continue
			header_names.append(name.decode('latin-1', errors='replace'))
			if name == b"transfer-encoding" and b"chunked" in value.lower():
				framing = "chunked"
			elif name == b"content-length" and framing != "chunked":
				try:
					cl = int(value)
					framing = "cl:%d" % cl
				except ValueError:
					pass

		body_len = len(body) if cl < 0 else min(cl, len(body))
		body_slice = body[:body_len] if cl >= 0 else body
		head = body_slice[:64]
		tail = body_slice[-64:] if len(body_slice) >= 64 else body_slice

		return cls(
			status=status,
			framing=framing,
			header_set=frozenset(header_names),
			body_len=body_len,
			body_head=_md5_hex(head),
			body_tail=_md5_hex(tail),
		)

	def diff(self, other: "Fingerprint") -> Set[str]:
		"""Return the set of axis names that differ between two fingerprints.

		``self.diff(other)`` is symmetric. Empty set means "structurally
		identical" by these axes; callers may further intersect with the
		complement of a noisy-axis set.
		"""
		out: Set[str] = set()
		if self.status != other.status:
			out.add("status")
		if self.framing != other.framing:
			out.add("framing")
		if self.header_set != other.header_set:
			out.add("header_set")
		if self.body_len != other.body_len:
			out.add("body_len")
		if self.body_head != other.body_head:
			out.add("body_head")
		if self.body_tail != other.body_tail:
			out.add("body_tail")
		return out

	def is_similar_to(self, other: "Fingerprint", tolerate: Optional[Set[str]] = None) -> bool:
		"""True iff ``self`` differs from ``other`` only on axes in
		``tolerate``. Convenience inverse of ``diff()``."""
		ignored = set(tolerate or set())
		return not (self.diff(other) - ignored)

	def __repr__(self):  # pragma: no cover - debug aid only
		return ("Fingerprint(status=%r, framing=%r, body_len=%d, "
				"header_set=%d names, head=%s..., tail=%s...)" % (
					self.status, self.framing, self.body_len,
					len(self.header_set), self.body_head[:8], self.body_tail[:8]))


def _send_and_capture(host: str, port: int, ssl_flag: bool, timeout: float,
		request_str: str, proxy=None) -> Optional[bytes]:
	try:
		web = EasySSL(ssl_flag)
		web.connect(host, port, timeout, proxy)
		web.send(request_str.encode('latin-1'))
		raw = web.recv_all(timeout)
		web.close()
		return raw
	except Exception:
		return None


def split_pipelined_responses(raw, expected: int = 2) -> List[str]:
	"""Split a raw byte buffer containing ``expected`` pipelined HTTP/1.x
	responses into separate response strings.

	Mirrors the framing logic of ``EasySSL.recv_multiple`` but operates
	on bytes that are already in memory -- useful when the caller has
	captured a pipeline reply via a different code path (e.g. the
	classic CLTE/TECL probe in smuggler.py) and needs to fingerprint
	just the victim leg without bleeding gadget-response bytes into it.

	Returns a list of latin-1 decoded strings (one per parsed response).
	If framing is missing or malformed mid-buffer, the remainder is
	returned as a single trailing element so callers can still inspect
	what was received.
	"""
	data = _to_bytes(raw)
	responses: List[str] = []
	if not data:
		return responses
	offset = 0
	total = len(data)
	for _ in range(max(1, expected)):
		if offset >= total:
			break
		hdr_end = data.find(b"\r\n\r\n", offset)
		if hdr_end < 0:
			responses.append(data[offset:].decode('latin-1', errors='replace'))
			break
		headers_blob = data[offset:hdr_end]
		body_start = hdr_end + 4
		body_end = total

		hdr_lower = headers_blob.lower()
		cl_idx = hdr_lower.find(b"content-length:")
		te_chunked = b"transfer-encoding:" in hdr_lower and b"chunked" in hdr_lower

		if te_chunked:
			cur = body_start
			while cur < total:
				line_end = data.find(b"\r\n", cur)
				if line_end < 0:
					break
				size_token = data[cur:line_end].split(b";", 1)[0].strip()
				try:
					chunk_size = int(size_token, 16)
				except ValueError:
					break
				cur = line_end + 2
				if chunk_size == 0:
					trail_end = data.find(b"\r\n\r\n", cur - 2)
					cur = trail_end + 4 if trail_end >= 0 else total
					break
				cur += chunk_size + 2
			body_end = min(cur, total)
		elif cl_idx >= 0:
			cl_line_end = hdr_lower.find(b"\r\n", cl_idx)
			if cl_line_end < 0:
				cl_line_end = len(hdr_lower)
			cl_value = hdr_lower[cl_idx + len(b"content-length:"):cl_line_end].strip()
			try:
				cl = int(cl_value)
				body_end = min(body_start + cl, total)
			except ValueError:
				body_end = total

		responses.append(data[offset:body_end].decode('latin-1', errors='replace'))
		offset = body_end
	return responses


def baseline_fingerprint(host: str, port: int, ssl_flag: bool, timeout: float,
		request_str: str, proxy=None, n: int = 3) -> Tuple[Fingerprint, Set[str]]:
	"""Sample the same request ``n`` times on fresh connections and return
	(consensus_fp, noisy_axes).

	The consensus fingerprint is the **first** successful sample (its
	values populate the returned ``Fingerprint``). ``noisy_axes`` lists
	axis names whose value was NOT identical across every sample --
	scanners must ignore these axes in their diff() calls for this
	target, since "noise" here means the server itself flips the axis
	between consecutive identical requests (Date headers, request-ids,
	cache wobble).

	Falls back to an empty fingerprint with all axes marked noisy if
	every sample failed -- safer than raising, the caller's diff()
	will just say "nothing reliably differs" and the scanner will
	abstain from a finding.
	"""
	samples: List[Fingerprint] = []
	for _ in range(max(1, n)):
		raw = _send_and_capture(host, port, ssl_flag, timeout, request_str, proxy)
		if raw is None:
			continue
		samples.append(Fingerprint.from_response(raw))
	if not samples:
		empty = Fingerprint("", "none", frozenset(), 0, _md5_hex(b""), _md5_hex(b""))
		return empty, set(_FP_AXES)

	consensus = samples[0]
	noisy: Set[str] = set()
	for other in samples[1:]:
		noisy |= consensus.diff(other)
	return consensus, noisy
