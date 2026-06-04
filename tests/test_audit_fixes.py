"""Regression tests for the audit-fix batch:

- EasySSL.send() now loops until every byte is flushed (partial-write fix).
- ScanCL0's no-gadget fallback builds a syntactically valid request.
- Findings registry -> JSON / SARIF serializers.
- Payload-filename host sanitization.
- Web GUI temp-file cleanup only touches files under TMP_DIR.
"""

import pytest

from lib.EasySSL import EasySSL
from lib.Scans import ScanCL0
import smuggler


# ----- EasySSL.send() partial-write -------------------------------------

class _ShortSock:
	"""Fake socket whose send() flushes at most `chunk` bytes per call, the way
	a real TLS socket can under congestion / when the payload exceeds a record."""

	def __init__(self, chunk=1000):
		self.chunk = chunk
		self.received = b""

	def send(self, data):
		n = min(self.chunk, len(data))
		self.received += data[:n]
		return n


def test_send_flushes_all_bytes_despite_short_writes():
	web = EasySSL(SSLFlag=False)
	sock = _ShortSock(chunk=1000)
	web.s = sock
	payload = b"A" * 5000 + b"B" * 137  # not a multiple of chunk
	returned = web.send(payload)
	assert returned == len(payload)
	assert sock.received == payload  # every byte landed, in order


def test_send_accepts_str_and_encodes_latin1():
	web = EasySSL(SSLFlag=False)
	sock = _ShortSock(chunk=4)
	web.s = sock
	web.send("héllo")  # non-ascii -> latin-1
	assert sock.received == "héllo".encode("latin-1")


# ----- ScanCL0 fallback gadget ------------------------------------------

def _cl0():
	return ScanCL0(
		host="127.0.0.1", port=0, ssl_flag=False, timeout=1.0,
		method="POST", endpoint="/", vhost="127.0.0.1", proxy=None,
		logh=None, quiet=True, cookies=[],
	)


def test_cl0_fallback_gadget_builds_valid_request():
	# The legacy fallback used path "/ HTTP/1.1", which the builder expanded to
	# "GET / HTTP/1.1 HTTP/1.1 ...". The fix uses "/robots.txt".
	scanner = _cl0()
	gadget = {"path": "/robots.txt", "look_for": "llow:", "header_only": False}
	req = scanner._build_cl0_attack("GET", gadget, cookie_hdr="")
	assert "HTTP/1.1 HTTP/1.1" not in req
	assert "GET /robots.txt HTTP/1.1" in req


# ----- Host slug sanitization -------------------------------------------

@pytest.mark.parametrize("raw,expected_safe", [
	("api.example.com", "api_example_com"),
	("../../etc/passwd", "______etc_passwd"),
	("a/b\\c:d", "a_b_c_d"),
	("", "host"),
])
def test_safe_host_slug(raw, expected_safe):
	slug = smuggler._safe_host_slug(raw)
	# No path separators or traversal survive.
	assert "/" not in slug and "\\" not in slug and ".." not in slug
	assert slug == expected_safe


# ----- Findings serializers ---------------------------------------------

_SAMPLE = [
	{"type": "CL0_GET", "mutation": None, "host": "h", "url": "https://h/",
	 "method": "GET", "payload_file": "payloads/x.txt", "status_label": None,
	 "gadget_hit": True, "confidence": "high", "timing_s": 1.2, "configfile": None},
	{"type": "TECL", "mutation": "te-cl", "host": "h", "url": "https://h/",
	 "method": "POST", "payload_file": "payloads/y.txt", "status_label": "timeout",
	 "gadget_hit": False, "confidence": None, "timing_s": None, "configfile": "default.py"},
]


def test_findings_to_json_shape():
	doc = smuggler.findings_to_json(_SAMPLE, target="https://h/")
	assert doc["tool"] == "smuggler"
	assert doc["finding_count"] == 2
	assert doc["target"] == "https://h/"
	assert doc["findings"] == _SAMPLE


def test_findings_to_sarif_shape():
	doc = smuggler.findings_to_sarif(_SAMPLE, target="https://h/")
	assert doc["version"] == "2.1.0"
	run = doc["runs"][0]
	assert run["tool"]["driver"]["name"] == "smuggler"
	assert {r["ruleId"] for r in run["results"]} == {"CL0_GET", "TECL"}
	# Every result carries an artifact location pointing at its payload file.
	uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
		for r in run["results"]]
	assert uris == ["payloads/x.txt", "payloads/y.txt"]
	# Rules are de-duplicated in the driver.
	assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {"CL0_GET", "TECL"}


def test_write_findings_report_roundtrips(tmp_path):
	import json
	p = tmp_path / "report.json"
	n = smuggler.write_findings_report(_SAMPLE, str(p), fmt="json", target="t")
	assert n == 2
	doc = json.loads(p.read_text())
	assert doc["finding_count"] == 2

	ps = tmp_path / "report.sarif"
	smuggler.write_findings_report(_SAMPLE, str(ps), fmt="sarif")
	sdoc = json.loads(ps.read_text())
	assert sdoc["version"] == "2.1.0"


# ----- Web GUI temp-file cleanup ----------------------------------------

def test_cleanup_tmp_files_scoped_to_tmp_dir(tmp_path):
	webgui = pytest.importorskip("webgui")
	# A file inside TMP_DIR is removed; a file outside is left untouched.
	inside = webgui.TMP_DIR / "req-deadbeef.req"
	inside.write_text("Authorization: Bearer fake\r\n\r\n")
	outside = tmp_path / "user-owned.txt"
	outside.write_text("keep me")

	webgui._cleanup_tmp_files([str(inside), str(outside)])

	assert not inside.exists()
	assert outside.exists()
