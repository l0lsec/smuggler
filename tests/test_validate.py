"""Tests for the self-contained desync confirmer (lib/Confirm.py).

Each test points DesyncConfirmer at an in-process mock_server behavior and
asserts the per-family verdict. The confirmer only ever sends its own
requests; these tests verify it reliably reproduces (or fails to reproduce)
a finding without any third-party traffic.
"""

import os

import pytest

import tests.mock_server as mock_server
from lib.Confirm import DesyncConfirmer, ConfirmError, family_for_kind


@pytest.fixture
def server_factory():
	srvs = []

	def factory(behavior):
		srv, _t, port = mock_server.start(behavior)
		srvs.append(srv)
		return port

	yield factory
	for s in srvs:
		mock_server.stop(s)


def _confirmer(port, tmp_path):
	return DesyncConfirmer(
		host="127.0.0.1", port=port, ssl_flag=False, timeout=2.0,
		proxy=None, vhost="127.0.0.1", method="POST", endpoint="/",
		payloads_dir=str(tmp_path))


def _write_payload(tmp_path, name, data):
	p = tmp_path / name
	if isinstance(data, str):
		data = data.encode("latin-1")
	p.write_bytes(data)
	return str(p)


# ----- family routing ----------------------------------------------------

def test_family_routing():
	assert family_for_kind("CL0") == "prefix"
	assert family_for_kind("CLTE") == "prefix"
	assert family_for_kind("BARELF") == "prefix"
	assert family_for_kind("HDRREMOVAL") == "differential"
	assert family_for_kind("HOPBYHOP_Authorization") == "differential"
	assert family_for_kind("CONNSTATE_FP") == "connstate"
	assert family_for_kind("PAUSE") == "pause"
	assert family_for_kind("H2_h2cl-basic") == "h2"


# ----- prefix mode (CL.0 against the cl0 oracle) -------------------------

def test_prefix_confirmed_on_cl0(server_factory, tmp_path):
	port = server_factory("cl0")
	smuggled = "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	poc = (
		"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"
		% (len(smuggled), smuggled))
	path = _write_payload(tmp_path, "http_127_0_0_1_CL0_x.txt", poc)

	c = _confirmer(port, tmp_path)
	verdict = c.confirm(path, scan_kind="CL0")
	assert verdict is True
	assert "CONFIRMED" in c.summarize()
	# Evidence written under payloads/confirmations/, own traffic only.
	ev = c._evidence_path
	assert ev and os.path.isfile(ev)
	assert "confirmations" in ev
	assert oct(os.stat(ev).st_mode & 0o777) == "0o600"


def test_prefix_not_confirmed_on_compliant(server_factory, tmp_path):
	port = server_factory("compliant")
	smuggled = "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	poc = (
		"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"
		% (len(smuggled), smuggled))
	path = _write_payload(tmp_path, "http_127_0_0_1_CL0_x.txt", poc)

	c = _confirmer(port, tmp_path)
	verdict = c.confirm(path, scan_kind="CL0")
	assert verdict is False
	assert "NOT CONFIRMED" in c.summarize()


# ----- differential mode -------------------------------------------------

def test_differential_confirmed_on_header_removal(server_factory, tmp_path):
	port = server_factory("header_removal")
	canary = "wrtzwrrrrr"
	body = "Host: " + canary
	attack = (
		"POST /?cb=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		"User-Agent: smuggler\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Connection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\n"
		"Content-Length: %d\r\n\r\n%s" % (len(body), body))
	path = _write_payload(tmp_path, "http_127_0_0_1_HDRREMOVAL_x.txt", attack)

	c = _confirmer(port, tmp_path)
	verdict = c.confirm(path, scan_kind="HDRREMOVAL")
	assert verdict is True


def test_differential_confirmed_on_hopbyhop(server_factory, tmp_path):
	port = server_factory("hopbyhop_strip")
	attack = (
		"GET /?cb=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: smuggler\r\n"
		"Authorization: Bearer good\r\n"
		"Connection: Authorization\r\nConnection: keep-alive\r\n\r\n")
	path = _write_payload(tmp_path, "http_127_0_0_1_HOPBYHOP_Authorization_x.txt", attack)

	c = _confirmer(port, tmp_path)
	verdict = c.confirm(path, scan_kind="HOPBYHOP_Authorization")
	assert verdict is True


def test_differential_not_confirmed_on_compliant(server_factory, tmp_path):
	port = server_factory("compliant")
	canary = "wrtzwrrrrr"
	body = "Host: " + canary
	attack = (
		"POST /?cb=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n"
		"Content-Length: %d\r\n\r\n%s" % (len(body), body))
	path = _write_payload(tmp_path, "http_127_0_0_1_HDRREMOVAL_x.txt", attack)

	c = _confirmer(port, tmp_path)
	assert c.confirm(path, scan_kind="HDRREMOVAL") is False


# ----- connection-state mode ---------------------------------------------

def test_connstate_confirmed(server_factory, tmp_path):
	port = server_factory("connstate")
	setup = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
	canary = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
	poc = "# Request 1 (setup):\n" + setup + "\n# Request 2 (canary):\n" + canary
	path = _write_payload(tmp_path, "http_127_0_0_1_CONNSTATE_x.txt", poc)

	c = _confirmer(port, tmp_path)
	assert c.confirm(path, scan_kind="CONNSTATE") is True


def test_connstate_not_confirmed_on_compliant(server_factory, tmp_path):
	port = server_factory("compliant")
	setup = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
	canary = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
	poc = "# Request 1 (setup):\n" + setup + "\n# Request 2 (canary):\n" + canary
	path = _write_payload(tmp_path, "http_127_0_0_1_CONNSTATE_x.txt", poc)

	c = _confirmer(port, tmp_path)
	assert c.confirm(path, scan_kind="CONNSTATE") is False


# ----- timed / pause mode ------------------------------------------------

def test_pause_confirmed_on_cl0(server_factory, tmp_path):
	port = server_factory("cl0")
	smuggled = "GET /robots.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	headers = (
		"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n" % len(smuggled))
	poc = headers + "[PAUSE 1s]" + smuggled
	path = _write_payload(tmp_path, "http_127_0_0_1_PAUSE_x.txt", poc)

	c = _confirmer(port, tmp_path)
	assert c.confirm(path, scan_kind="PAUSE") is True


# ----- H2 mode (no live H2 in the mock -> clean negative) ----------------

def test_h2_handles_no_http2_target(server_factory, tmp_path):
	port = server_factory("compliant")
	poc = "# h2cl-basic\n# H2.CL\n# gadget=/robots.txt token='llow:'\n"
	path = _write_payload(tmp_path, "http_127_0_0_1_H2_h2cl-basic_x.txt", poc)

	c = _confirmer(port, tmp_path)
	# Plaintext mock never negotiates h2 -> NOT CONFIRMED, but no crash.
	assert c.confirm(path, scan_kind="H2_h2cl-basic") is False
	assert "NOT CONFIRMED" in c.summarize()


# ----- refusals (no socket opened) ---------------------------------------

def test_refuse_nonexistent_payload(tmp_path):
	c = _confirmer(1, tmp_path)
	with pytest.raises(ConfirmError):
		c.confirm(str(tmp_path / "does_not_exist.txt"), scan_kind="CL0")


def test_refuse_payload_outside_payloads_dir(tmp_path):
	# A real file, but outside the confirmer's payloads_dir -> refused.
	outside = tmp_path.parent / "outside.txt"
	outside.write_text("POST / HTTP/1.1\r\nHost: x\r\n\r\n")
	c = _confirmer(1, tmp_path)
	with pytest.raises(ConfirmError):
		c.confirm(str(outside), scan_kind="CL0")


def test_refuse_followup_host_mismatch(server_factory, tmp_path):
	port = server_factory("cl0")
	poc = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
	path = _write_payload(tmp_path, "http_127_0_0_1_CL0_x.txt", poc)
	followup = tmp_path / "followup.txt"
	followup.write_text("GET / HTTP/1.1\r\nHost: someone-else.example\r\n\r\n")

	c = _confirmer(port, tmp_path)
	with pytest.raises(ConfirmError):
		c.confirm(path, followup_path=str(followup), scan_kind="CL0")
