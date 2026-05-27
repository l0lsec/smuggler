"""Tests for lib.Timing.TimingBaseline."""

import pytest

import tests.mock_server as mock_server
from lib.Timing import TimingBaseline, _median, _mad


def test_median_odd_count():
	assert _median([1.0, 3.0, 2.0]) == 2.0


def test_median_even_count():
	assert _median([1.0, 2.0, 3.0, 4.0]) == 2.5


def test_median_empty():
	assert _median([]) == 0.0


def test_mad_uniform_zero():
	# All samples identical -> MAD is exactly 0.
	assert _mad([2.0, 2.0, 2.0], med=2.0) == 0.0


def test_mad_sane_spread():
	# Samples 1,2,3,4,5 -> median 3. Deviations |x-3| = 2,1,0,1,2 ->
	# median(deviations) = 1.0
	assert _mad([1.0, 2.0, 3.0, 4.0, 5.0], med=3.0) == 1.0


def test_is_anomalous_returns_false_on_empty_baseline():
	# An empty baseline (every probe failed) must never flag anything.
	tb = TimingBaseline(median_s=0.0, mad_s=0.0, samples=[])
	assert tb.is_anomalous(10.0) is False
	assert tb.is_anomalous(0.0) is False


def test_is_anomalous_respects_mad_floor():
	# All samples identical -> MAD=0, but the floor prevents the
	# is_anomalous predicate from classifying every wobble as anomalous.
	tb = TimingBaseline(median_s=0.1, mad_s=0.0, samples=[0.1, 0.1, 0.1],
		mad_floor_s=0.05)
	assert tb.is_anomalous(0.12, k=3.0) is False   # |0.12 - 0.1| = 0.02 < 3 * 0.05
	assert tb.is_anomalous(0.5, k=3.0) is True     # |0.5 - 0.1| = 0.4 > 0.15


def test_is_anomalous_uses_real_mad_when_above_floor():
	tb = TimingBaseline(median_s=0.5, mad_s=0.2, samples=[0.3, 0.5, 0.7],
		mad_floor_s=0.05)
	# k=3 -> threshold = 0.6 -> 1.2 - 0.5 = 0.7 > 0.6 -> anomalous
	assert tb.is_anomalous(1.2, k=3.0) is True
	# 0.9 - 0.5 = 0.4 < 0.6 -> not anomalous
	assert tb.is_anomalous(0.9, k=3.0) is False


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


def test_sample_against_live_server(server_factory):
	port = server_factory("compliant")
	req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	tb = TimingBaseline.sample("127.0.0.1", port, False, 2.0, req, n=4)
	assert tb.sample_count >= 1
	# Localhost: every sample should be well under the 2s ceiling.
	assert tb.median_s < 2.0
	assert all(s >= 0 for s in tb.samples)


def test_sample_returns_empty_on_unreachable_target():
	tb = TimingBaseline.sample("127.0.0.1", 1, False, 0.5,
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", n=2)
	assert tb.sample_count == 0
	# Empty baseline never flags anomaly.
	assert tb.is_anomalous(99.0) is False
