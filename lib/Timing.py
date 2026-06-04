"""Statistical RTT baseline for the classic timing oracle.

The original ``_confirm_timeout_anomaly`` in ``smuggler.py`` uses a
binary decision: did the socket time out (``self._timeout - 1`` second
deadline) or did it return? That works on a quiet network but produces
false positives on jittery CDNs (one stray 5s spike looks like a
desync) and false negatives on slow upstreams (where a real desync
adds only ~2s to a 5s baseline).

``TimingBaseline`` replaces that binary view with a small distribution:
sample N RTTs of the same benign request on fresh connections, store
median + median-absolute-deviation, and offer ``is_anomalous(rtt, k)``
which fires when ``|rtt - median| > k * MAD``. MAD is preferred over
stddev because it's robust to the very outliers we're trying to detect
in the first place.

A MAD floor (default 50ms) prevents divide-by-zero on perfectly flat
distributions (mock servers, localhost) and also tightens the floor on
near-zero MADs that would otherwise classify trivial 10ms wobble as
"anomalous".
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from lib.EasySSL import EasySSL


def _median(values: List[float]) -> float:
	if not values:
		return 0.0
	s = sorted(values)
	mid = len(s) // 2
	if len(s) % 2 == 1:
		return s[mid]
	return (s[mid - 1] + s[mid]) / 2.0


def _mad(values: List[float], med: float) -> float:
	"""Median absolute deviation. Robust to outliers, which matters here
	because the whole point of the baseline is to flag outliers."""
	if not values:
		return 0.0
	deviations = [abs(v - med) for v in values]
	return _median(deviations)


class TimingBaseline:
	"""Distribution snapshot for ``timeout``-style oracle augmentation."""

	__slots__ = ("median_s", "mad_s", "samples", "mad_floor_s")

	def __init__(self, median_s: float, mad_s: float, samples: List[float],
			mad_floor_s: float = 0.05):
		self.median_s = median_s
		self.mad_s = mad_s
		self.samples = list(samples)
		self.mad_floor_s = mad_floor_s

	@property
	def sample_count(self) -> int:
		return len(self.samples)

	@classmethod
	def sample(cls, host: str, port: int, ssl_flag: bool, timeout: float,
			request_str: str, proxy=None, n: int = 5,
			mad_floor_s: float = 0.05) -> "TimingBaseline":
		"""Send ``request_str`` ``n`` times on fresh connections and
		compute (median, MAD) over the per-request RTT in seconds.

		Returns an empty baseline (zero median/MAD, no samples) if every
		probe failed. ``is_anomalous`` on an empty baseline always
		returns False so callers won't false-positive on transient
		network failures during setup.
		"""
		samples: List[float] = []
		for _ in range(max(1, n)):
			try:
				web = EasySSL(ssl_flag)
				web.connect(host, port, timeout, proxy)
				start = datetime.now()
				web.send(request_str.encode('latin-1'))
				_ = web.recv_all(timeout)
				rtt = (datetime.now() - start).total_seconds()
				web.close()
				samples.append(rtt)
			except Exception:
				continue
		med = _median(samples)
		mad = _mad(samples, med)
		return cls(median_s=med, mad_s=mad, samples=samples, mad_floor_s=mad_floor_s)

	def is_anomalous(self, rtt_s: float, k: float = 3.0) -> bool:
		"""True iff ``rtt_s`` is more than ``k * MAD`` away from the
		median. MAD is floored to ``self.mad_floor_s`` so localhost-flat
		baselines don't make every 10ms wobble look anomalous, and the
		method returns False on an empty baseline (sample failure) so
		callers don't false-positive during setup.
		"""
		if not self.samples:
			return False
		mad = max(self.mad_s, self.mad_floor_s)
		return abs(rtt_s - self.median_s) > (k * mad)

	def __repr__(self):  # pragma: no cover - debug aid only
		return ("TimingBaseline(median=%.3fs, mad=%.3fs, n=%d)" % (
			self.median_s, self.mad_s, len(self.samples)))
