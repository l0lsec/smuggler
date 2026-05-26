# Smuggler tests

Run the suite from the project root:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## What's covered

| File | Purpose |
| --- | --- |
| `mock_server.py` | Pluggable HTTP/1.1 server with toggleable HRS-class behaviors |
| `test_scans.py` | Positive + negative cases per advanced scanner (`ScanCL0`, `ScanHeaderRemoval`, `ScanParserDiscrepancy`, `ScanHopByHop`) |
| `test_recv_multiple.py` | Regression for `EasySSL.recv_multiple` splitting bug (bodies containing the literal `HTTP/`) |
| `test_replay_rewrite.py` | Regression for `ReplayManager.build_request_with_id` Content-Length recomputation |

## Adding tests for a new scanner

1. Add a new behavior key in `mock_server.py` that simulates the
   vulnerability class your scanner detects.
2. Add `_positive` and `_negative` tests in `test_scans.py` mirroring the
   existing pattern.
3. Keep the timeout small (`2.0` s) -- everything runs in-process.

## What's deliberately not covered

- Tests that require a real HTTP/2 stack are not run (we don't ship an h2
  mock); `ScanH2Desync` is tested manually against known-vulnerable
  endpoints.
- TLS paths are not exercised; the mock server is plain HTTP. All scanners
  use the same `ssl_flag` plumbing so this is acceptable for unit-level
  coverage.
- `--persistent-connection` integration is not in scope here -- that mode
  is exercised by the existing live-target replay flow.

## Example request files

These are sample HTTP request files used either as `-r/--request` input
or as `--baseline-request` input. **Pick the right file for your mode**
— the in-tool validator will warn you if you don't.

| File | Mode | Notes |
| --- | --- | --- |
| `req_clean.txt` | `-r` (scan mode) | Plain GET, no body, no embedded smuggle. Use this as your scan-mode template. |
| `req_poc.txt` | `-r --replay` | Deliberate CL.TE POC with chunked terminator + smuggled `GET /admin`. Sent verbatim by `--replay`. |
| `req1.txt`, `req2.txt`, `req3.txt` | `-r --replay` | Legacy POC-shaped samples kept for backwards compat; scan mode will warn if you use them without `--replay`. |
| `baseline_test.txt` | `--baseline-request` | Sample baseline for differential analysis against a smuggling POC during `--replay`. |
