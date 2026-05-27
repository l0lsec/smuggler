```
  ______                         _              
 / _____)                       | |             
( (____  ____  _   _  ____  ____| | _____  ____ 
 \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)
 _____) ) | | | |_| ( (_| ( (_| | || ____| |    
(______/|_|_|_|____/ \___ |\___ |\_)_____)_|    
                    (_____(_____|               

     @l0lsec
```

# Smuggler

An HTTP Request Smuggling / Desync testing tool written in Python 3.

> **This is my fork.** Inspired by — and originally based on — the OG
> [@defparam/smuggler](https://github.com/defparam/smuggler). Active
> development now lives at
> [l0lsec/smuggler](https://github.com/l0lsec/smuggler); the upstream
> repository has not been updated in a while, so this fork is where new
> scanners, the web GUI, the test harness, and bug fixes are landing.

**Version 2.0** — adds 9 advanced scanner classes (CL.0, TE.0, bare-LF
chunked, pause-based, parser-discrepancy, header-removal, Expect,
hop-by-hop, connection-state, HTTP/2 downgrade), a confirmation-first
oracle for the classic TE.CL / CL.TE scanners, a NiceGUI web frontend
(`webgui.py`), a pytest harness with a mock HRS server, and a long list
of correctness fixes around persistent connections, replay-mode CL
recomputation, and request-file validation.

**Version 1.1** (upstream) — replay mode, proxy support, custom request
files, persistent connections, enhanced cookie handling.

## Acknowledgements

A huge thank-you to [Evan Custodio / @defparam](https://github.com/defparam)
for building the original Smuggler — this fork would not exist without
his work. The MIT license carries through unchanged.

A special thanks to [James Kettle](https://skeletonscribe.net/) for his
[research and methods into HTTP desyncs](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn),
which the scanners in this fork build on.

And a special thanks to [Ben Sadeghipour](https://www.nahamsec.com/) for
beta testing the original Smuggler at [Nahamcon 2020](https://nahamcon.com).

## IMPORTANT
This tool does not guarantee no false-positives or false-negatives. Just because a mutation may report OK does not mean there isn't a desync issue, but more importantly just because the tool indicates a potential desync issue does not mean there definitely exists one. The script may encounter request processors from large entities (i.e. Google/AWS/Yahoo/Akamai/etc..) that may show false positive results.

## Installation

1) git clone https://github.com/l0lsec/smuggler.git
2) cd smuggler
3) python3 smuggler.py -h

## Web GUI (optional)

Smuggler ships with a NiceGUI-based web frontend that exposes every CLI flag
as a form control, streams colorized output to the browser in real time, and
gives you a stop button plus a payloads browser. The GUI is a thin wrapper
around `smuggler.py` (it spawns the CLI as a subprocess) so behavior is
identical and no functionality is hidden.

```
pip install -r requirements.txt      # installs nicegui
python3 webgui.py                     # serves on http://127.0.0.1:8765
```

By default the server binds to `127.0.0.1` only. Do NOT expose it on a
public interface -- it is a remote-scan launcher. Pass `--public` only if
you understand the risk.

Features:

- Three target modes: single URL, list of hosts (piped via stdin), or
  request file (upload, path, or inline-paste editor).
- All flags surfaced: `-v/--vhost`, `-m/--method`, `-t/--timeout`,
  `-c/--configfile` (auto-populated from `configs/*.py`),
  `--proxy`, `--cookies`, `--persistent-connection`, `--http2`,
  `--scan-type` (multiselect), `--pause-timeout`, `-x/--exit_early`,
  `-q/--quiet`, `--no-color`, `-l/--log`.
- Replay mode (`--replay`) with optional baseline request file
  (`--baseline-request`) for differential comparison.
- Live counters (Total / Success / Failed / Timeout / Error / RPS / latest
  request ID) parsed from the existing `[REPLAY]` status line.
- Stop button sends `SIGINT` (which `ReplayManager` already treats as a
  clean shutdown), then escalates to `SIGTERM` and `SIGKILL`.
- "Copy command" button surfaces the exact `python3 smuggler.py ...`
  invocation so you can paste it into a shell.
- `payloads/` browser with download links for any files produced by a
  CRITICAL finding.

## Example Usage

Single Host:
```
python3 smuggler.py -u <URL>
```

List of hosts:
```
cat list_of_hosts.txt | python3 smuggler.py
```

Using a custom request file:
```
python3 smuggler.py -r request.txt
```

Replay mode with custom request:
```
python3 smuggler.py -r request.txt --replay
```

Replay mode with baseline comparison:
```
python3 smuggler.py -r smuggling_request.txt --baseline-request normal_request.txt --replay
```

Using proxy:
```
python3 smuggler.py -u https://target.com --proxy http://127.0.0.1:8080
```

With custom cookies:
```
python3 smuggler.py -u https://target.com --cookies "sessionid=abc123; csrftoken=xyz789"
```

Persistent connection mode:
```
python3 smuggler.py -u https://target.com --persistent-connection
```

## Options

```
usage: smuggler.py [-h] [-u URL] [-v VHOST] [-x] [-m METHOD] [-l LOG] [-q]
                   [-t TIMEOUT] [--no-color] [-c CONFIGFILE] [--proxy PROXY]
                   [--cookies COOKIES] [-r REQUEST] [--replay]
                   [--baseline-request BASELINE_REQUEST]
                   [--persistent-connection]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL with Endpoint
  -v VHOST, --vhost VHOST
                        Specify a virtual host
  -x, --exit_early      Exit scan on first finding
  -m METHOD, --method METHOD
                        HTTP method to use (e.g GET, POST) Default: POST
  -l LOG, --log LOG     Specify a log file
  -q, --quiet           Quiet mode will only log issues found
  -t TIMEOUT, --timeout TIMEOUT
                        Socket timeout value Default: 5
  --no-color            Suppress color codes
  -c CONFIGFILE, --configfile CONFIGFILE
                        Filepath to the configuration file of payloads
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)
  --cookies COOKIES     Custom cookies to include in all requests (e.g., 'sessionid=abc123; csrftoken=xyz789')
  -r REQUEST, --request REQUEST
                        File containing raw HTTP request to use as template
  --replay              Replay the request file continuously until stopped (Ctrl+C)
  --baseline-request BASELINE_REQUEST
                        File containing normal HTTP request for baseline comparison in replay mode
  --persistent-connection
                        Use a single persistent TCP connection for all requests instead of creating new connections
```

Smuggler at a minimum requires either a URL via the -u/--url argument, a request file via -r/--request, or a list of URLs piped into the script via stdin.
If the URL specifies `https://` then Smuggler will connect to the host:port using SSL/TLS. If the URL specifies `http://`
then no SSL/TLS will be used at all. If only the host is specified, then the script will default to `https://`

When using a request file (-r/--request), Smuggler will automatically extract the target host, method, endpoint, and cookies from the file, making it easy to test with your own custom requests.

Use -v/--vhost \<host> to specify a different host header from the server address

Use -x/--exit_early to exit the scan of a given server when a potential issue is found. In piped mode smuggler will just continue to the next host on the list

Use -m/--method \<method> to specify a different HTTP verb from POST (i.e GET/PUT/PATCH/OPTIONS/CONNECT/TRACE/DELETE/HEAD/etc...)

Use -l/--log \<file> to write output to file as well as stdout

Use -q/--quiet reduce verbosity and only log issues found

Use -t/--timeout \<value> to specify the socket timeout. The value should be high enough to conclude that the socket is hanging, but low enough to speed up testing (default: 5)

Use --no-color to suppress the output color codes printed to stdout (logs by default don't include color codes)

Use -c/--configfile \<configfile> to specify your smuggler mutation configuration file (default: default.py)

## New Features

### Custom Request Files
Use -r/--request \<file> to specify a file containing a raw HTTP request to use as a template. This allows you to test with your own custom headers, cookies, and request structure. The tool will automatically extract the host, method, endpoint, and cookies from the request file.

### Replay Mode
Use --replay to continuously replay a request file until stopped (Ctrl+C). This is useful for:
- Testing desync vulnerabilities in real-time
- Monitoring for desync issues during development
- Performance testing with custom requests

When using replay mode, you can also specify --baseline-request \<file> to send a normal request immediately after each smuggling POC request for comparison.

### Proxy Support
Use --proxy \<url> to route traffic through a proxy. Supports HTTP proxies using the CONNECT method. Example: `--proxy http://127.0.0.1:8080`

### Custom Cookies
Use --cookies \<cookies> to specify custom cookies that will be included in all requests. Example: `--cookies "sessionid=abc123; csrftoken=xyz789"`

### Persistent Connections
Use --persistent-connection to use a single TCP connection for all requests instead of creating new connections for each test. This can improve performance and better simulate real-world scenarios.

## Config Files
Configuration files are python files that exist in the ./config directory of smuggler. These files describe the content of the HTTP requests and the transfer-encoding mutations to test.


Here is example content of default.py:
```python
def render_template(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	# p.header += "Transfer-Encoding: chunked" +RN	
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p


mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["tabprefix2"] = render_template("Transfer-Encoding\t:\tchunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")

for i in [0x1,0x4,0x8,0x9,0xa,0xb,0xc,0xd,0x1F,0x20,0x7f,0xA0,0xFF]:
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	mutations["xprespace-%02x"%i] = render_template("X: X%cTransfer-Encoding: chunked"%(i))
	mutations["endspacex-%02x"%i] = render_template("Transfer-Encoding: chunked%cX: X"%(i))
	mutations["rxprespace-%02x"%i] = render_template("X: X\r%cTransfer-Encoding: chunked"%(i))
	mutations["xnprespace-%02x"%i] = render_template("X: X%c\nTransfer-Encoding: chunked"%(i))
	mutations["endspacerx-%02x"%i] = render_template("Transfer-Encoding: chunked\r%cX: X"%(i))
	mutations["endspacexn-%02x"%i] = render_template("Transfer-Encoding: chunked%c\nX: X"%(i))
```

There are no input arguments yet on specifying your own customer headers and user-agents. It is recommended to create your own configuration file based on default.py and modify it to your liking.

Smuggler comes with 3 configuration files: default.py (fast), doubles.py (niche, slow), exhaustive.py (very slow)
default.py is the fastest because it contains less mutations.

specify configuration files using the -c/--configfile \<configfile> command line option

## Payloads Directory
Inside the Smuggler directory is the payloads directory. When Smuggler finds a potential CLTE or TECL desync issue, it will automatically dump a binary txt file of the problematic payload in the payloads directory. All payload filenames are annotated with the hostname, desync type and mutation type. Use these payloads to netcat directly to the server or to import into other analysis tools.

## Detection Capability Matrix

The table below maps each attack class to the scanner that implements it,
its oracle type, and the confidence you can place in a positive finding.

| Attack class | Scanner (`--scan-type`) | Oracle | Confidence |
| --- | --- | --- | --- |
| TE.CL / CL.TE | `tecl`, `clte` (default) | Timing anomaly + positive gadget-smuggle probe (uses the dynamic `GadgetOracle` -- see below) | High when both signals fire; medium on timing alone |
| CL.0 / 0.CL | `cl0` | Pipelined victim request observes the smuggled gadget; tries the user's method + GET + POST | High (3-of-5 confirmations required) |
| TE.0 | `te0` | Pipelined victim request observes the smuggled gadget after a zero-chunk terminator | High (3-of-5) |
| Bare-LF / Bare-CR chunked | `bare-lf` | Pipelined victim observes the smuggled prefix when chunk framing uses bare LF/CR | High (3-of-5) |
| Pause-based desync | `pause` | Send headers, pause N s, send body; pipelined victim observes smuggled prefix | Medium-high (2-of-3); pause length tunable with `--pause-timeout` |
| Connection-state attack | `connection-state` | Pipelined `bad-Host` request returns a different status than a same request on a fresh connection | Medium; confirmed via second pipeline |
| Parser discrepancy | `parser-discrepancy` | Per-technique control + canary probe; only flags when the technique alone matches baseline but the canary diverges | Medium-high (now resistant to malformed-technique false positives) |
| Header removal (Keep-Alive) | `header-removal` | Matched-pair comparison of harmless vs attack request; requires 3 of 5 reproducible divergences | Medium-high |
| Expect-based desync | `expect` | Multiple Expect variants pipelined with a victim; same gadget oracle as CL.0 | High when confirmed |
| Hop-by-hop auth bypass | `hop-by-hop` | Baseline vs `Connection: <header>` probe; status flip confirmed 2-of-3 | High when reproducible |
| HTTP/2 downgrade | `h2` (or `--http2`) | Sends the H2 attack stream, then opens a parallel H1 connection and checks whether the victim received the gadget response | High (was previously low/wrong - see "HTTP/2 oracle" below) |

### Dynamic gadget oracle

Every gadget-based scanner (`tecl`/`clte`, `cl0`, `te0`, `bare-lf`,
`expect`, `pause`) shares a single per-target `GadgetOracle`
(`lib/Oracle.py`). On the first call it walks a candidate catalogue --
`OPTIONS *`, `OPTIONS /`, a randomized 404 probe, `/robots.txt`,
`/favicon.ico`, `/sitemap.xml`, and a query-reflection probe -- picks
the first response that successfully diverges from a baseline of the
real target endpoint, and auto-derives a `look_for` signature using
(in priority order):

1. **Per-run canary reflection.** The oracle injects a random token
   (`smug=<8-char-canary>`) into the gadget URL where the gadget
   supports a query string. If the response reflects the token, that
   token is the signature -- no chance of accidental collision.
2. **Status-code divergence.** When the gadget returns a different
   status than the baseline (e.g. gadget=`200`, baseline=`404`), the
   signature becomes `HTTP/1.1<code>`, matched header-only.
3. **Distinctive response header.** A header name present in the gadget
   response but absent from baseline (`Allow:`, `Last-Modified:`, etc.)
   becomes the signature.
4. **Body n-gram diff.** Failing the above, the longest printable
   8-byte-or-greater token unique to the gadget body is selected.
5. **Static fallback.** The candidate's hard-coded literal (e.g.
   `"llow:"` for `/robots.txt`) is used only when every other
   derivation fails.

In addition, every signature includes `HTTP/1.1 405` as an alternate so
the classic *"smuggled request reached the backend but was rejected"*
tell still fires. The selected gadget is cached for the rest of the
scan run; the probe cost (4-6 small GETs) is paid once.

This replaces the previous hard-coded `GET /robots.txt` + `"llow:"`
pair, which silently failed on targets that:

- don't serve `/robots.txt`
- route `/robots.txt` to a different upstream than the target endpoint
- strip the `Disallow:` line at the edge
- happen to have `"llow:"` in their normal response (`allow:` CSP
  directives, Bootstrap CSS, etc.) -- which manifested as a false
  positive

When no candidate is viable (target completely unreachable, all probes
returning 5xx) the scanners transparently fall back to the legacy pair
so behavior never regresses below the prior baseline.

### HTTP/2 oracle

Earlier versions inspected the H2 response stream itself for gadget tokens
(`llow:`, `robots`). That cannot work in principle: a smuggled HTTP/1.1
prefix only manifests on the *backend's next request*, never on the H2
stream that carried it. The current implementation sends a follow-up H1
victim request on a parallel connection and only flags when the victim
response leaks the gadget. This eliminates a large class of both false
positives (matched on benign body text) and false negatives (real desyncs
that produced an innocuous H2 response).

### Caveat for `--persistent-connection`

When this flag is set, an anomalous mutation will reset the persistent
TCP connection automatically (any timeout, disconnect, or socket error
forces a reconnect). This stops the previous bug where a desync on
mutation N produced cascading false positives on mutation N+1.

## Tests

The `tests/` directory now contains a unit-test harness in addition to
example request files:

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

`tests/mock_server.py` provides a pluggable HTTP/1.1 server that
simulates each HRS class; `tests/test_scans.py` runs positive + negative
cases against every advanced scanner; `tests/test_recv_multiple.py` and
`tests/test_replay_rewrite.py` are regression coverage for the response
splitter and the replay-mode request rewriter.

## Helper Scripts
After you find a desync issue feel free to use my Turbo Intruder desync scripts found Here: https://github.com/defparam/tiscripts
`DesyncAttack_CLTE.py` and `DesyncAttack_TECL.py` are great scripts to help stage a desync attack

## License
These scripts are released under the MIT license. See [LICENSE](https://github.com/l0lsec/smuggler/blob/master/LICENSE).
The original copyright (c) 2020 Evan Custodio is preserved.
