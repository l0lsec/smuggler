# NOTE: despite the filename, this config does NOT test HTTP/2. It is a small
# curated set of classic HTTP/1.1 Transfer-Encoding mutations (a subset of
# chunks.py) used by the TE.CL / CL.TE scan. For real HTTP/2 downgrade
# smuggling use `--http2` / `--scan-type h2`, which is handled by the dedicated
# scanner in lib/H2Scans.py and ignores `-c/--configfile`.

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

mutations["vanilla"] = render_template("Transfer-Encoding: chunked")
mutations["connection"] = render_template("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
mutations["dualchunk"] = render_template("Transfer-Encoding: chunked\r\nTransfer-encoding: identity")
mutations["revdualchunk"] = render_template("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
mutations["commaCow"] = render_template("Transfer-Encoding: chunked, cow")
mutations["cowComma"] = render_template("Transfer-Encoding: cow, chunked")

mutations["badsetupCR"] = render_template("Foo: bar\rTransfer-Encoding: chunked")
mutations["badsetupLF"] = render_template("Foo: bar\nTransfer-Encoding: chunked")
mutations["0dwrap"] = render_template("Foo: bar\r\n\rTransfer-Encoding: chunked")
mutations["bodysplit"] = render_template("Foo: bar\n\nTransfer-Encoding: chunked")
