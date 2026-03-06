#!/usr/bin/python3
# MIT License
# 
# Copyright (c) 2020 Evan Custodio
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import re
import time
import sys
import os
import random
import string
import importlib
import hashlib
import signal
import threading
from copy import deepcopy
from time import sleep
from datetime import datetime
from lib.Payload import Payload, Chunked, EndChunk, RawPayload
from lib.EasySSL import EasySSL
from lib.colorama import Fore, Style
from lib.Scans import ALL_SCANS, ScanCL0, ScanPauseDesync, ScanConnectionState, ScanParserDiscrepancy, ScanHeaderRemoval, ScanExpectDesync
from urllib.parse import urlparse

try:
	from lib.H2Scans import ScanH2Desync
	H2_SCAN_AVAILABLE = True
except ImportError:
	H2_SCAN_AVAILABLE = False

class Desyncr():
	def __init__(self, configfile, smhost, smport=443, url="", method="POST", endpoint="/",  SSLFlag=False, logh=None, smargs=None, custom_request=None):
		self._configfile = configfile
		self._host = smhost
		self._port = smport
		self._method = method
		self._endpoint = endpoint
		self._vhost = smargs.vhost
		self._url = url
		self._timeout = float(smargs.timeout)
		self.ssl_flag = SSLFlag
		self._logh = logh
		self._quiet = smargs.quiet
		self._exit_early = smargs.exit_early
		self._attempts = 0
		self._cookies = []
		self._proxy = getattr(smargs, 'proxy', None)
		self._custom_request = custom_request
		self._persistent_connection = getattr(smargs, 'persistent_connection', False)
		self._web_connection = None
		
		# Add cookies from custom request file if provided
		if custom_request and 'cookies' in custom_request and custom_request['cookies']:
			self._cookies.extend(custom_request['cookies'])
			info = ((Fore.CYAN + str(len(custom_request['cookies']))+ Fore.MAGENTA), self._logh)
			print_info("Cookies from request file: %s" % (info[0]))
		
		# Parse custom cookies from command line if provided (these will be added to request file cookies)
		if hasattr(smargs, 'cookies') and smargs.cookies:
			self._parse_custom_cookies(smargs.cookies)

	def _parse_custom_cookies(self, cookie_string):
		"""Parse custom cookies from command line argument and add to self._cookies"""
		try:
			# Split by semicolon and clean up each cookie
			cookies = [cookie.strip() for cookie in cookie_string.split(';') if cookie.strip()]
			# Add semicolon to each cookie if not present
			for cookie in cookies:
				if not cookie.endswith(';'):
					cookie += ';'
				self._cookies.append(cookie)
		except Exception as e:
			error = ((Fore.CYAN + "Error parsing cookies: " + str(e) + Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))

	def _establish_persistent_connection(self):
		"""Establish a persistent connection if enabled"""
		if self._persistent_connection and not self._web_connection:
			try:
				self._web_connection = EasySSL(self.ssl_flag)
				self._web_connection.connect(self._host, self._port, self._timeout, self._proxy, persistent=True)
				info = ((Fore.CYAN + "Persistent connection established"+ Fore.MAGENTA), self._logh)
				print_info("Connection : %s" % (info[0]))
			except Exception as e:
				error = ((Fore.CYAN + "Failed to establish persistent connection: " + str(e) + Fore.MAGENTA), self._logh)
				print_info("Error      : %s" % (error[0]))
				self._web_connection = None

	def _close_persistent_connection(self):
		"""Close the persistent connection if it exists"""
		if self._web_connection:
			try:
				self._web_connection.close()
				self._web_connection = None
			except Exception as e:
				error = ((Fore.CYAN + "Error closing persistent connection: " + str(e) + Fore.MAGENTA), self._logh)
				print_info("Error      : %s" % (error[0]))

	def _test(self, payload_obj):
		try:
			# Use persistent connection if available, otherwise create a new one
			if self._persistent_connection and self._web_connection:
				web = self._web_connection
			else:
				web = EasySSL(self.ssl_flag)
				web.connect(self._host, self._port, self._timeout, self._proxy)
			
			web.send(str(payload_obj).encode())
			#print(payload_obj)
			start_time = datetime.now()
			res = web.recv_nb(self._timeout)
			end_time = datetime.now()
			
			# Only close if not using persistent connection
			if not self._persistent_connection:
				web.close()
			
			if res is None:
				delta_time = end_time - start_time
				if delta_time.seconds < (self._timeout-1):
					return (2, res, payload_obj) # Return code 2 if disconnected before timeout
				return (1, res, payload_obj) # Return code 1 if connection timedout
			# Filter out problematic characters
			res_filtered = ""
			for single in res:
				if single > 0x7F:
					res_filtered += '\x30'
				else:
					res_filtered += chr(single)
			res = res_filtered
			#if '504' in res:
			
			#print("\n\n"+str(str(payload_obj)))
			#print("\n\n"+res)
			return (0, res, payload_obj) # Return code 0 if normal response returned
		except Exception as exception_data:
			#print(exception_data)
			return (-1, None, payload_obj) # Return code -1 if some except occured
		
	def _get_cookies(self):
		RN = "\r\n"
		
		# If cookies were provided via custom request file, skip automatic cookie fetching
		if self._custom_request and 'cookies' in self._custom_request and self._custom_request['cookies']:
			info = ((Fore.CYAN + "Using cookies from request file"+ Fore.MAGENTA), self._logh)
			print_info("Cookies    : %s" % (info[0]))
			return True
		
		try:
			cookies = []
			web = EasySSL(self.ssl_flag)
			web.connect(self._host, self._port, 2.0, self._proxy)
			
			# Use default request for cookie retrieval
			p = Payload()
			p.host = self._host
			p.method = "GET"
			p.endpoint = self._endpoint
			p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
			p.header += "Host: __HOST__" + RN
			p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
			p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
			p.header += "Content-Length: 0" + RN
			p.body = ""
			#print (str(p))
			web.send(str(p).encode())
			
			sleep(0.5)
			res = web.recv_nb(2.0)
			web.close()
			if (res is not None):
				res = res.decode().split("\r\n")
				for elem in res:
					if len(elem) > 11:
						if elem[0:11].lower().replace(" ", "") == "set-cookie:":
							cookie = elem.lower().replace("set-cookie:","")
							cookie = cookie.split(";")[0] + ';'
							cookies += [cookie]
				info = ((Fore.CYAN + str(len(cookies))+ Fore.MAGENTA), self._logh)
				print_info("Cookies    : %s (Appending to the attack)" % (info[0]))
				self._cookies += cookies
			return True
		except Exception as exception_data:
			error = ((Fore.CYAN + "Unable to connect to host"+ Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))
			return False

	def run(self):
		RN = "\r\n"
		mutations = {}
		
		# Establish persistent connection if enabled
		if self._persistent_connection:
			self._establish_persistent_connection()
		
		if not self._get_cookies():
			return
			
		if (self._configfile[1] != '/'):
			self._configfile = os.path.dirname(os.path.realpath(__file__)) + "/configs/" + self._configfile

		try:
			f = open(self._configfile)
		except:
			error = ((Fore.CYAN + "Cannot find config file"+ Fore.MAGENTA), self._logh)
			print_info("Error      : %s" % (error[0]))
			exit(1)
			
		script = f.read()
		f.close()
		
		exec(script)
			
		for mutation_name in mutations.keys():
			if self._create_exec_test(mutation_name, mutations[mutation_name]) and self._exit_early:
				break
		
		if self._quiet:
			sys.stdout.write("\r"+" "*100+"\r")
		
		# Close persistent connection if it was established
		if self._persistent_connection:
			self._close_persistent_connection()

	def run_advanced_scans(self, scan_types, pause_timeout=61):
		def adv_print(name, msg):
			spacing = 13
			sys.stdout.write("\r"+" "*100+"\r")
			full_msg = Style.BRIGHT + Fore.MAGENTA + "[%s]%s: %s" % \
				(Fore.CYAN + name + Fore.MAGENTA, " "*(spacing-len(name)),
				 Fore.YELLOW + msg)
			sys.stdout.write(CF(full_msg + Style.RESET_ALL))
			sys.stdout.flush()
			print()
			if self._logh is not None:
				ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
				plaintext = ansi_escape.sub('', full_msg)
				self._logh.write(plaintext + "\n")
				self._logh.flush()

		def adv_write(smhost, payload, ptype):
			furl = smhost.replace('.', '_')
			if self.ssl_flag:
				furl = "https_" + furl
			else:
				furl = "http_" + furl
			if os.path.islink(sys.argv[0]):
				_me = os.readlink(sys.argv[0])
			else:
				_me = sys.argv[0]
			fname = os.path.realpath(os.path.dirname(_me)) + "/payloads/%s_%s.txt" % (furl, ptype)
			adv_print("CRITICAL", "%s Payload: %s URL: %s" % \
				(Fore.MAGENTA + ptype, Fore.CYAN + fname + Fore.MAGENTA, Fore.CYAN + self._url))
			with open(fname, 'wb') as file:
				if isinstance(payload, RawPayload):
					file.write(payload.to_bytes())
				else:
					file.write(bytes(str(payload), 'utf-8'))

		if not self._get_cookies():
			return

		vhost = self._vhost if self._vhost else self._host

		scan_map = {
			"cl0": ScanCL0,
			"pause": ScanPauseDesync,
			"connection-state": ScanConnectionState,
			"parser-discrepancy": ScanParserDiscrepancy,
			"header-removal": ScanHeaderRemoval,
			"expect": ScanExpectDesync,
		}

		for scan_name in scan_types:
			if scan_name == "h2":
				if H2_SCAN_AVAILABLE:
					scanner = ScanH2Desync(
						self._host, self._port, self.ssl_flag, self._timeout,
						self._method, self._endpoint, vhost, self._proxy,
						self._logh, self._quiet, self._cookies
					)
					scanner.run(adv_print, adv_write)
				else:
					adv_print("H2", "HTTP/2 scanning requires the h2 library (pip install h2)")
				continue

			if scan_name not in scan_map:
				adv_print("Error", "Unknown scan type: %s" % scan_name)
				continue

			scan_cls = scan_map[scan_name]
			if scan_name == "pause":
				scanner = scan_cls(
					self._host, self._port, self.ssl_flag, self._timeout,
					self._method, self._endpoint, vhost, self._proxy,
					self._logh, self._quiet, self._cookies, pause_timeout
				)
			else:
				scanner = scan_cls(
					self._host, self._port, self.ssl_flag, self._timeout,
					self._method, self._endpoint, vhost, self._proxy,
					self._logh, self._quiet, self._cookies
				)
			scanner.run(adv_print, adv_write)

	# ptype == 0 (Attack payload, timeout could mean potential TECL desync)
	# ptype == 1 (Edgecase payload, expected to work)
	def _check_tecl(self, payload, ptype=0):
		te_payload = deepcopy(payload)
		if (self._vhost == ""):
			te_payload.host = self._host
		else:
			te_payload.host = self._vhost
		te_payload.method = self._method
		te_payload.endpoint = self._endpoint
		
		if len(self._cookies) > 0:
			te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
		
		if not ptype:
			te_payload.cl = 6 # timeout val == 6, good value == 5
		else:
			te_payload.cl = 5 # timeout val == 6, good value == 5
		te_payload.body = EndChunk+"X"
		#print (te_payload)
		return self._test(te_payload)

	# ptype == 0 (timeout payload, timeout could mean potential CLTE desync)
	# ptype == 1 (Edgecase payload, expected to work)
	def _check_clte(self, payload, ptype=0):
		te_payload = deepcopy(payload)
		if (self._vhost == ""):
			te_payload.host = self._host
		else:
			te_payload.host = self._vhost
		te_payload.method = self._method
		te_payload.endpoint = self._endpoint
		
		if len(self._cookies) > 0:
			te_payload.header += "Cookie: " + ''.join(self._cookies) + "\r\n"
			
		if not ptype:
			te_payload.cl = 4 # timeout val == 4, good value == 11
		else:
			te_payload.cl = 11 # timeout val == 4, good value == 11
		te_payload.body = Chunked("Z")+EndChunk
		#print (te_payload)
		return self._test(te_payload)


	def _create_exec_test(self, name, te_payload):
		def pretty_print(name, dismsg):
			spacing = 13
			sys.stdout.write("\r"+" "*100+"\r")
			msg = Style.BRIGHT + Fore.MAGENTA + "[%s]%s: %s" % \
			(Fore.CYAN + name + Fore.MAGENTA, " "*(spacing-len(name)), dismsg)
			sys.stdout.write(CF(msg + Style.RESET_ALL))
			sys.stdout.flush()

			if dismsg[-1] == "\n":
				ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
				plaintext = ansi_escape.sub('', msg)
				if self._logh is not None:
					self._logh.write(plaintext)
					self._logh.flush()


		def write_payload(smhost, payload, ptype):
			furl = smhost.replace('.', '_')
			if (self.ssl_flag):
				furl = "https_" + furl
			else:
				furl = "http_" + furl
			if os.path.islink(sys.argv[0]):
				_me = os.readlink(sys.argv[0])
			else:
				_me = sys.argv[0]
			fname = os.path.realpath(os.path.dirname(_me)) + "/payloads/%s_%s_%s.txt" % (furl,ptype,name)
			pretty_print("CRITICAL", "%s Payload: %s URL: %s\n" % \
			(Fore.MAGENTA+ptype, Fore.CYAN+fname+Fore.MAGENTA, Fore.CYAN+self._url))
			with open(fname, 'wb') as file:
				file.write(bytes(str(payload),'utf-8'))

		# First lets test TECL
		pretty_print(name, "Checking TECL...")
		start_time = time.time()
		tecl_res = self._check_tecl(te_payload, 0)
		tecl_time = time.time()-start_time

		# Next lets test CLTE
		pretty_print(name, "Checking CLTE...")
		start_time = time.time()
		clte_res = self._check_clte(te_payload, 0)
		clte_time = time.time()-start_time

		if (clte_res[0] == 1):
			# Potential CLTE found
			# Lets check the edge case to be sure
			clte_res2 = self._check_clte(te_payload, 1)
			if clte_res2[0] == 0:
				self._attempts += 1
				if (self._attempts < 3):
					return self._create_exec_test(name, te_payload)
				else:
					dismsg = Fore.RED + "Potential CLTE Issue Found" + Fore.MAGENTA + " - " + Fore.CYAN + self._method + Fore.MAGENTA + " @ " + Fore.CYAN + ["http://","https://",][self.ssl_flag]+ self._host + self._endpoint + Fore.MAGENTA + " - " + Fore.CYAN + self._configfile.split('/')[-1] + "\n"
					pretty_print(name, dismsg)
					
					# Write payload out to file
					write_payload(self._host, clte_res[2], "CLTE")
					self._attempts = 0
					return True

			else:
				# No edge behavior found
				dismsg = Fore.YELLOW + "CLTE TIMEOUT ON BOTH LENGTH 4 AND 11" + ["\n", ""][self._quiet]
				pretty_print(name, dismsg)

		elif (tecl_res[0] == 1):
			# Potential TECL found
			# Lets check the edge case to be sure
			tecl_res2 = self._check_tecl(te_payload, 1)
			if tecl_res2[0] == 0:
				self._attempts += 1
				if (self._attempts < 3):
					return self._create_exec_test(name, te_payload)
				else:
					#print (str(tecl_res2[2]))
					#print (tecl_res2[1])
					dismsg = Fore.RED + "Potential TECL Issue Found" + Fore.MAGENTA + " - " + Fore.CYAN + self._method + Fore.MAGENTA + " @ " + Fore.CYAN + ["http://","https://",][self.ssl_flag]+ self._host + self._endpoint + Fore.MAGENTA + " - " + Fore.CYAN + self._configfile.split('/')[-1] + "\n"
					pretty_print(name, dismsg)
					
					# Write payload out to file
					write_payload(self._host, tecl_res[2], "TECL")
					self._attempts = 0
					return True
			else:
				# No edge behavior found
				dismsg = Fore.YELLOW + "TECL TIMEOUT ON BOTH LENGTH 6 AND 5" + ["\n", ""][self._quiet]
				pretty_print(name, dismsg)


		#elif ((tecl_res[0] == 1) and (clte_res[0] == 1)):
		#	# Both types of payloads not supported
		#	dismsg = Fore.YELLOW + "NOT SUPPORTED" + ["\n", ""][self._quiet]
		#	pretty_print(name, dismsg)
		elif ((tecl_res[0] == -1) or (clte_res[0] == -1)):
			# ERROR
			dismsg = Fore.YELLOW + "SOCKET ERROR" + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)

		elif ((tecl_res[0] == 0) and (clte_res[0] == 0)):
			# No Desync Found
			tecl_msg = (Fore.MAGENTA + " (TECL: " + Fore.CYAN +"%.2f" + Fore.MAGENTA + " - " + \
			Fore.CYAN +"%s" + Fore.MAGENTA + ")") % (tecl_time, tecl_res[1][9:9+3])

			clte_msg = (Fore.MAGENTA + " (CLTE: " + Fore.CYAN +"%.2f" + Fore.MAGENTA + " - " + \
			Fore.CYAN +"%s" + Fore.MAGENTA + ")") % (clte_time, clte_res[1][9:9+3])

			dismsg = Fore.GREEN + "OK" + tecl_msg + clte_msg + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)

		elif ((tecl_res[0] == 2) or (clte_res[0] == 2)):
			# Disconnected
			dismsg = Fore.YELLOW + "DISCONNECTED" + ["\n", ""][self._quiet]
			pretty_print(name, dismsg)
			
		self._attempts = 0
		return False

class ReplayManager():
	def __init__(self, custom_request, host, port, ssl_flag, timeout, proxy=None, logh=None, baseline_request=None, persistent_connection=False):
		self.custom_request = custom_request
		self.baseline_request = baseline_request
		self.host = host
		self.port = port
		self.ssl_flag = ssl_flag
		self.timeout = timeout
		self.proxy = proxy
		self.logh = logh
		self.persistent_connection = persistent_connection
		self.web_connection = None
		self.stats = {
			'total_requests': 0,
			'successful_requests': 0,
			'failed_requests': 0,
			'timeout_requests': 0,
			'error_requests': 0,
			'baseline_requests': 0,
			'baseline_successful': 0,
			'baseline_failed': 0,
			'baseline_timeout': 0,
			'baseline_error': 0,
			'start_time': None,
			'last_request_time': None
		}
		self.running = False
		self.request_id = 0
		self.baseline_response = None
		
	def generate_request_id(self):
		"""Generate a unique identifier for each request"""
		self.request_id += 1
		timestamp = int(time.time() * 1000)  # milliseconds
		return f"REQ-{timestamp}-{self.request_id:06d}"
	
	def establish_persistent_connection(self):
		"""Establish a persistent connection if enabled"""
		if self.persistent_connection and not self.web_connection:
			try:
				self.web_connection = EasySSL(self.ssl_flag)
				self.web_connection.connect(self.host, self.port, self.timeout, self.proxy, persistent=True)
				print_info("Persistent connection established for replay mode")
			except Exception as e:
				print_info(f"Failed to establish persistent connection: {e}")
				self.web_connection = None
				# Disable persistent connection if it fails
				self.persistent_connection = False

	def close_persistent_connection(self):
		"""Close the persistent connection if it exists"""
		if self.web_connection:
			try:
				self.web_connection.close()
				self.web_connection = None
			except Exception as e:
				print_info(f"Error closing persistent connection: {e}")
	
	def send_request(self, request_id):
		"""Send a single request and return the result"""
		try:
			# Use persistent connection if available, otherwise create a new one
			if self.persistent_connection and self.web_connection:
				web = self.web_connection
				# Check if connection is still valid
				if not hasattr(web, 'connected') or not web.connected:
					# Connection is not valid, try to re-establish
					self.establish_persistent_connection()
					if self.web_connection:
						web = self.web_connection
					else:
						# Fall back to new connection
						web = EasySSL(self.ssl_flag)
						web.connect(self.host, self.port, self.timeout, self.proxy)
			else:
				web = EasySSL(self.ssl_flag)
				web.connect(self.host, self.port, self.timeout, self.proxy)
			
			# Build the request with unique identifier
			request_data = self.build_request_with_id(request_id)
			web.send(request_data.encode())
			
			start_time = datetime.now()
			res = web.recv_nb(self.timeout)
			end_time = datetime.now()
			
			# Only close if not using persistent connection
			if not self.persistent_connection:
				web.close()
			
			self.stats['total_requests'] += 1
			self.stats['last_request_time'] = end_time
			
			if res is None:
				delta_time = end_time - start_time
				if delta_time.seconds < (self.timeout - 1):
					self.stats['failed_requests'] += 1
					return (2, res, request_id)  # Disconnected
				else:
					self.stats['timeout_requests'] += 1
					return (1, res, request_id)  # Timeout
			else:
				self.stats['successful_requests'] += 1
				return (0, res, request_id)  # Success
				
		except Exception as e:
			self.stats['error_requests'] += 1
			# If using persistent connection and we get an error, try to reset it
			if self.persistent_connection and self.web_connection:
				try:
					self.web_connection.close()
					self.web_connection = None
				except:
					pass
				# Try to re-establish connection
				self.establish_persistent_connection()
			return (-1, None, request_id)  # Error
	
	def send_baseline_request(self, request_id):
		"""Send a baseline request and return the result"""
		if not self.baseline_request:
			return None
			
		try:
			# Use persistent connection if available, otherwise create a new one
			if self.persistent_connection and self.web_connection:
				web = self.web_connection
				# Check if connection is still valid
				if not hasattr(web, 'connected') or not web.connected:
					# Connection is not valid, try to re-establish
					self.establish_persistent_connection()
					if self.web_connection:
						web = self.web_connection
					else:
						# Fall back to new connection
						web = EasySSL(self.ssl_flag)
						web.connect(self.host, self.port, self.timeout, self.proxy)
			else:
				web = EasySSL(self.ssl_flag)
				web.connect(self.host, self.port, self.timeout, self.proxy)
			
			# Build the baseline request with unique identifier
			request_data = self.build_baseline_request_with_id(request_id)
			web.send(request_data.encode())
			
			start_time = datetime.now()
			res = web.recv_nb(self.timeout)
			end_time = datetime.now()
			
			# Only close if not using persistent connection
			if not self.persistent_connection:
				web.close()
			
			self.stats['baseline_requests'] += 1
			
			if res is None:
				delta_time = end_time - start_time
				if delta_time.seconds < (self.timeout - 1):
					self.stats['baseline_failed'] += 1
					return (2, res, request_id)  # Disconnected
				else:
					self.stats['baseline_timeout'] += 1
					return (1, res, request_id)  # Timeout
			else:
				self.stats['baseline_successful'] += 1
				return (0, res, request_id)  # Success
				
		except Exception as e:
			self.stats['baseline_error'] += 1
			# If using persistent connection and we get an error, try to reset it
			if self.persistent_connection and self.web_connection:
				try:
					self.web_connection.close()
					self.web_connection = None
				except:
					pass
				# Try to re-establish connection
				self.establish_persistent_connection()
			return (-1, None, request_id)  # Error
	
	def build_request_with_id(self, request_id):
		"""Build the HTTP request with unique identifier injected as URL parameters"""
		# Get the raw content and split into lines
		lines = self.custom_request['raw'].split('\n')
		
		# Find the first request line (starts with HTTP method)
		first_request_line_idx = 0
		for i, line in enumerate(lines):
			line_stripped = line.strip()
			if line_stripped and ' ' in line_stripped:
				parts = line_stripped.split(' ')
				if len(parts) >= 2 and parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
					first_request_line_idx = i
					break
		
		# Get the first request line
		request_line = lines[first_request_line_idx].strip()
		
		# Extract method, endpoint, and HTTP version
		request_parts = request_line.split(' ')
		method = request_parts[0]
		endpoint = request_parts[1]
		http_version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"
		
		# Add request ID and timestamp as URL parameters to the first request
		timestamp = int(time.time() * 1000)
		separator = '&' if '?' in endpoint else '?'
		modified_endpoint = f"{endpoint}{separator}request_id={request_id}&timestamp={timestamp}"
		
		# Build the modified request line
		modified_request_line = f"{method} {modified_endpoint} {http_version}"
		
		# Rebuild the entire request with the modified first line
		modified_lines = lines.copy()
		modified_lines[first_request_line_idx] = modified_request_line
		
		# Convert back to string and ensure proper line endings
		modified_request = '\n'.join(modified_lines)
		
		# Convert \n to \r\n for proper HTTP format
		modified_request = modified_request.replace('\n', '\r\n')
		
		return modified_request
	
	def build_baseline_request_with_id(self, request_id):
		"""Build the baseline HTTP request with unique identifier injected as URL parameters"""
		# Get the raw content and split into lines
		lines = self.baseline_request['raw'].split('\n')
		
		# Find the first request line (starts with HTTP method)
		first_request_line_idx = 0
		for i, line in enumerate(lines):
			line_stripped = line.strip()
			if line_stripped and ' ' in line_stripped:
				parts = line_stripped.split(' ')
				if len(parts) >= 2 and parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
					first_request_line_idx = i
					break
		
		# Get the first request line
		request_line = lines[first_request_line_idx].strip()
		
		# Extract method, endpoint, and HTTP version
		request_parts = request_line.split(' ')
		method = request_parts[0]
		endpoint = request_parts[1]
		http_version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"
		
		# Add request ID and timestamp as URL parameters to the first request
		timestamp = int(time.time() * 1000)
		separator = '&' if '?' in endpoint else '?'
		modified_endpoint = f"{endpoint}{separator}baseline_id={request_id}&timestamp={timestamp}"
		
		# Build the modified request line
		modified_request_line = f"{method} {modified_endpoint} {http_version}"
		
		# Rebuild the entire request with the modified first line
		modified_lines = lines.copy()
		modified_lines[first_request_line_idx] = modified_request_line
		
		# Convert back to string and ensure proper line endings
		modified_request = '\n'.join(modified_lines)
		
		# Convert \n to \r\n for proper HTTP format
		modified_request = modified_request.replace('\n', '\r\n')
		
		return modified_request
	
	def compare_responses(self, smuggled_response, baseline_response):
		"""Compare smuggled response with baseline response and return differences"""
		if not baseline_response or not smuggled_response:
			return "No baseline response to compare"
		
		# Filter out problematic characters from both responses
		def filter_response(res):
			if res is None:
				return ""
			filtered = ""
			for single in res:
				if single > 0x7F:
					filtered += '\x30'
				else:
					filtered += chr(single)
			return filtered
		
		smuggled_filtered = filter_response(smuggled_response)
		baseline_filtered = filter_response(baseline_response)
		
		# Compare status codes
		smuggled_status = smuggled_filtered[9:12] if len(smuggled_filtered) > 12 else "N/A"
		baseline_status = baseline_filtered[9:12] if len(baseline_filtered) > 12 else "N/A"
		
		# Compare response lengths
		smuggled_length = len(smuggled_filtered)
		baseline_length = len(baseline_filtered)
		
		differences = []
		if smuggled_status != baseline_status:
			differences.append(f"Status: {baseline_status} -> {smuggled_status}")
		if smuggled_length != baseline_length:
			differences.append(f"Length: {baseline_length} -> {smuggled_length}")
		
		# Check for content differences (simplified comparison)
		if smuggled_filtered != baseline_filtered:
			differences.append("Content differs")
		
		return "; ".join(differences) if differences else "Responses match"
	
	def display_stats(self):
		"""Display current statistics"""
		if self.stats['start_time']:
			elapsed = datetime.now() - self.stats['start_time']
			elapsed_seconds = elapsed.total_seconds()
			requests_per_second = self.stats['total_requests'] / elapsed_seconds if elapsed_seconds > 0 else 0
		else:
			elapsed_seconds = 0
			requests_per_second = 0
		
		# Clear line and display stats
		sys.stdout.write("\r" + " " * 100 + "\r")
		stats_msg = (Style.BRIGHT + Fore.CYAN + "[REPLAY] " + 
					Fore.MAGENTA + "Total: " + Fore.GREEN + str(self.stats['total_requests']) + 
					Fore.MAGENTA + " | Success: " + Fore.GREEN + str(self.stats['successful_requests']) +
					Fore.MAGENTA + " | Failed: " + Fore.RED + str(self.stats['failed_requests']) +
					Fore.MAGENTA + " | Timeout: " + Fore.YELLOW + str(self.stats['timeout_requests']) +
					Fore.MAGENTA + " | Error: " + Fore.RED + str(self.stats['error_requests']))
		
		# Add baseline stats if baseline requests are being sent
		if self.baseline_request:
			stats_msg += (Fore.MAGENTA + " | Baseline: " + Fore.GREEN + str(self.stats['baseline_successful']) +
						Fore.MAGENTA + "/" + Fore.RED + str(self.stats['baseline_requests']))
		
		stats_msg += (Fore.MAGENTA + " | RPS: " + Fore.CYAN + f"{requests_per_second:.2f}" +
					Fore.MAGENTA + " | ID: " + Fore.CYAN + f"REQ-{self.request_id:06d}" + Style.RESET_ALL)
		
		sys.stdout.write(CF(stats_msg))
		sys.stdout.flush()
	
	def run_replay(self):
		"""Run the continuous replay loop"""
		if not self.custom_request:
			print_info("Error: No request file provided for replay mode")
			return
		
		# Establish persistent connection if enabled
		if self.persistent_connection:
			self.establish_persistent_connection()
		
		self.running = True
		self.stats['start_time'] = datetime.now()
		
		print_info("Starting continuous replay mode... Press Ctrl+C to stop")
		print_info("Target: %s" % (Fore.CYAN + f"{'https' if self.ssl_flag else 'http'}://{self.host}:{self.port}"))
		print_info("Request: %s" % (Fore.CYAN + f"{self.custom_request['method']} {self.custom_request['endpoint']}"))
		if self.baseline_request:
			print_info("Baseline: %s" % (Fore.CYAN + f"{self.baseline_request['method']} {self.baseline_request['endpoint']}"))
		
		try:
			while self.running:
				request_id = self.generate_request_id()
				
				# Send the smuggling POC request
				result = self.send_request(request_id)
				
				# Send baseline request after smuggling request if baseline is configured
				baseline_result = None
				if self.baseline_request:
					# Add a small delay between requests when using persistent connection
					if self.persistent_connection:
						time.sleep(0.01)  # 10ms delay between requests
					baseline_result = self.send_baseline_request(request_id)
					
					# Compare responses if both were successful
					if result[0] == 0 and baseline_result and baseline_result[0] == 0:
						comparison = self.compare_responses(result[1], baseline_result[1])
						if "differs" in comparison or "->" in comparison:
							# Log significant differences
							print_info("Response difference detected: %s" % (Fore.YELLOW + comparison))
				
				# Display stats every request
				self.display_stats()
				
				# Small delay to prevent overwhelming the server
				time.sleep(0.1)
				
		except KeyboardInterrupt:
			self.running = False
			print_info("\nReplay stopped by user")
			self.display_final_stats()
		except Exception as e:
			self.running = False
			print_info(f"\nReplay stopped due to error: {e}")
			self.display_final_stats()
		finally:
			# Close persistent connection if it was established
			if self.persistent_connection:
				self.close_persistent_connection()
	
	def display_final_stats(self):
		"""Display final statistics when replay stops"""
		if self.stats['start_time']:
			elapsed = datetime.now() - self.stats['start_time']
			elapsed_seconds = elapsed.total_seconds()
			requests_per_second = self.stats['total_requests'] / elapsed_seconds if elapsed_seconds > 0 else 0
		else:
			elapsed_seconds = 0
			requests_per_second = 0
		
		print_info("=" * 60)
		print_info("REPLAY STATISTICS")
		print_info("=" * 60)
		print_info("Total Requests    : %s" % (Fore.CYAN + str(self.stats['total_requests'])))
		print_info("Successful        : %s" % (Fore.GREEN + str(self.stats['successful_requests'])))
		print_info("Failed            : %s" % (Fore.RED + str(self.stats['failed_requests'])))
		print_info("Timeouts          : %s" % (Fore.YELLOW + str(self.stats['timeout_requests'])))
		print_info("Errors            : %s" % (Fore.RED + str(self.stats['error_requests'])))
		
		# Add baseline statistics if baseline requests were sent
		if self.baseline_request and self.stats['baseline_requests'] > 0:
			print_info("")
			print_info("Baseline Requests : %s" % (Fore.CYAN + str(self.stats['baseline_requests'])))
			print_info("Baseline Success  : %s" % (Fore.GREEN + str(self.stats['baseline_successful'])))
			print_info("Baseline Failed   : %s" % (Fore.RED + str(self.stats['baseline_failed'])))
			print_info("Baseline Timeouts : %s" % (Fore.YELLOW + str(self.stats['baseline_timeout'])))
			print_info("Baseline Errors   : %s" % (Fore.RED + str(self.stats['baseline_error'])))
		
		print_info("Duration          : %s" % (Fore.CYAN + f"{elapsed_seconds:.2f} seconds"))
		print_info("Requests/Second   : %s" % (Fore.CYAN + f"{requests_per_second:.2f}"))
		if self.stats['last_request_time']:
			print_info("Last Request      : %s" % (Fore.CYAN + self.stats['last_request_time'].strftime("%Y-%m-%d %H:%M:%S")))
		print_info("=" * 60)

def parse_request_file(filepath):
	"""Parse an HTTP request from a file and return its components"""
	try:
		with open(filepath, 'r') as f:
			content = f.read()
		
		# Split headers and body
		parts = content.split('\r\n\r\n', 1)
		if len(parts) == 1:
			# Try with just \n\n
			parts = content.split('\n\n', 1)
		
		headers_section = parts[0]
		body = parts[1] if len(parts) > 1 else ""
		
		# Parse request line
		lines = headers_section.split('\n')
		request_line = lines[0].strip()
		request_parts = request_line.split(' ')
		
		if len(request_parts) < 3:
			raise ValueError("Invalid request line format")
		
		method = request_parts[0]
		endpoint = request_parts[1]
		
		# Parse headers to find Host and Cookie
		host = None
		cookies = []
		for line in lines[1:]:
			line_stripped = line.strip()
			if line_stripped.lower().startswith('host:'):
				host = line_stripped.split(':', 1)[1].strip()
			elif line_stripped.lower().startswith('cookie:'):
				# Extract cookie value
				cookie_value = line_stripped.split(':', 1)[1].strip()
				# The cookie value might already have semicolons, parse them
				if cookie_value:
					# Split by semicolon and clean up
					cookie_parts = [c.strip() for c in cookie_value.split(';') if c.strip()]
					for cookie in cookie_parts:
						if cookie and not cookie.endswith(';'):
							cookies.append(cookie + ';')
						elif cookie:
							cookies.append(cookie)
		
		return {
			'method': method,
			'endpoint': endpoint,
			'host': host,
			'cookies': cookies,
			'headers': headers_section,
			'body': body,
			'raw': content
		}
	except FileNotFoundError:
		print_info("Error: Request file not found: %s" % (Fore.CYAN + filepath))
		exit(1)
	except Exception as e:
		print_info("Error parsing request file: %s" % (Fore.CYAN + str(e)))
		exit(1)

def process_uri(uri):
	u = urlparse(uri)

	if u.scheme == "https":
		ssl_flag = True
		std_port = 443
	elif u.scheme == "http":
		ssl_flag = False
		std_port = 80
	else:
		print_info("Error malformed URL not supported: %s" % (Fore.CYAN + uri))
		exit(1)

	if u.port:
		return (u.hostname, u.port, u.path, ssl_flag)
	else:
		return (u.hostname, std_port, u.path, ssl_flag)

def CF(text):
	global NOCOLOR
	if NOCOLOR:
		ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
		text = ansi_escape.sub('', text)
	return text

def banner(sm_version):
	print(CF(Fore.CYAN))
	print(CF(r"  ______                         _              "))
	print(CF(r" / _____)                       | |             "))
	print(CF(r"( (____  ____  _   _  ____  ____| | _____  ____ "))
	print(CF(r" \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)"))
	print(CF(r" _____) ) | | | |_| ( (_| ( (_| | || ____| |    "))
	print(CF(r"(______/|_|_|_|____/ \___ |\___ |\_)_____)_|    "))
	print(CF(r"                    (_____(_____|               "))
	print(CF(r""))
	print(CF(r"     @defparam                         %s"%(sm_version)))
	print(CF(Style.RESET_ALL))

def print_info(msg, file_handle=None):
	ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
	msg = Style.BRIGHT + Fore.MAGENTA + "[%s] %s"%(Fore.CYAN+'+'+Fore.MAGENTA, msg) + Style.RESET_ALL
	plaintext = ansi_escape.sub('', msg)
	print(CF(msg))
	if file_handle is not None:
		file_handle.write(plaintext+"\n")

if __name__ == "__main__":
	global NOCOLOR
	if sys.version_info < (3, 0):
		print("Error: Smuggler requires Python 3.x")
		sys.exit(1)

	Parser = argparse.ArgumentParser()
	Parser.add_argument('-u', '--url', help="Target URL with Endpoint")
	Parser.add_argument('-v', '--vhost', default="", help="Specify a virtual host")
	Parser.add_argument('-x', '--exit_early', action='store_true',help="Exit scan on first finding")
	Parser.add_argument('-m', '--method', default="POST", help="HTTP method to use (e.g GET, POST) Default: POST")
	Parser.add_argument('-l', '--log', help="Specify a log file")
	Parser.add_argument('-q', '--quiet', action='store_true', help="Quiet mode will only log issues found")
	Parser.add_argument('-t', '--timeout', default=5.0, help="Socket timeout value Default: 5")
	Parser.add_argument('--no-color', action='store_true', help="Suppress color codes")
	Parser.add_argument('-c', '--configfile', default="default.py", help="Filepath to the configuration file of payloads")
	Parser.add_argument('--proxy', help="Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)")
	Parser.add_argument('--cookies', help="Custom cookies to include in all requests (e.g., 'sessionid=abc123; csrftoken=xyz789')")
	Parser.add_argument('-r', '--request', help="File containing raw HTTP request to use as template")
	Parser.add_argument('--replay', action='store_true', help="Replay the request file continuously until stopped (Ctrl+C)")
	Parser.add_argument('--baseline-request', help="File containing normal HTTP request for baseline comparison in replay mode (sent immediately after smuggling POC)")
	Parser.add_argument('--persistent-connection', action='store_true', help="Use a single persistent TCP connection for all requests instead of creating new connections")
	Parser.add_argument('--scan-type', default="tecl,clte", help="Comma-separated scan types: tecl,clte,cl0,pause,connection-state,parser-discrepancy,header-removal,expect,h2,all (default: tecl,clte)")
	Parser.add_argument('--http2', action='store_true', help="Enable HTTP/2 downgrade scans")
	Parser.add_argument('--pause-timeout', type=int, default=61, help="Timeout in seconds for pause-based desync (default: 61)")
	Args = Parser.parse_args()  # returns data from the options specified (echo)

	NOCOLOR = Args.no_color
	if os.name == 'nt':
		NOCOLOR = True

	Version = "v2.0"
	banner(Version)

	if sys.version_info < (3, 0):
		print_info("Error: Smuggler requires Python 3.x")
		sys.exit(1)

	# Parse request file if provided
	custom_request = None
	if Args.request:
		custom_request = parse_request_file(Args.request)
		print_info("Request File: %s"%(Fore.CYAN + Args.request))
	
	# Parse baseline request file if provided
	baseline_request = None
	if Args.baseline_request:
		baseline_request = parse_request_file(Args.baseline_request)
		print_info("Baseline Request File: %s"%(Fore.CYAN + Args.baseline_request))
	
	# Handle replay mode
	if Args.replay:
		if not Args.request:
			print_info("Error: Replay mode requires a request file (-r/--request)")
			Parser.print_help()
			exit(1)
		
		if not custom_request['host']:
			print_info("Error: Request file must contain a Host header for replay mode")
			exit(1)
		
		# Extract host and port from the request
		host = custom_request['host']
		port = 443  # Default HTTPS port
		ssl_flag = True  # Default to HTTPS
		
		# Check if host contains a port
		if ':' in host:
			host, port_str = host.split(':', 1)
			port = int(port_str)
			ssl_flag = port != 80  # Assume HTTPS unless port 80
		
		# Initialize FileHandle for replay mode
		FileHandle = None
		if Args.log is not None:
			try:
				FileHandle = open(Args.log, "w")
			except:
				print_info("Error: Issue with log file destination")
				exit(1)
		
		# Create and run replay manager
		replay_manager = ReplayManager(
			custom_request=custom_request,
			host=host,
			port=port,
			ssl_flag=ssl_flag,
			timeout=float(Args.timeout),
			proxy=Args.proxy,
			logh=FileHandle,
			baseline_request=baseline_request,
			persistent_connection=Args.persistent_connection
		)
		replay_manager.run_replay()
		if FileHandle is not None:
			FileHandle.close()
		exit(0)
	
	# If the URL argument is not specified then check stdin or request file
	if Args.url is None and Args.request is None:
		if sys.stdin.isatty():
			print_info("Error: no direct URL, request file, or piped URL specified\n")
			Parser.print_help()
			exit(1)
		Servers = sys.stdin.read().split("\n")
	elif Args.request:
		# If request file is provided, use it to determine the target
		if custom_request['host']:
			# Build URL from request file
			# Assume HTTPS by default unless the host contains a port or URL is specified
			target_url = "https://" + custom_request['host'] + custom_request['endpoint']
			Servers = [target_url + " " + custom_request['method']]
		else:
			print_info("Error: Request file must contain a Host header")
			exit(1)
	else:
		Servers = [Args.url + " " + Args.method]

	FileHandle = None
	if Args.log is not None:
		try:
			FileHandle = open(Args.log, "w")
		except:
			print_info("Error: Issue with log file destination")
			print(Parser.print_help())
			sys.exit(1)

	for server in Servers:
		# If the next on the list is blank, continue
		if server == "":
			continue
		# Tokenize
		server = server.split(" ")

		# This is for the stdin case, if no method was specified default to GET
		if len(server) == 1:
			server += [Args.method]

		# If a protocol is not specified then default to https
		if server[0].lower().strip()[0:4] != "http":
			server[0] = "https://" + server[0]


		host, port, endpoint, SSLFlagval = process_uri(server[0])
		method = server[1].upper()
		configfile = Args.configfile
		
		# Override with values from custom request if provided
		if custom_request:
			method = custom_request['method']
			endpoint = custom_request['endpoint']

		print_info("URL        : %s"%(Fore.CYAN + server[0]), FileHandle)
		print_info("Method     : %s"%(Fore.CYAN + method), FileHandle)
		print_info("Endpoint   : %s"%(Fore.CYAN + endpoint), FileHandle)
		print_info("Configfile : %s"%(Fore.CYAN + configfile), FileHandle)
		print_info("Timeout    : %s"%(Fore.CYAN + str(float(Args.timeout)) + Fore.MAGENTA + " seconds"), FileHandle)
		if Args.proxy:
			print_info("Proxy      : %s"%(Fore.CYAN + Args.proxy), FileHandle)
		if Args.cookies:
			print_info("Cookies    : %s"%(Fore.CYAN + Args.cookies), FileHandle)
		if Args.request:
			print_info("Request    : %s"%(Fore.CYAN + Args.request), FileHandle)
		print_info("Scan Types : %s"%(Fore.CYAN + Args.scan_type), FileHandle)

		scan_types_str = Args.scan_type
		if Args.http2 and "h2" not in scan_types_str:
			scan_types_str += ",h2"

		requested_scans = [s.strip() for s in scan_types_str.split(",") if s.strip()]
		if "all" in requested_scans:
			requested_scans = ["tecl", "clte", "cl0", "pause", "connection-state",
				"parser-discrepancy", "header-removal", "expect", "h2"]

		classic_scans = [s for s in requested_scans if s in ("tecl", "clte")]
		advanced_scans = [s for s in requested_scans if s not in ("tecl", "clte")]

		if classic_scans:
			sm = Desyncr(configfile, host, port, url=server[0], method=method, endpoint=endpoint, SSLFlag=SSLFlagval, logh=FileHandle, smargs=Args, custom_request=custom_request)
			sm.run()

		if advanced_scans:
			print_info("Advanced   : %s"%(Fore.CYAN + ", ".join(advanced_scans)), FileHandle)
			sm_adv = Desyncr(configfile, host, port, url=server[0], method=method, endpoint=endpoint, SSLFlag=SSLFlagval, logh=FileHandle, smargs=Args, custom_request=custom_request)
			sm_adv.run_advanced_scans(advanced_scans, pause_timeout=Args.pause_timeout)


	if FileHandle is not None:
		FileHandle.close()
