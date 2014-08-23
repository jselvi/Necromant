#!/usr/bin/python
# Python Script that looks for unused Virtual Hosts, given a IP range and a hostname's list
# Jose Selvi - jselvi[a.t]pentester[d0.t]es - http://www.pentester.es
# Version 0.1 - 04/May/2011 - Search and show matches

# Importing
import httplib
import socket
import sys
import os
import re
import hashlib
import signal

# Help and Usage
def help():
	print "# Necromant v0.1 - 04/May/2011"
	print "# Dead Virtual Host Searcher"	
	print "# Jose Selvi - jselvi (4.t) pentester (d0.t) es"
	print "# http://www.pentester.es"
	print "# http://tools.pentester.es/necromant"
	print
	print "Usage: "+sys.argv[0]+" hostname.list url.list"
	print
	return

def httphash( url , hostname ):
	[proto, aux, ip] = url.split("/")
	try:
		if proto == "https:":
			conn = httplib.HTTPSConnection(ip, timeout=5)
		else:
			conn = httplib.HTTPConnection(ip, timeout=5)
		conn.putrequest("GET", "/", skip_host=True)
        	conn.putheader("Host", hostname)
        	conn.endheaders()
		resobj = conn.getresponse()
        	content = resobj.read()
		status = resobj.status
		location = resobj.getheader('Location')
		fingerprint = str(status) + str(location) + str(content)
		fingerprint = re.sub( 'http(s)?://[a-zA-Z0-9\-\.\_]+/', 'http://hostname/', fingerprint )
	except KeyboardInterrupt:
		exit
	except:
		fingerprint = "NONE"
	m = hashlib.md5()
	m.update(fingerprint)
	return (m.hexdigest())

# Testing parameter
if len(sys.argv) < 3:
	help()
	exit()
if not os.path.exists(sys.argv[1]) or not os.path.exists(sys.argv[2]):
	help()
	exit()

# Reading HostNames from File
hostlist_temp = [f.rstrip() for f in open(sys.argv[1], 'r')]
# Testing sense
hostre = re.compile('^[a-zA-Z0-9.-]+$')
hostlist = []
for host in hostlist_temp:
        if hostre.match(host):
                hostlist += [host]

# Reading IP:Port from File
ipport_temp = [f.rstrip() for f in open(sys.argv[2], 'r')]
# Testing sense
ipre = re.compile('http(s)?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\:[0-9]+)?$')
ipport = []
for ipp in ipport_temp:
	if ipre.match(ipp):
		
		# Splitting IPs pieces
		aux2 = ipp.split(":")[1]
		iptext = aux2.split("/")[2]
		ip = iptext.split(".")
		# Testing sense
		isip = 0
		for i in range(0,4):
			if not ( 0<=ip[i]<=255 ):
				isip = -1
		#if not ( 1<=port<=65535 ):
		#	isip = -1
		if isip:
			ipport += [ipp]

# Showing Detected Hostnames
sys.stderr.write("Looking for this HostNames:\n")
for host in hostlist:
	sys.stderr.write("\t- "+host+"\n")
sys.stderr.write("\n")

# Showing Detected IP:Port
sys.stderr.write("Looking at this Servers:\n")
for ipp in ipport:
	sys.stderr.write("\t- "+ipp+"\n")
sys.stderr.write("\n")

# Result Array
result = []

# For each IP, we're looking for hostnames in Bing
try:
	for IP in ipport:
		sys.stderr.write("Searching hostnames for: "+IP+"\n")
		# Check a Bad HostName
		badhash = httphash( IP, "thisnameneverexist.foo.com" )
		# Test all possible HostNames from List
		for hostname in hostlist:
			hosthash = httphash( IP, hostname )
			if badhash != hosthash:
				# Print founded hostname
				sys.stderr.write("\t- "+hostname+"\n")
				result += [hostname+":"+IP]
except:
	sys.stderr.write("Exiting...")

# Print results
sys.stderr.write("\nVirtual Hosts Found:\n")
for res in result:
	print res
