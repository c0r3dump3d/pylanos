
	  ____        _                 ___  ____  
	 |  _ \ _   _| |    __ _ _ __  / _ \/ ___| 
	 | |_) | | | | |   / _` | '_ \| | | \___ \ 
	 |  __/| |_| | |__| (_| | | | | |_| |___) |
	 |_|    \__, |_____\__,_|_| |_|\___/|____/ 
	        |___/                              

A little Python script for LAN OS detection using nmap -O.


What's PyLanOS?
===============

	PyLanOS it's a simple Python script to scan a LAN network and detect the Operative System present in the LAN. 
	It's make use of nmap with -O option to scan and then parse the result to show in a friendly way. 


Advice: 
=======
	Like others offensive tools, the author disclaims all responsibility in the use of this script.

	

Installing:
==========

	# apt-get install python-ipy python-nmap 
	# git clone https://github.com/c0r3dump3d/pylanos.git


Usage:
======

	usage: PyLanOS.py [-h] [-H HOST] [-f FILE] [-o OUTPUT] [-l NOLAN] [-v VERBOSE]

	A little Python script for LAN OS detection (nmap -O)

	optional arguments:
  	-h, --help  show this help message and exit
  	-H HOST     A single host or CIDR notation.
  	-f FILE     A host list in a file.
  	-o OUTPUT   The output write to a file.
  	-l NOLAN    No LAN host discover. Default no.
  	-v VERBOSE  Verbose option to see the result of nmap -O, for each host.
              Default no.

Example:
========
	
	For better performace of the scan it's necessary root privileges.

	* A simple scan:

                ./PyLanOS -H 192.168.1.0/24 -o os_lan.txt 
        
	* A scan with extra probes for host discovery:

		./PyLanOS -H 192.168.1.0/24 -o os_scan.txt -l yes 

Author:
=======

        c0r3dump | coredump<@>autistici.org

