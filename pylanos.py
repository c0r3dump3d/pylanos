#!/usr/bin/python
# -*- coding: utf-8 -*-

__license__ = """

PyLanOS, a simple script to detect LAN OS detection, using nmap -A option.


Author:
        c0r3dump | coredump<@>autistici.org

PyLanOS project site: https://github.com/c0r3dump3d/pylanos

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

The authors disclaims all responsibility in the use of this tool.

"""

import time
import errno
import os
import sys
import argparse
import subprocess

try:
    from IPy import IP
except ImportError:
    print("You need to install IPy module: pip install IPy")
    exit(1)


class NmapDoesNotExistError(Exception):
    pass


class BackgroundColors(object):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
            self.HEADER = ''
            self.OKBLUE = ''
            self.OKGREEN = ''
            self.WARNING = ''
            self.FAIL = ''
            self.ENDC = ''


def nmap_scan(host, lan=False, verbose=False):

    hup = 0
    hdown = 0

    try:
        if lan:
            scanv = subprocess.Popen(["nmap", "-PR", "-O", str(host)],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]
        else:
            scanv = subprocess.Popen(["nmap", "-PE", "-PP",
                                     "-PS21,22,23,25,80, 443,3306,3389,8080",
                                     "-O", str(host)], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE).communicate()[0]
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NmapDoesNotExistError('Make sure nmap is installed.\n')

    scanlist = scanv.split()
    if verbose:
        print(scanv)

    if "down" in scanv:
        print '|___ ' + 'it\s down.'
        osres = 'down'
        hdown = hdown + 1
        return osres, hup, hdown

    print '|___' + ' it\'s up ...',
    hup = hup + 1

    if 'printer' in scanlist:
        osres = 'Printer'
        print BackgroundColors.OKBLUE + osres + ' system.' + BackgroundColors.ENDC
    elif 'Fortinet' in scanlist:
        osres = 'Fortinet'
        print BackgroundColors.OKBLUE + osres + ' system.' + BackgroundColors.ENDC
    elif 'Linux' in scanlist:
        osres = 'Linux'
        print BackgroundColors.OKGREEN + osres + ' system.' + BackgroundColors.ENDC
    elif 'windows_counterdows' in scanlist:
        osres = 'windows_counterdows'
        print BackgroundColors.OKGREEN + osres + ' system.' + BackgroundColors.ENDC
    elif 'Apple' in scanlist:
        osres = 'Apple'
        print BackgroundColors.OKGREEN + osres + ' system.' + BackgroundColors.ENDC
    elif 'IOS' in scanlist:
        osres = 'IOS'
        print BackgroundColors.OKBLUE + osres + ' system.' + BackgroundColors.ENDC
    else:
        osres = 'Unknow'
        print(BackgroundColors.FAIL + osres + ' system.Unable to determine \
                the OS type.' + BackgroundColors.ENDC)

    return osres, hup, hdown


def hello():
    print(BackgroundColors.OKGREEN)
    print(BackgroundColors.ENDC)


def main():

    host_to_os = {} # map os to each host
    hosts = [] # list to keep the hosts for scanning.
    os_types = [] # keeps the different os types
    host_counter = 0 # keeps track of number of hosts
    linux_counter = 0 # keeps track of linux hosts
    apple_counter = 0 # keeps track of apple hosts
    windows_counter = 0 # keeps track of windows_counterdows hosts
    ios_counter = 0 # keeps track of ios hosts
    forti_counter = 0 # keeps track of forti hosts
    unknown_counter = 0 # keeps track of unknown os
    printer_counter = 0 # keeps track of printers
    other_counter = 0 # keeps track of other os types

    parse = argparse.ArgumentParser(description='A little Python script for \
                                    LAN OS detection (nmap -O)')
    parse.add_argument('-H', action='store', dest='host', help='A single host \
                       or CIDR notation.')
    parse.add_argument('-f', action='store', dest='file', help='A host list \
                       in a file.')
    parse.add_argument('-o', action='store', dest='output', help='The output \
                       write to a file.')
    parse.add_argument('-l', action='store', type=bool, dest='lan',
                       default=False, help='No LAN host discover')
    parse.add_argument('-v', action='store', type=bool, dest='verbose',
                       default=False, help='Verbose option to see the result \
                       of nmap -O, for each host')

    hello()
    argus = parse.parse_args()

    if not os.geteuid() == 0:
        sys.exit("Root permissions are needed to scan for os.\n")

    if argus.host is None and argus.file is None:
        parse.print_help()
        exit(1)

    if argus.verbose:
        verbose = True
    else:
        verbose = False

    if argus.lan:
        lan = True
    else:
        lan = False

    if argus.file is not None:
        with open(argus.file, 'r') as f:
            for line in f.readlines():
                line = line.split('\n')
                hosts.append(line[0])
                host_counter = host_counter + 1
    else:
        try:
            IP(argus.host)
        except ValueError:
            print("Invalid host address.")
            exit(1)

        if "/" in argus.host:
            for ip in IP(argus.host):
                hosts.append(str(ip))
                host_counter = host_counter + 1
            del hosts[0]

        else:
            hosts.append(argus.host)
            host_counter = host_counter + 1

    timeStart = int(time.time())
    for host in hosts:
        print "Scanning %s with nmap ..." % host
        os_type, hup, hdown = nmap_scan(host, lan, verbose)
        os_types.append(os_type)
    timeDone = int(time.time())
    timeRes = timeDone-timeStart

    for os_type in os_types:
        if os_type == "windows_counterdows":
            windows_counter = windows_counter + 1
        elif os_type == "Linux":
            linux_counter = linux_counter + 1
        elif os_type == "Apple":
            apple_counter = apple_counter + 1
        elif os_type == "Unknow":
            unknown_counter = unknown_counter + 1
        elif os_type == "IOS":
            ios_counter = ios_counter + 1
        elif os_type == "Printer":
            printer_counter = printer_counter + 1
        elif os_type == "Fortinet":
            forti_counter = forti_counter + 1
        elif os_type != "down":
            other_counter = other_counter + 1

    print
    print BackgroundColors.HEADER + '++++++++++++++++++++++++++++++++++++++++'
    print BackgroundColors.HEADER + '++++++++++++++++++++++++++++++++++++++++'
    print BackgroundColors.HEADER + '++           SOME STATISTICS          ++'
    print BackgroundColors.HEADER + '++++++++++++++++++++++++++++++++++++++++'
    print BackgroundColors.HEADER + '++++++++++++++++++++++++++++++++++++++++'
    print BackgroundColors.OKBLUE
    print 'Scan time (s): ' + str(timeRes)
    print 'Number of hosts: ' + str(host_counter)
    print 'Host Alive: ' + str(hup)
    print 'Host Down: ' + str(hdown)
    print
    if hup == 0:
        exit(0)

    if windows_counter != 0:
        print('[+] Number of windows systems detected: %d (%d %%)'
              % (windows_counter, windows_counter * 100 / hup))
    if linux_counter != 0:
        print('[+] Number of GNU/Linux systems detected: %d (%d %%)'
              % (linux_counter, linux_counter * 100 / hup))
    if apple_counter != 0:
        print('[+] Number of Apple systems detected: %d (%d %%)'
              % (apple_counter, apple_counter * 100 / hup))
    if printer_counter != 0:
        print('[+] Number of Printer systems detected: %d (%d %%)'
              % (printer_counter, printer_counter * 100 / hup))
    if ios_counter != 0:
        print('[+] Number of Cisco systems detected: %d (%d %%)'
               % (ios_counter, ios_counter * 100 / hup))
    if forti_counter != 0:
        print('[+] Number of Fortinet systems detected: %d (%d %%)'
               % (forti_counter, forti_counter * 100 / hup))
    if other_counter != 0:
        print('[+] Number of other_counters systems detected: %d (%d %%)'
              % (other_counter, other_counter * 100 / hup))
    if unknown_counter != 0:
        print('[+] Number of Unknow systems detected: %d (%d %%)'
              % (unknown_counter, unknown_counter * 100 / hup))

    print BackgroundColors.ENDC

    for idx, host in enumerate(hosts):
        host_to_os[host] = os_types[idx] # map os to host

    if argus.output is not None:
        fileout = argus.output
        with open(fileout, 'w') as f:
            for key in host_to_os:
                f.write(key + ' ==> ' + host_to_os[key] + '\n')


if __name__ == "__main__":
    main()
