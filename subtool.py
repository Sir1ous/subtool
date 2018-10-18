#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import socket
import argparse
import json
import netaddr
import subprocess
import os
from tempfile import NamedTemporaryFile as mktemp
from collections import defaultdict

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

verbose=False

pinfo = lambda s: print("%s[*] %s" % (ENDC,s)) if verbose else False
pok = lambda s: print("%s[+]%s %s" % (GREEN, ENDC, s)) if verbose else False
perr = lambda s: print("%s[-]%s %s" % (RED, ENDC, s))

def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.error:
        return 0

def read_data(filename, isjson):
    with open(filename) as f:
        if isjson:
            raw = f.read()
            content = json.loads(raw)
        else:
            content = f.readlines()
    content = [x.strip() for x in content]
    return content

def resolve_domains(hostnames):
    results = {}
    for hostname in hostnames:
        resolved_ip = resolve_hostname(hostname)
        if resolved_ip != 0:
            results[hostname] = resolved_ip
    return results


def TCPConnect(ip, port_nr, delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(delay)
    try:
        sock.connect((ip, port_nr))
    except:
        return False
    return True

def perform_scan(targets, ports):
    try:
        subprocess.Popen('nmapa', stdout=subprocess.PIPE)
        do_nmap_scan(targets, ports)
    except:
        perr("nmap not found, using built-in scanner!")
        do_normal_scan(targets)

def do_nmap_scan(targets, ports):
    pinfo("Performing nmap scan:")
    #We need to write a tmp file with list of IP's to scan, because nmap does not support
    #scanning multiple hosts from command line args
    f = mktemp(dir='/tmp',delete=False)
    for hostname, ip in targets.iteritems():
        f.write("%s\n" % hostname)
    f.close()
    scan_args = '-sC -v -oA scan_results'
    #TODO: This should probably have some sort of output parsing but I like the way it is currently
    p = subprocess.Popen('nmap %s -v -p %s -iL %s' % (scan_args, ports, f.name), shell=True)
    p.wait()
    os.unlink(f.name)


def do_normal_scan(targets, ports=[80,443]):
    pinfo("Performing simple scan:")
    scan_results=defaultdict(list)
    for hostname, ip in targets.iteritems():
        for p in ports:
            if TCPConnect(ip, p, 1):
                scan_results[ip].append(p)
    #TODO: make it look better?
    for ip, res in scan_results.iteritems():
        print("%s:%s" % (ip, ','.join(map(str,res))))

def filter_domains(targets, scope):
    if not scope:
        return targets
    pinfo("Filtering results by scope")
    result = {}
    for hostname, ip in targets.iteritems():
        for s in scope:
            if check_scope(ip, s):
                result[hostname] = ip
                break
    return result


def check_scope(target_ip, scope):
    return True if netaddr.IPAddress(target_ip) in netaddr.IPNetwork(scope) else False

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='This script aims to help with processing output from subdomain enumeration tools. It has the ability to resolve domains, check them against target scope, and perform port scans.', epilog="example: %s -f domains.json -fj -o output.json -oj -s 172.0.0.0/8 --scan --ports 80,443,8443" % os.path.basename(__file__))
    parser.add_argument('-f', dest='file', type=str, required=True,
                        help='Input file')
    parser.add_argument('-o', dest='output', type=str,
                        help='Output file')
    parser.add_argument('-fj', dest='json', action='store_true',
                        help='Parse input file as JSON')
    parser.add_argument('-oj', dest='outputjson', action='store_true',
                        help='Output in JSON format')
    parser.add_argument('-sf', dest='scope_file', type=str,
                        help='File with target scope (IP ranges or single IP addresses)')
    parser.add_argument('-s', dest='scope_single', type=str,
                        help='Single target scope (IP range or single IP address)')
    parser.add_argument('--scan', dest='ifscan', action='store_true',
                        help='Perform a scan')
    parser.add_argument('--ports', dest='ports', default='80,443', type=str,
                        help='Port numbers to scan (80,443,8000-9000)')
    args = parser.parse_args()

    pinfo("Parsing input data")
    hostnames = read_data(args.file, args.json)

    pinfo("Resolving domains")
    results_unfiltered = resolve_domains(hostnames)

    pinfo("Reading scope info from file")
    scope = []
    if args.scope_single:
        scope.append(args.scope_single)
    elif args.scope_file:
        scope = read_data(args.scope_file, False)

    results = filter_domains(results_unfiltered, scope)

    if args.output != None:
        with open(args.output, "w") as f:
            if args.outputjson:
                f.write(json.dumps(results))
            else:
                for hostname,ip in results.iteritems():
                    f.write("%s:%s\n" % (hostname,ip))
    else:
        if args.outputjson:
            from pprint import pprint as p
            p(json.dumps(results))
        else:
            for hostname, ip in results.iteritems():
                print("%s:%s" % (hostname,ip))

    if args.ifscan:
        perform_scan(results, args.ports)

