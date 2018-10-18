```
usage: subtool.py [-h] -f FILE [-o OUTPUT] [-fj] [-oj] [-sf SCOPE_FILE]
                  [-s SCOPE_SINGLE] [--scan] [--ports PORTS]

This script aims to help with processing output from subdomain enumeration
tools. It has the ability to resolve domains, check them against target scope,
and perform port scans.

optional arguments:
  -h, --help       show this help message and exit
  -f FILE          Input file
  -o OUTPUT        Output file
  -fj              Parse input file as JSON
  -oj              Output in JSON format
  -sf SCOPE_FILE   File with target scope (IP ranges or single IP addresses)
  -s SCOPE_SINGLE  Single target scope (IP range or single IP address)
  --scan           Perform a scan
  --ports PORTS    Port numbers to scan (80,443,8000-9000)

example: subtool.py -f domains.json -fj -o output.json -oj -s 172.0.0.0/8
--scan --ports 80,443,8443
```
