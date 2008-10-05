#!/usr/bin/env python
# encoding: utf-8

# Convert the postgrey_whitelist_clients file to a format
# suitable for use with the postlicyd Postfix policy daemon

# Copyright © 2008 Aymeric Augustin
# Released under the GPL

import os, re, sys


def process(infile, outfile):

    re_domain_name = re.compile(r'[a-z0-9.\-]+\.[a-z]+')
    re_ip_address = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    outfile.write('# Automatically converted for use by postlicyd\n\n')

    # Store each entry to avoid duplicates
    entries = []

    for line in infile:
        # Comments: keep them
        if line == '\n' or line[0] == '#':
            outfile.write(line)
        # IP addresses: keep as is
        elif re_ip_address.match(line):
            outfile.write(line)
        # Regexps: extract final constant part
        elif line[0] == '/':
            line = line.rstrip(r'$/').replace(r'\.', r'.')
            host = re_domain_name.findall(line)[-1]
            result = host + '\n'
            if result not in entries:
                entries.append(result)
                outfile.write(result)
        # Domain names: prepend a dot if the domain name contains only one dot
        elif re_domain_name.match(line):
            if line.count('.') < 2:
                result = '.' + line
            else:
                result = line
            if result not in entries:
                entries.append(result)
                outfile.write(result)
        # Unrecognized: report on stderr and comment in output
        else:
            outfile.write('# IGNORED: ' + line)
            sys.stderr.write("Couldn't process line: %s" % line)


if __name__ == '__main__':

    # Check number of arguments
    if len(sys.argv) > 3:
        print "Usage: %s [input] [output]" % sys.argv[0]
        print "If input/output is omitted or -, stdin/stdout is used."
        sys.exit(1)

    # Parse first argument
    if len(sys.argv) > 1 and sys.argv[1] != '-':
        infile = open(sys.argv[1], 'r')
    else:
        infile = sys.stdin

    # Parse second argument
    if len(sys.argv) > 2 and sys.argv[2] != '-':
        if sys.argv[1] == sys.argv[2]:
            print "Source file and destination file are identical, aborting"
            sys.exit(1)
        if os.path.exists(sys.argv[2]):
            print "Destination file %s already exists, aborting" % sys.argv[2]
            sys.exit(1)
        outfile = open(sys.argv[2], 'w')
    else:
        outfile = sys.stdout

    # Do the processing
    process(infile, outfile)
