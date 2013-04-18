#!/usr/bin/env python

# yarad - Yara daemon
# AlienVault Labs - https://github.com/jaimeblasco/AlienvaultLabs
#
# Licensed under GNU/GPLv3
# aortega@alienvault.com

import glob
import yara
from multiprocessing import Process
import socket
import os
import ConfigParser
import sys
import json

config = ConfigParser.ConfigParser()
config.read("yarad.cfg")

daemonize = config.getint("server", "daemon")
if daemonize == 1:
    import daemon

rules_f = config.get("server", "rules_file")
pidfile = config.get("server", "pidfile")

srv_config = {}
srv_config["host"] = config.get("inet", "host")
srv_config["port"] = config.getint("inet", "port")

def linesplit(socket):
    # untested
    buffer = socket.recv(4096)
    done = False
    while not done:
        if "\n" in buffer:
            (line, buffer) = buffer.split("\n", 1)
            yield line+"\n"
        else:
            more = socket.recv(4096)
            if not more:
                done = True
            else:
                buffer = buffer+more
    if buffer:
        yield buffer

def dispatch_client_inet_socket(conn, rules):
    infile = conn.makefile()
    f = ""
    while True:
        try:
            f = infile.readline()
            if not f: break

            f = f.rstrip("\n\r")
            if os.path.exists(f) and os.path.isfile(f):
                matches = []
                for i in rules.match(f):
                    matches.append({
                        "name": i.rule, "namespace": i.namespace,
                        "meta": i.meta, "tags": i.tags
                    })
                infile.write(json.dumps(matches)+"\n")
            else:
                infile.write("[]\n")
            infile.flush()
        except:
            break
    infile.close()

def write_pidfile(pidfile):
    f = open(pidfile, "w")
    f.write("%s\n" % (str(os.getpid())))
    f.close()

def mainloop(rules, srv_config):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((srv_config["host"], srv_config["port"]))
    server.listen(1)
    while True:
        conn, addr = server.accept()
        p = Process(target=dispatch_client_inet_socket, args=(conn, rules))
        p.start()
    server.close()

print "[*] Starting"
print "[*] Loading rules (%s) ... " % (rules_f),
sys.stdout.flush()

sigs = dict([(name.replace(".yara", "").split("/")[-1], name) for name in glob.glob(rules_f+"/*.yara")])
rules = yara.compile(filepaths=sigs)
print "OK"

if daemonize == 1:
    print "[*] Forking ..."
    with daemon.DaemonContext():
        write_pidfile(pidfile)
        mainloop(rules, srv_config)
else:
    write_pidfile(pidfile)
    mainloop(rules, srv_config)

