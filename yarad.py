#!/usr/bin/env python
#
# Licensed under GNU/GPLv3
#
# This version of yara is derived from aortega@alienvault.com's https://github.com/jaimeblasco/AlienvaultLabs
# 

import glob
import yara
from multiprocessing import Process
import socket
import os
import ConfigParser
import sys
import json
import time

def dispatch_client_inet_socket(connfile, rules, max_size_mb):
    while True:
        try:
            filepath = connfile.readline()
            if not filepath: break
  
            start = time.time()          
            matches = []
            res = {'matches':matches}
            filepath = filepath.rstrip("\n\r")
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    size = os.stat(filepath).st_size
                    if size > max_size_mb:
                        res['error'] = 'file size too large, size > %d bytes'%max_size_mb
                    else:
                        for i in rules.match(filepath):
                            matches.append({
                                "name": i.rule, "namespace": i.namespace,
                                "meta": i.meta, "tags": i.tags
                            })
                else:
                    res['error'] = 'not a file'
            else:
                res['error'] = 'file not found'
            end = time.time()
            res['exec_time'] = "%.2fms"%((end-start)*1000)
            connfile.write(json.dumps(res)+"\n")
            connfile.flush()
        except:
            break
    connfile.close()

def write_pidfile(pidfile):
    with open(pidfile, "w") as pid_file:
        pid_file.write("%s\n" % (str(os.getpid())))

def mainloop(rules, host, port, max_size_mb):
    print "[*] Listening on %s:%d ..."%(host, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    while True:
        conn, addr = server.accept()
        print "[*] Accepted connection from %s:%d ..."%(addr[0], addr[1])
        p = Process(target=dispatch_client_inet_socket, args=(conn.makefile(), rules, max_size_mb))
        p.start()
    server.close()

if  __name__ =='__main__':
    print "[*] Starting ..."
    config = ConfigParser.ConfigParser()
    config.read("yarad.cfg")

    rules_dir   = config.get("server", "rules_dir")
    pidfile     = config.get("server", "pidfile")
    host        = config.get("server", "host")
    port        = config.getint("server", "port")
    max_size_mb = config.getfloat("server", "max_size_mb")*(2**20)

    print "[*] Loading rules (%s) ... " % (rules_dir)
    sys.stdout.flush()

    sigs = dict([(name.replace(".yara", "").split("/")[-1], name) for name in glob.glob(rules_dir+"/*.yara")])
    rules = yara.compile(filepaths=sigs)
    print "[*] Rules loaded"

    if config.getint("server", "daemon") == 1:
        print "[*] Forking ..."
        import daemon
        with daemon.DaemonContext():
            write_pidfile(pidfile)
            mainloop(rules, host, port, max_size_mb)
    else:
        write_pidfile(pidfile)
        mainloop(rules, host, port, max_size_mb)

