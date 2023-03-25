from portscan import PortScanner
from runner import Runner
from dns import DnsResolution
from domains import SubdomainScannerAmass
from bbdb import BBDB
import os
import sys
import time

os.environ['PATH'] += ":/home/joona/go/bin"

db = BBDB()

project = db.insert_project("testproject")

subs = SubdomainScannerAmass("io.fi")
subs.start(recursive=False)
domains = subs.domainobjects
print(domains)

resolved = []
for domain in domains:
    try:
        d = DnsResolution(domain.name)
        d.resolve()
        db.insert_domain(domain.name, project['id'], ",".join(domain.sources))
        for i in d.a():
            db.insert_host_for_domainname(domain.name, i, "ipv4")
            resolved.append(i)
        for i in d.aaaa():
            db.insert_host_for_domainname(domain.name, i, "ipv6")
            resolved.append(i)
    except Exception as e:
        print(e)
        continue
print(resolved)

x = PortScanner(resolved)
output = x.scan()
ps_results = x.parse(output)
for host in ps_results:
    for port in host.ports:
        db.insert_port_for_host(port.port, port.protocol, port.product, port.version, host.ip)