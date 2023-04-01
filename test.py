from portscan import PortScanner
from dns import DnsResolution
from domains import SubdomainScannerAmass
from techdetect import WebTechDetect
from bbdb import BBDB
import techdetect
import os
import json

os.environ['PATH'] += ":/home/joona/go/bin"

db = BBDB()

project = db.insert_project("yahoo")

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
        db.insert_port_for_host(port.port, port.protocol, port.service, port.product, port.version, host.ip)

domains = db.all_domains_by_projectid(project['id'])

for domain in domains:
    ports = []
    dbports = db.all_ports_for_subdomain(domain['name'])
    for p in dbports:
        if p["protocol"] == "tcp":
            ports.append(p["number"])
    if dbports:
        td = WebTechDetect(domain['name'], ",".join(str(p) for p in ports))
        try:
            results = td.start()
            for result in results:
                port_id = 0
                for tmpp in dbports:
                    if tmpp["number"] == result.port:
                        port_id = tmpp["id"]
                        break
                db.insert_webs(domain['id'], port_id, result.url, result.response, result.title, json.dumps(result.metadata))
            print("yo")
        except techdetect.WebTechDetectException:
            continue