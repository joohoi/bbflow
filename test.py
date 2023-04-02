from portscan import PortScanner
from dns import DnsResolution
from domains import SubdomainScannerAmass
from techdetect import WebTechDetect
from bbdb import BBDB
import techdetect
import os
import json

os.environ['PATH'] += ":/home/joona/go/bin"

#db = BBDB()

#project = db.insert_project("yahoo")

#subs = SubdomainScannerAmass("io.fi")
#subs.start(recursive=False)
#domains = subs.domainobjects
#print(domains)


class Automation(object):
    def __init__(self, project_name):
        self.project_name = project_name
        self.db = BBDB()
        self.db.insert_project(self.project_name)
        self.project = self.db.project_by_name(self.project_name)
        self.domains = []
        self.resolved = []

    def _enum_domains(self, name, recursive=False, depth=1):
        subs = SubdomainScannerAmass(name)
        subs.start(recursive, depth)
        return subs.domainobjects

    def _resolve_domains(self, domainobjects):
        resolved_domains = []
        for domain in domainobjects:
            try:
                d = DnsResolution(domain.name)
                d.resolve()
                if d.did_resolve():
                    domain.resolved = True
                    domain.dns["a"] = d.a()
                    domain.dns["aaaa"] = d.aaaa()
                    domain.dns["cname"] = d.cname()
                    domain.dns["txt"] = d.txt()
                    domain.dns["ns"] = d.ns()
                    domain.dns["mx"] = d.mx()
                    domain.dns["soa"] = d.soa()
                    domain.dns["srv"] = d.srv()
                    domain.dns["ptr"] = d.ptr()
                    resolved_domains.append(domain)
            except Exception as e:
                print("Error while trying to resolve subdomain {} : {}".format(domain.name, e))
                continue
        return resolved_domains

    def resolve_and_update(self, domains):
        found_domains = []
        for domain in domains:
            found_domains += self._enum_domains(domain)
        resolved_domains = self._resolve_domains(found_domains)
        for domain in resolved_domains:
            db_domain = self.db.insert_domain(domain.name, self.project['id'], ",".join(domain.sources))
            for i in domain.dns["a"]:
                self.db.insert_host_for_domainname(domain.name, i, "ipv4")
                self.db.insert_or_update_dns(domain.name, "a", i)
            for i in domain.dns["aaaa"]:
                self.db.insert_host_for_domainname(domain.name, i, "ipv6")
                self.db.insert_or_update_dns(domain.name, "aaaa", i)
            for i in domain.dns["cname"]:
                self.db.insert_or_update_dns(domain.name, "cname", i)
            for i in domain.dns["txt"]:
                self.db.insert_or_update_dns(domain.name, "txt", i)
            for i in domain.dns["ns"]:
                self.db.insert_or_update_dns(domain.name, "ns", i)
            for i in domain.dns["mx"]:
                self.db.insert_or_update_dns(domain.name, "mx", i)
            #for i in domain.dns["soa"]:
            #    self.db.insert_or_update_dns(domain.name, "soa", i)
            for i in domain.dns["srv"]:
                self.db.insert_or_update_dns(domain.name, "srv", i)
            for i in domain.dns["ptr"]:
                self.db.insert_or_update_dns(domain.name, "ptr", i)

    def portscan_and_update(self):
        db_hosts = self.db.hosts_by_projectname(self.project["name"])
        hosts = [h["address"] for h in db_hosts]
        scanner = PortScanner(hosts)
        output = scanner.scan()
        ps_results = scanner.parse(output)
        for host in ps_results:
            for port in host.ports:
                self.db.insert_or_update_port_for_host(port.port, port.protocol, port.service, port.product,
                                                       port.version, host.ip)

    def techdetect_and_update(self):
        db_domains = self.db.all_domains_by_projectid(self.project['id'])
        for domain in db_domains:
            ports = []
            dbports = self.db.all_ports_for_subdomain(domain['name'])
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
                            if tmpp["number"] == result.port and tmpp["address"] == result.metadata['host']:
                                port_id = tmpp["id"]
                                break
                        self.db.insert_or_update_webs(domain['id'], port_id, result.url,
                                                      result.response, result.title,
                                                      json.dumps(result.metadata))
                except techdetect.WebTechDetectException:
                    continue


a = Automation("Oma!")
#a.resolve_and_update(["io.fi", "1o.fi", "kuori.org"])
a.portscan_and_update()
a.techdetect_and_update()

"""
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
                    if tmpp["number"] == result.port and tmpp["address"] == result.metadata['host']:
                        port_id = tmpp["id"]
                        break
                db.insert_webs(domain['id'], port_id, result.url, result.response, result.title, json.dumps(result.metadata))
            print("yo")
        except techdetect.WebTechDetectException:
            continue"""
