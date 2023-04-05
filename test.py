from portscan import PortScanner
from dns import DnsResolution
from domains import SubdomainScannerAmass
from techdetect import WebTechDetect
from bbdb import BBDB
from PIL import Image
import techdetect
import os
import json
import requests
import time
import uuid
import shutil
import ipaddress

os.environ['PATH'] += ":/home/joona/go/bin"

SCREENSHOT_DIR = "static/screenshots/"


class Automation(object):
    def __init__(self, project_name):
        self.project_name = project_name
        self.db = BBDB()
        self.db.insert_project(self.project_name)
        self.project = self.db.project_by_name(self.project_name)
        self.domains = []
        self.resolved = []
        self._proc = None
        self.running = False
        self.current_job = ""

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
            self.db.insert_domain(domain.name, self.project["id"], ",".join(domain.sources))
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
            for i in domain.dns["srv"]:
                self.db.insert_or_update_dns(domain.name, "srv", i)
            for i in domain.dns["ptr"]:
                self.db.insert_or_update_dns(domain.name, "ptr", i)

    def portscan_and_update(self):
        db_hosts = self.db.hosts_by_projectname(self.project["name"])
        hosts = []
        cdn_hosts = []
        for h in db_hosts:
            if self.is_cdn(h["address"]):
                cdn_hosts.append(h)
            else:
                hosts.append(h["address"])

        scanner = PortScanner(hosts)
        output = scanner.scan()
        ps_results = scanner.parse(output)
        for host in ps_results:
            for port in host.ports:
                self.db.insert_or_update_port_for_host(port.port, port.protocol, port.service, port.product,
                                                       port.version, host.ip)
        for host in cdn_hosts:
            self.db.insert_or_update_port_for_host("80", "tcp", "http", "CDN HTTP", "", host["address"])
            self.db.insert_or_update_port_for_host("443", "tcp", "https", "CDN HTTPS", "", host["address"])

    def screenshot_webs(self, refresh=False):
        GOWITNESS_URL = "https://bbss.0xff.fi/api/"
        GOWITNESS_AUTH = "Basic MGRyZTpCTU9JYjI0bW9pYm0yNG9hc2R2YnZhdg=="
        headers = {"Authorization": GOWITNESS_AUTH, "Content-Type": "application/json"}
        domains = self.db.all_domains_by_projectid(self.project['id'])
        all_webs = []
        queued_webs = []
        for domain in domains:
            tmp_webs = self.db.webs_for_domain(domain['name'])
            all_webs += tmp_webs
        for web in all_webs:
            if refresh or not web["screenshot"]:
                queued_webs.append(web)
                requests.post(GOWITNESS_URL + "screenshot",
                              headers=headers,
                              json={"url": web["url"], "oneshot": "false"}, verify=False)
                time.sleep(2)
        retries = 0
        max_retries = 5
        if queued_webs:
            while retries < max_retries and len(queued_webs) > 0:
                retries += 1
                ss_req = requests.get(GOWITNESS_URL + "list", headers=headers, verify=False)
                if ss_req.status_code == 200:
                    ss_data = ss_req.json()
                    queued_webs = self._update_screenshots(queued_webs, ss_data)

    def _update_screenshots(self, queued_webs, ss_data):
        remaining_webs = []
        for web in queued_webs:
            found = False
            for ss in ss_data:
                if ss["URL"] == web["url"]:
                    screenshotpath = self._get_screenshot(ss["ID"])
                    if screenshotpath:
                        self.db.update_webs_screenshot(web["id"], screenshotpath)
                        found = True
            if not found:
                remaining_webs.append(web)
        return remaining_webs

    def _get_screenshot(self, id):
        GOWITNESS_URL = "https://bbss.0xff.fi/api/"
        GOWITNESS_AUTH = "Basic MGRyZTpCTU9JYjI0bW9pYm0yNG9hc2R2YnZhdg=="
        headers = {"Authorization": GOWITNESS_AUTH}
        filename = str(uuid.uuid4()) + ".png"
        res = requests.get(GOWITNESS_URL + "detail/{}".format(id) + "/screenshot", headers=headers, verify=False, stream=True)
        if res.status_code == 200:
            with open(SCREENSHOT_DIR + filename, 'wb') as f:
                shutil.copyfileobj(res.raw, f)
            with Image.open(SCREENSHOT_DIR + filename) as img:
                img.thumbnail((640, 640))
                img.save(SCREENSHOT_DIR + "thumb_" + filename, "PNG")
            return filename
        return None

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

    def is_cdn(self, host):
        cdn = None
        with open('cdnranges.txt') as f:
            cdndata = json.loads(f.read())
        for cdn_name, cidrlist in cdndata.items():
            for cidr in cidrlist:
                if ipaddress.ip_address(host) in ipaddress.ip_network(cidr):
                    cdn = cdn_name
                    break
        return cdn


a = Automation("Visma")
a.resolve_and_update(["vismaonline.com"])
a.portscan_and_update()
a.techdetect_and_update()
a.screenshot_webs()

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
