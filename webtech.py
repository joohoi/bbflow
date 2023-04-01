import techdetect
from techdetect import WebTechDetect
from bbdb import BBDB
import os

os.environ['PATH'] += ":/home/joona/go/bin"

db = BBDB()

project = db.insert_project("yahoo")

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
            print("yo")
        except techdetect.WebTechDetectException:
            continue