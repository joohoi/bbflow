import flask
from flask import render_template
from werkzeug.exceptions import abort
from bbdb import BBDB

app = flask.Flask(__name__)

db = BBDB()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/projects')
def projects():
    projects = db.all_projects()
    return render_template('projects.html', projects=projects)


@app.route('/projects/<int:project_id>')
def project(project_id):
    project = db.project_by_id(project_id)
    if not project:
        abort(404)
    domains = [get_domain_object(d) for d in db.all_domains_by_projectid(project_id)]
    return render_template('project.html', project=project, domains=domains)

@app.route('/domain/<int:domain_id>')
def domain(domain_id):
    domain = db.domain_by_id(domain_id)
    if not domain:
        abort(404)
    project = db.project_by_id(domain["project_id"])
    domain = get_domain_object(domain)
    db_hosts = db.hosts_by_domain(domain["domain_name"])
    hosts = [get_host_object(h) for h in db_hosts]
    return render_template('domain.html', domain=domain, project=project, hosts=hosts)

@app.route('/host/<int:host_id>')
def host(host_id):
    host = db.host_by_id(host_id)
    if not host:
        abort(404)
    host = get_host_object(host)
    return render_template('host.html', host=host)

def get_domain_object(domain):
    services = db.all_ports_for_subdomain(domain["name"])
    unique_ports = set([p["number"] for p in services])

    return {
        "domain_id": domain["id"],
        "domain_name": domain["name"],
        "domain_object": domain,
        "last_seen": domain["last_seen"],
        "hosts": db.hosts_by_domain(domain["name"]),
        "services": services,
        "ports": unique_ports,
        "dns": db.dns_for_domain(domain["name"]),
        "websites": db.webs_for_domain(domain["name"])
    }

def get_host_object(host):
    ports = db.all_ports_for_host(host["address"])
    domains = db.all_domains_by_host(host["address"])
    webs = db.webs_for_host(host["address"])
    return {
        "host_id": host["id"],
        "host_address": host["address"],
        "host_object": host,
        "last_seen": host["last_seen"],
        "ports": ports,
        "domains": domains,
        "websites": webs
    }

