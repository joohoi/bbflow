import psycopg2
import psycopg2.extras

DATABASE_HOST = "localhost"
DATABASE_PORT = "5433"
DATABASE_USER = "postgres"
DATABASE_PASSWORD = "mysecretpassword"

class BBDB(object):
    def __init__(self, host=DATABASE_HOST, port=DATABASE_PORT, user=DATABASE_USER, password=DATABASE_PASSWORD):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.conn = None
        self.cur = None
        self._connect()

    def _connect(self):
        self.conn = psycopg2.connect(host=self.host, port=self.port, user=self.user, password=self.password)
        self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def _disconnect(self):
        self.cur.close()
        self.conn.close()

    def _execute(self, query, params=tuple()):
        self.cur.execute(query, params)
        self.conn.commit()

    def _execute_fetch(self, query, params=tuple()):
        self.cur.execute(query, params)
        return self.cur.fetchall()

    def _execute_fetchone(self, query, params=tuple()):
        self.cur.execute(query, params)
        return self.cur.fetchone()

    def _insert_fetchone(self, query, params=tuple()):
        self.cur.execute(query, params)
        retval = self.cur.fetchone()
        self.conn.commit()
        return retval

    def _execute_fetchmany(self, query, params=tuple(), size=1):
        self.cur.execute(query, params)
        return self.cur.fetchmany(size)

    def _execute_fetchall(self, query, params=tuple()):
        self.cur.execute(query, params)
        return self.cur.fetchall()

    def _insert_fetchall(self, query, params=tuple()):
        self.cur.execute(query, params)
        retval = self.cur.fetchall()
        self.conn.commit()
        return retval


    def hosts_by_domain(self, domain):
        query = """
        SELECT * FROM hosts h 
            INNER JOIN domains_hosts dh 
            ON h.id = dh.hosts_id 
            INNER JOIN domains d 
            ON d.id = dh.domains_id 
        WHERE d.name = %s
        """
        return self._execute_fetchall(query, (domain,))

    def insert_project(self, name):
        query = "INSERT INTO projects (name) VALUES (%s) ON CONFLICT (name) DO UPDATE SET name=excluded.name RETURNING id"
        return self._insert_fetchone(query, (name,))

    def insert_or_update_dns(self, domain, type, value):
        records = self.dns_for_domain(domain)
        found_rec = None
        if records:
            for rec in records:
                if rec["type"] == type and rec["value"] == value:
                    found_rec = rec
                    break
        if found_rec:
            self._update_dns(found_rec["id"], type, value)
            return found_rec
        else:
            dbdomain = self.domain_by_name(domain)
            return self._insert_dns(dbdomain["id"], type, value)

    def dns_for_domain(self, domain):
        query = """
        SELECT d.* FROM dns d 
            INNER JOIN domains dom 
            ON d.domains_id = dom.id 
        WHERE dom.name = %s
        """
        return self._execute_fetchall(query, (domain,))
    def _insert_dns(self, domain_id, type, value):
        query = "INSERT INTO dns (domains_id, type, value) VALUES (%s, %s, %s) RETURNING id"
        return self._insert_fetchone(query, (domain_id, type, value))

    def _update_dns(self, dns_id, type, value):
        query = "UPDATE dns SET type = %s, value = %s, last_seen = now() WHERE id = %s"
        return self._execute(query, (type, value, dns_id))

    def host_by_ip(self, ip):
        query = "SELECT * FROM hosts WHERE address = %s"
        return self._execute_fetchone(query, (ip,))

    def hosts_by_projectname(self, project):
        query = """
        SELECT h.* FROM hosts h 
            INNER JOIN domains_hosts dh 
            ON h.id = dh.hosts_id 
            INNER JOIN domains d 
            ON d.id = dh.domains_id 
            INNER JOIN projects p 
            ON p.id = d.project_id 
        WHERE p.name = %s
        """
        return self._execute_fetchall(query, (project,))

    def project_by_name(self, name):
        query = "SELECT * FROM projects WHERE name = %s"
        return self._execute_fetchone(query, (name,))

    def domain_by_name(self, name):
        query = "SELECT * FROM domains WHERE name = %s"
        return self._execute_fetchone(query, (name,))

    def insert_host(self, address, family):
        query = "INSERT INTO hosts (address, family) VALUES (%s, %s) ON CONFLICT (address) DO UPDATE SET last_seen=now() RETURNING id"
        return self._insert_fetchone(query, (address, family))

    def insert_domain(self, name, project, sources=""):
        query = "INSERT INTO domains (name, sources, project_id) VALUES (%s, %s, %s) ON CONFLICT (name) DO UPDATE SET last_seen=now() RETURNING id"
        return self._insert_fetchone(query, (name, sources, project))

    def _domain_host_relation(self, domain_id, host_id):
        query = "SELECT * FROM domains_hosts WHERE domains_id = %s AND hosts_id = %s"
        return self._execute_fetchone(query, (domain_id, host_id))

    def insert_host_for_domainname(self, domain, address, family):
        dres = self.domain_by_name(domain)
        hres = self.insert_host(address, family)
        exists = self._domain_host_relation(dres["id"], hres["id"])
        if exists:
            return exists
        else:
            query = "INSERT INTO domains_hosts (domains_id, hosts_id) VALUES (%s, %s) RETURNING id"
            return self._insert_fetchone(query, (dres["id"], hres["id"]))

    def fetch_port(self, port, host):
        hres = self.host_by_ip(host)
        query = "SELECT * FROM ports WHERE number = %s AND host_id = %s"
        return self._execute_fetchone(query, (port, hres["id"]))

    def insert_port(self, port, protocol, service, product, version, host_id):
        query = "INSERT INTO ports (number, protocol, service, product, version, host_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id"
        return self._insert_fetchone(query, (port, protocol, service, product, version, host_id))

    def update_port_by_id(self, port_id, service, product, version):
        query = "UPDATE ports SET service = %s, product = %s, version = %s, last_seen=now() WHERE id = %s"
        return self._execute(query, (service, product, version, port_id))

    def insert_or_update_port_for_host(self, port, protocol, service, product, version, host):
        hres = self.host_by_ip(host)
        existing_port = self.fetch_port(port, host)
        if not existing_port:
            return self.insert_port(port, protocol, service, product, version, hres["id"])
        else:
            self.update_port_by_id(existing_port["id"], service, product, version)
            return existing_port
    def all_domains_by_projectid(self, project_id):
        query = "SELECT * FROM domains WHERE project_id = %s"
        return self._execute_fetchall(query, (project_id,))

    def all_ports_for_subdomain(self, subdomain):
        query = "SELECT DISTINCT p.*, h.address FROM ports p INNER JOIN hosts h ON p.host_id = h.id INNER JOIN domains_hosts dh ON h.id = dh.hosts_id INNER JOIN domains d ON d.id = dh.domains_id WHERE d.name = %s"
        return self._execute_fetchall(query, (subdomain,))

    def _webs_for_domainid_portid(self, domain_id, port_id):
        query = "SELECT * FROM webs WHERE domain_id = %s AND port_id = %s"
        return self._execute_fetchone(query, (domain_id, port_id))

    def insert_webs(self, domain_id, port_id, url, response, title, metadata):
        query = "INSERT INTO webs (url, domain_id, port_id, response, title, metadata) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id"
        return self._insert_fetchone(query, (url, domain_id, port_id, response, title, metadata))

    def insert_or_update_webs(self, domain_id, port_id, url, response, title, metadata):
        existing_web = self._webs_for_domainid_portid(domain_id, port_id)
        if existing_web:
            return self.update_webs(domain_id, port_id, url, response, title, metadata)
        else:
            query = "INSERT INTO webs (url, domain_id, port_id, response, title, metadata) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id"
            return self._insert_fetchone(query, (url, domain_id, port_id, response, title, metadata))
    def update_webs(self, domain_id, port_id, url, response, title, metadata):
        query = "UPDATE webs SET url=%s, domain_id=%s, port_id=%s, response=%s, title=%s, metadata=%s WHERE domain_id=%s AND port_id=%s RETURNING id"
        return self._insert_fetchone(query, (url, domain_id, port_id, response, title, metadata, domain_id, port_id))