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

    def host_by_ip(self, ip):
        query = "SELECT * FROM hosts WHERE address = %s"
        return self._execute_fetchone(query, (ip,))

    def project_by_name(self, name):
        query = "SELECT * FROM projects WHERE name = %s"
        return self._execute_fetchone(query, (name,))

    def domain_by_name(self, name):
        query = "SELECT * FROM domains WHERE name = %s"
        return self._execute_fetchone(query, (name,))

    def insert_host(self, address, family):
        query = "INSERT INTO hosts (address, family) VALUES (%s, %s) ON CONFLICT (address) DO UPDATE SET address=excluded.address RETURNING id"
        return self._insert_fetchone(query, (address, family))

    def insert_domain(self, name, project, sources=""):
        query = "INSERT INTO domains (name, sources, project_id) VALUES (%s, %s, %s) ON CONFLICT (name) DO UPDATE SET name=excluded.name RETURNING id"
        return self._insert_fetchone(query, (name, sources, project))

    def insert_host_for_domainname(self, domain, address, family):
        dres = self.domain_by_name(domain)
        hres = self.insert_host(address, family)
        query = "INSERT INTO domains_hosts (domains_id, hosts_id) VALUES (%s, %s) RETURNING id"
        return self._insert_fetchone(query, (dres["id"], hres["id"]))

    def fetch_port(self, port, host):
        hres = self.host_by_ip(host)
        query = "SELECT * FROM ports WHERE number = %s AND host_id = %s"
        return self._execute_fetchone(query, (port, hres["id"]))

    def insert_port(self, port, protocol, service, product, version, host_id):
        query = "INSERT INTO ports (number, protocol, service, product, version, host_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id"
        return self._insert_fetchone(query, (port, protocol, service, product, version, host_id))

    def insert_port_for_host(self, port, protocol, service, product, version, host):
        hres = self.host_by_ip(host)
        existing_port = self.fetch_port(port, hres["address"])
        if not existing_port:
            return self.insert_port(port, protocol, service, product, version, hres["id"])
        else:
            return {}
    def all_domains_by_projectid(self, project_id):
        query = "SELECT * FROM domains WHERE project_id = %s"
        return self._execute_fetchall(query, (project_id,))

    def all_ports_for_subdomain(self, subdomain):
        query = "SELECT * FROM ports p INNER JOIN hosts h ON p.host_id = h.id INNER JOIN domains_hosts dh ON h.id = dh.hosts_id INNER JOIN domains d ON d.id = dh.domains_id WHERE d.name = %s"
        return self._execute_fetchall(query, (subdomain,))