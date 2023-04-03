"""Class for DNS resolution"""
import json
import time

from runner import Runner


class DnsResolutionException(Exception):
    pass


class DnsResolutionNotFound(Exception):
    pass


class DnsResolution(object):
    """Class that does DNS resolution for a given domain name for A, AAAA, CNAME, TXT and NS records using a command line tool dnsx"""
    def __init__(self, domain):
        """
        Constructor for DnsResolution class

        :param domain: is the domain name
        :var domain: is the domain name
        :var _a: is a list of A records
        :var _aaaa: is a list of AAAA records
        :var _cname: is a list of CNAME records
        :var _txt: is a list of TXT records
        :var _ns: is a list of NS records
        """
        self.domain = domain
        self._a = []
        self._aaaa = []
        self._cname = []
        self._txt = []
        self._ns = []
        self._mx = []
        self._ptr = []
        self._soa = []
        self._srv = []
        self._process = None
        self.running = False

    def resolve(self):
        """
        Does the DNS resolution using the dnsx command line tool
        """
        self._process = Runner("dnsx -a -aaaa -cname -txt -ns -mx -soa -ptr -srv -resp -json", stdin=self.domain)
        self.running = True
        self._process.start()
        while self._process.running():
            time.sleep(0.01)
        self.running = False
        if self._process.exitcode() != 0:
            raise DnsResolutionException("dnsx failed with exit code {}".format(self._process.exitcode()))
        if self._process.output() == "":
            # Domain was not resolvable
            raise DnsResolutionNotFound("dnsx failed to resolve {}".format(self.domain))
        try:
            output = json.loads(self._process.output())
        except ValueError:
            raise DnsResolutionException("dnsx failed with invalid output")

        for i in self._extract_field("a", output):
            self._a.append(i)
        for i in self._extract_field("aaaa", output):
            self._aaaa.append(i)
        for i in self._extract_field("cname", output):
            self._cname.append(i)
        for i in self._extract_field("txt", output):
            self._txt.append(i)
        for i in self._extract_field("ns", output):
            self._ns.append(i)
        for i in self._extract_field("mx", output):
            self._mx.append(i)
        for i in self._extract_field("ptr", output):
            self._ptr.append(i)
        for i in self._extract_field("soa", output):
            self._soa.append(i)
        for i in self._extract_field("srv", output):
            self._srv.append(i)

    def kill(self):
        """
        Kills the running process
        """
        if self.running:
            self._process.kill()

    def _extract_field(self, fieldname, data):
        """
        Extracts a field from the data

        :param fieldname: is the name of the field to extract
        :param data: is the data to extract the field from
        :return: the value of the field
        """
        try:
            return data[fieldname]
        except KeyError:
            return []

    def did_resolve(self):
        return any([self._a, self._aaaa, self._cname, self._txt, self._ns, self._mx, self._ptr, self._soa, self._srv])

    def a(self):
        """
        Returns a list of A records

        :return: list of A records
        """
        return self._a

    def aaaa(self):
        """
        Returns a list of AAAA records

        :return: list of AAAA records
        """
        return self._aaaa

    def cname(self):
        """
        Returns a list of CNAME records

        :return: list of CNAME records
        """
        return self._cname

    def txt(self):
        """
        Returns a list of TXT records

        :return: list of TXT records
        """
        return self._txt

    def ns(self):
        """
        Returns a list of NS records

        :return: list of NS records
        """
        return self._ns

    def mx(self):
        """
        Returns a list of MX records

        :return: list of MX records
        """
        return self._mx

    def ptr(self):
        """
        Returns a list of PTR records

        :return: list of PTR records
        """
        return self._ptr

    def soa(self):
        """
        Returns a list of SOA records

        :return: list of SOA records
        """
        return self._soa

    def srv(self):
        """
        Returns a list of SRV records

        :return: list of SRV records
        """
        return self._srv