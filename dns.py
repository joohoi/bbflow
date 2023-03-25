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

    def resolve(self):
        """
        Does the DNS resolution using the dnsx command line tool
        """
        runner = Runner("dnsx -a -aaaa -cname -txt -ns -resp -json", stdin=self.domain)
        runner.start()
        while runner.running():
            time.sleep(0.01)
        if runner.exitcode() != 0:
            raise DnsResolutionException("dnsx failed with exit code {}".format(runner.exitcode()))
        if runner.output() == "":
            # Domain was not resolvable
            raise DnsResolutionNotFound("dnsx failed to resolve {}".format(self.domain))
        try:
            output = json.loads(runner.output())
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