"""Portscanner implementation using nmap"""
import ipaddress
import time
from datetime import datetime

import xml.etree.ElementTree as ET


from runner import Runner


class PortScannerException(Exception):
    pass


class PortScanner(object):
    """Port scanner that uses nmap, scans a given single host,
    range of hosts or a list of individual hosts for all ports.
    The output format used should be XML and the output file name should be a
    timestamped file name. The output XML file is parsed in a separate parsing function
    and port number, protocol and service information should be stored in a list of Host and Port objects.
    The Port objects should be within the Host objects.
    """

    def __init__(self, hosts, ports=None, topports=1000):
        """Constructor for PortScanner class

        :param hosts: list of ip addresses to scan
        :param ports: is the list of ports to scan
        """
        self.hosts = hosts
        self.ports = ports
        self.topports = topports
        self.running = False
        self._process = None

    def scan(self):
        """
        Creates a temporary file which is a newline separated list of hosts to scan. Runs command "nmap -sS -sV -script vulners --script-args mincvss=6.0 -p<ports> -iL <tempfile> -oX <timestampedfile>" using Runner class. Returns the name of the timestamped file.
        """
        timestamped_filename = "{}.xml".format(round(datetime.utcnow().timestamp() * 1000))
        with open("tempfile.txt", "w") as f:
            for host in self.hosts:
                f.write(host + "\n")
        whichports = ""
        if self.ports is None:
            whichports = "--top-ports {}".format(self.topports)
        else:
            whichports = "-p{}".format(self.ports)

        self._process = Runner("nmap -sC --host-timeout 5m -T4 -iL tempfile.txt {} -oX {}".format(whichports, timestamped_filename))
        self.running = True
        self._process.start()
        while self._process.running():
            time.sleep(0.01)
            if self._process.run_time() > 5 * 60 * len(self.hosts):
                # Process has most likely halted, as we have --host-timeout 5m
                self._process.kill()
                self.running = False
                raise PortScannerException("nmap froze, and was killed")
        self.running = False
        if self._process.exitcode() != 0:
            output = ""
            if self._process.output():
                output = self._process.output()
            if self._process.error():
                output += "\n" + self._process.error()
            raise PortScannerException("nmap failed with exit code {}: {}".format(self._process.exitcode(), output))
        return timestamped_filename

    def kill(self):
        """Kills the nmap process"""
        if self.running:
            self._process.kill()

    """def parse(self, filename):

        :param filename: is the name of the XML file to parse
        :return: a list of Host objects
        
        with open(filename, 'r') as fh:
            data = fh.read()
        parsed_data = xmltodict.parse(data)
        hosts = parsed_data['nmaprun']['host']
        hosts_list = []
        if type(hosts) is dict:
            # single host result
            hosts_list.append(self._parse_host(hosts))
        elif type(hosts) is list:
            # multiple hosts result
            for host in hosts:
                hosts_list.append(self._parse_host(host))
        return hosts_list
    """
    def parse(self, in_xml):
        results = []
        xml_tree = ET.parse(in_xml)
        xml_root = xml_tree.getroot()
        for host in xml_root.findall('host'):
            port_list = []
            ip = host.find('address').get('addr')
            ports = host.findall('ports')[0].findall('port')
            for port in ports:
                state = port.find('state').get('state')
                if state == 'open':
                    port_id = port.attrib['portid']
                    protocol = port.attrib['protocol']
                    service_name = port.find('service').get('product')
                    if service_name is None:
                        service_name = port.find('service').get('name')
                    service_product = port.find('service').get('product')
                    if service_product is None:
                        service_product = ''
                    service_version = port.find('service').get('version')
                    if service_version is None:
                        service_version = ''
                    port_list.append(Port(port_id, protocol, service_name, service_product, service_version))
            if port_list:
                results.append(Host(ip, port_list))
        return results

    """def _parse_host(self, host):

        ip = host['address']['@addr']
        ports = host['ports']['port']
        ports_list = []
        for port in ports:
            port_number = port['@portid']
            protocol = port['@protocol']
            service = port['service']['@name']
            product = port['service']['@product']
            version = port['service']['@version']

            ports_list.append(Port(port_number, protocol, service, product, version))
        return Host(ip, ports_list)"""

class Host(object):
    """A host object representing a single IPv4 or IPv6 address.
    A host can have multiple open ports, it should be a list of Port objects.
    It should have a variable and a function to determine if it's a Ipv4 or IPv6 address.
    """
    def __init__(self, ip, ports=[]):
        """Constructor for Host class

        :param ip: is the IPv4 or IPv6 address
        :param ports: is a list of Port objects

        :var ip: is the IPv4 or IPv6 address
        :var ports: is a list of Port objects
        """
        self.ip = ip
        self.ports = ports
    def __str__(self):
        return "Host: {}, Ports: {}".format(self.ip, self.ports)

    def __repr__(self):
        return self.__str__()

    def is_ipv4(self):
        """
        Returns True if self.ip is a ipv4 family address, False otherwise.

        :return: True if self.ip is a ipv4 family address, False otherwise.
        """
        try:
            ipaddress.IPv4Address(self.ip)
            return True
        except ipaddress.AddressValueError:
            return False


    def is_ipv6(self):
        """Returns True if self.ip is a ipv6 family address, False otherwise.

        :return: True if self.ip is a ipv6 family address, False otherwise.
        """
        try:
            ipaddress.IPv6Address(self.ip)
            return True
        except ipaddress.AddressValueError:
            return False
        pass

class Port(object):
    """A port object representing a single port number, protocol, service name and service banner"""
    def __init__(self, port, protocol="", service="", product="", version="", vulns=""):
        """Constructor for Port class

        :param port: is the port number
        :param protocol: is the protocol
        :param service: is the service name
        :param product: is the service banner
        :param version: is the service version
        :param vulns: vulners output
        """
        self.port = port
        self.protocol = protocol
        self.service = service
        self.product = product
        self.version = version
        self.vulns = vulns
    def __str__(self):
        return "Port: {}, Protocol: {}, Service: {}, Product: {}, Version: {}, Vulns: {}".format(self.port, self.protocol, self.service, self.product, self.version, self.vulns)

    def __repr__(self):
        return self.__str__()