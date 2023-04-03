from runner import Runner
import datetime
import json

class SubdomainToolException(Exception):
    """Raised when a subdomain enum tool has a return code of non-zero"""
    pass

class SubdomainScannerRoot(object):
    """
    Root class for subdomain scanners
    """
    def __init__(self, maindomain):
        """
        Constructor for subdomain scanner root class

        :param maindomain: is the main domain name
        :var subdomains: is a list of subdomains
        :var _checked: is a list of processed subdomains
        :var domainobjects: is a list of domain objects of the type Domain
        """
        self.maindomain = maindomain
        self.subdomains = []
        self._checked = []
        self.domainobjects = []
        self._process = None
        self.running = False

    def checked(self, name):
        """Mark a subdomain as checked"""
        self._checked.append(name)

    def anyunchecked(self):
        """Returns True if there are any unchecked subdomains"""
        return not (all(item in self._checked for item in self.subdomains) and self.maindomain in self._checked)

    def nextunchecked(self):
        """Returns the next unchecked subdomain or None if there are unchecked subdomains

        :return: next unchecked subdomain or None
        """
        if not self.anyunchecked():
            return None
        if self.maindomain not in self._checked:
            return self.maindomain
        else:
            for i in self.subdomains:
                if i not in self._checked:
                    return i
        return None

    def allunchecked(self):
        """
        Returns a list of all unchecked subdomains

        :return: list of unchecked subdomains or empty list
        """
        ret = []
        if self.maindomain not in self._checked:
            ret.append(self.maindomain)
        for i in self.subdomains:
            if i not in self._checked:
                ret.append(i)
        return ret

    def start(self, recursive=False, depth=1):
        """
        Starts the subdomain scanner

        :param recursive: if True, the scanner will continue to scan subdomains of subdomains
        :param depth: how many levels of subdomains to scan
        """
        name = self.nextunchecked()
        ret = self._run(name)
        self.parse(ret)
        if recursive:
            curdepth = 0
            while curdepth < depth:
                jobs = self.allunchecked()
                for j in jobs:
                    ret = self._run(j)
                    self.parse(ret)
                curdepth += 1

    def parse(self):
        """This needs to be implemented in the child class"""
        pass

    def _run(self, name):
        """This needs to be implemented in the child class"""
        pass

    def _isnew(self, name):
        return name not in self._checked

    def _timestamp(self):
        return "{}".format(round(datetime.datetime.utcnow().timestamp() * 1000))

    def _tmpfilename(self):
        return "{}.json".format(self._timestamp())


class SubdomainScannerAmass(SubdomainScannerRoot):
    """
    Amass subdomain scanner
    """
    def __init__(self, maindomain):
        """Constructor for Amass subdomain scanner

        :param maindomain: is the main domain name
        """
        super(SubdomainScannerAmass, self).__init__(maindomain)

    def _run(self, name):
        """
        Runs amass for a given domain name

        :param name: domain name to run amass for
        :return: filepath to amass output file
        """

        tmpfile = self._tmpfilename()
        self._process = Runner("amass enum -d {} -passive -json {}".format(name, tmpfile))
        self.running = True
        self._process.start()
        self._process.waituntilready()
        self.running = False
        if self._process.exitcode() and self._process.exitcode() != 0:
            raise SubdomainToolException(self._process.error())
        self.checked(name)
        return tmpfile

    def kill(self):
        """Kills the amass process"""
        try:
            self._process.kill()
        except AttributeError:
            pass

    def parse(self, data):
        """
        Gets a filepath to amass output file as a parameter
        {"name":"yoooo.com","domain":"yoooo.com","addresses":null,"tag":"dns","sources":["DNS","Bing","Yahoo","Ask","DuckDuckGo","HyperStat"]}
        :param data: filepath to amass output file
        :return:
        """
        with open(data, 'r') as fh:
            rawdata = fh.readlines()
        for line in rawdata:
            jobj = json.loads(line)
            # amass reports wildcards as 2a, probably based on some underlying api
            checkname = jobj["name"].split(".")
            wildcard = False
            if checkname[0] == "2a":
                jobj["name"] = ".".join(checkname[1:])
                wildcard = True
            if jobj["name"] not in self.subdomains:
                self.subdomains.append(jobj["name"])
            newdomain = Domain(jobj["name"], jobj["sources"], jobj["tag"], wildcard)
            self.domainobjects.append(newdomain)


class Domain(object):
    """Domain object holds information about the domain name, sources, tag and if it's a wildcard
    """
    def __init__(self, name, sources, tag, wildcard=False):
        """Constructor for Domain object

        :param name: is the domain name
        :param sources: is a list of sources where the domain name was found
        :param tag: is the tag of the domain name
        :param wildcard: is a boolean that indicates if the domain name is a wildcard
        """
        self.name = name
        self.sources = sources
        self.tag = tag
        self.wildcard = wildcard
        self.resolved = False
        self.dns = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "ptr": [], "soa": [], "srv": [], "txt": []}

    def __repr__(self):
        return "Name: {} / Sources: {} / Tag: {} / Wildcard: {}".format(
            self.name, ",".join(self.sources), self.tag, self.wildcard)