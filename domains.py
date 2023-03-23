from runner import Runner
import datetime
import json

class SubdomainToolException(Exception):
    """Raised when a subdomain enum tool has a return code of non-zero"""
    pass

class SubdomainScannerRoot(object):
    def __init__(self, maindomain):
        self.maindomain = maindomain
        self.subdomains = []
        self._checked = []
        self.domainobjects = []

    def checked(self, name):
        self._checked.append(name)

    def anyunchecked(self):
        return not (all(item in self._checked for item in self.subdomains) and self.maindomain in self._checked)

    def nextunchecked(self):
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
        ret = []
        if self.maindomain not in self._checked:
            ret.append(self.maindomain)
        for i in self.subdomains:
            if i not in self._checked:
                ret.append(i)
        return ret

    def start(self, recursive=False, depth=1):
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
    def __init__(self, maindomain):
        super(SubdomainScannerAmass, self).__init__(maindomain)

    def _run(self, name):
        print("yay, running for {}".format(name))
        tmpfile = self._tmpfilename()
        r = Runner("amass enum -d {} -passive -json {}".format(name, tmpfile))
        r.start()
        r.waituntilready()
        if r.exitcode() and r.exitcode() != 0:
            raise SubdomainToolException(r.error())
        self.checked(name)
        return tmpfile

    def parse(self, data):
        """
        Gets a filepath to amass output file as a parameter
        {"name":"yoooo.com","domain":"yoooo.com","addresses":null,"tag":"dns","sources":["DNS","Bing","Yahoo","Ask","DuckDuckGo","HyperStat"]}
        :param data:
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
    def __init__(self, name, sources, tag, wildcard=False):
        self.name = name
        self.sources = sources
        self.tag = tag
        self.wildcard = wildcard

    def __repr__(self):
        return "Name: {} / Sources: {} / Tag: {} / Wildcard: {}".format(
            self.name, ",".join(self.sources), self.tag, self.wildcard)