import time
import pathlib
import json

from runner import Runner


class WebTechDetectException(Exception):
    pass


class WebTechDetect(object):
    def __init__(self, domain, ports):
        self.domain = domain
        self.ports = ports
        self.running = False
        self._process = None

    def start(self):
        tmpdir = "./techdetect"
        pathlib.Path(tmpdir).mkdir(parents=True, exist_ok=True)
        self._process = Runner("httpx -sc -cl -ct -favicon -hash -title -server -td -ip -random-agent -cdn -json -srd {} -p {}".format(
            tmpdir, self.ports), stdin=self.domain)
        self.running = True
        self._process.start()
        while self._process.running():
            time.sleep(0.01)
        self.running = False
        if self._process.exitcode() != 0:
            raise WebTechDetectException("httpx failed with exit code {}: {}\n{}".format(
                self._process.exitcode(), self._process.output(), self._process.error()))
        if self._process.output() == "":
            raise WebTechDetectException("httpx failed to detect any web technologies (no output) for {}".format(self.domain))
        outputs = []
        for line in self._process.output().splitlines():
            outputs.append(self._parse(line))
        return outputs

    def kill(self):
        if self.running:
            self._process.kill()

    def _parse(self, data):
        entry = json.loads(data)
        try:
            url = entry["url"]
        except KeyError:
            url = ""
        try:
            domain = entry["input"]
        except KeyError:
            domain = ""
        try:
            port = int(entry["port"])
        except KeyError:
            port = 0
        try:
            title = entry["title"]
        except KeyError:
            title = ""
        try:
            response = ""
            responsefn = entry["stored_response_path"]
            with open(responsefn, "r") as f:
                response = f.read()
        except KeyError:
            pass
        return WebResponse(domain, port, url, title, response, entry)


class WebResponse(object):
    def __init__(self, domain, port, url, title, response, metadata):
        self.domain = domain
        self.port = port
        self.url = url
        self.title = title
        self.response = response
        self.metadata = metadata

    def __str__(self):
        return "{} - {}".format(self.url, self.title)
    def __repr__(self):
        return self.__str__()