import time
import pathlib

from runner import Runner


class WebTechDetectException(Exception):
    pass


class WebTechDetect(object):
    def __init__(self, domain, ports):
        self.domain = domain
        self.ports = ports

    def start(self):
        tmpdir = "./techdetect"
        pathlib.Path(tmpdir).mkdir(parents=True, exist_ok=True)
        r = Runner("httpx -sc -cl -ct -favicon -hash -title -server -td -ip -random-agent -cdn -json -srd {} -p {}".format(
            tmpdir, self.ports), stdin=self.domain)
        r.start()
        while r.running():
            time.sleep(0.01)
        if r.exitcode() != 0:
            raise WebTechDetectException("httpx failed with exit code {}: {}\n{}".format(r.exitcode(), r.output(), r.error()))
        if r.output() == "":
            raise WebTechDetectException("httpx failed to detect any web technologies (no output) for {}".format(self.domain))
        print("---------------------------------------\n{}\n---------------------------------------".format(r.output()))

    def _parse(self, data):
        pass

class WebResponse(object):
    def __init__(self, domain, port, title, response, metadata):
        self.domain = domain
        self.port = port
        self.title = title
        self.response = response
        self.metadata = metadata