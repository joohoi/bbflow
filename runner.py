import subprocess
import time

class Runner(object):
    def __init__(self, command, stdin=None):
        self.command = command.split(" ")
        self.started = False
        self.proc = None
        self._stdin = stdin
        self._output = ""
        self._error = ""

    def start(self):
        self.proc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
        self.started = True
        if self._stdin:
            self.proc.communicate(input=self._stdin)

    def running(self):
        if self.started:
            if self.proc.poll() == None:
                return True
        return False

    def exitcode(self):
        if self.started:
            return self.proc.poll()
        return None

    def output(self):
        self._update()
        return self._output

    def waituntilready(self):
        while self.running():
            time.sleep(0.01)

    def _update(self):
        if self.started:
            output, error = self.proc.communicate()
            self._output = output
            self._error = error

    def error(self):
        self._update()
        return self._error