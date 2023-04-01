import subprocess
import time

class Runner(object):
    """
    Class for running external commands
    """
    def __init__(self, command, stdin=None):
        """
        Constructor for Runner class

        :param command: is the command to run
        :param stdin: is the input to the command

        :var command: is the command to run
        :var started: is True if the command has been started
        :var proc: is the subprocess object
        :var _stdin: is the input to the command
        :var _output: is the output of the command
        :var _error: is the error output of the command
        """
        self.command = command.split(" ")
        self.started = False
        self.proc = None
        self._stdin = stdin
        self._output = ""
        self._error = ""
        self.start_time = 0

    def start(self):
        """
        Starts the command
        """
        self.proc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
        self.started = True
        self.start_time = time.time()
        if self._stdin:
            self.proc.communicate(input=self._stdin)

    def running(self):
        """
        Returns True if the command is running

        :return: True if the command is running
        """
        if self.started:
            if self.proc.poll() == None:
                return True
        return False

    def exitcode(self):
        """
        Returns the exit code of the command or None if the command is still running

        :return: exit code of the command or None
        """
        if self.started:
            return self.proc.poll()
        return None

    def output(self):
        """
        Returns the output of the command

        :return: output of the command
        """
        self._update()
        return self._output

    def waituntilready(self):
        """
        Waits until the command is ready
        """
        while self.running():
            time.sleep(0.01)

    def _update(self):
        """
        Updates the output and error variables
        """
        if self.started:
            output, error = self.proc.communicate()
            self._output = output
            self._error = error

    def error(self):
        """
        Returns the error output of the command
        """
        self._update()
        return self._error

    def run_time(self):
        """
        Returns the runtime of the command
        """
        return int(time.time() - self.start_time)

    def kill(self):
        """
        Kills the command
        """
        self.proc.kill()