import os
import readline
import atexit
from Exceptions.ISAFExceptions import ISAFException


class BaseInterpreter(object):
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        if not os.path.exists(self.history_file):
            open(self.history_file, 'a+').close()
        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)
        readline.parse_and_bind('set enable-keypad on')
        readline.set_completer(self.complete)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")

    def parseLine(self, line):
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        return ">>>"

    def getCommandHandler(self, command):
        try:
            commandHandler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise ISAFException("Unknown command: '{}'".format(command))
        return commandHandler

    def start(self):



