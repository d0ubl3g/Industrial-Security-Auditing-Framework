import os
import readline
import atexit
from Exceptions.ISAFExceptions import ISAFException
from Utils.Printer import printer_queue
import Utils


class BaseInterpreter(object):
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        if not os.path.exists(self.history_file):
            open(self.history_file, 'a+').close()

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

        readline.parse_and_bind('set enable-keypad on')

        readline.set_completer(self.complete)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")

    @staticmethod
    def parse_line(line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument)
        """
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            try:
                command_handler = getattr(self.current_module, "command_{}".format(command))
            except AttributeError:
                raise ISAFException("Unknown command: '{}'".format(command))
        return command_handler

    def start(self):
        """ icssploit main entry point. Starting interpreter loop. """

        Utils.print_info(self.banner)
        printer_queue.join()
        while True:
            try:
                command, args = self.parse_line(input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args)
            except ISAFException as err:
                Utils.print_error(err)
            except EOFError:
                Utils.print_info()
                Utils.print_status("ISAF stopped.")
                break
            except KeyboardInterrupt:
                Utils.print_info()
            finally:
                printer_queue.join()

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args = self.parse_line(line)
                if cmd == '':
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, 'complete_' + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer
        self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return filter(lambda entry: entry.startswith(text), self.suggested_commands())

    @staticmethod
    def default_completer(*ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()

