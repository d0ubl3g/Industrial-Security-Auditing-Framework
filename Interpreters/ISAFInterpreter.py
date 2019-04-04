import os
from Interpreters import BaseInterpreter


class ISAFInterpreter(BaseInterpreter):
    history_file = os.path.expanduser("~/.isaf_history")
    global_help = """
    ISAF General Commands:
    help                        Print this help menu.
    use <module>                Select a module for usage.
    exec <shell command> <args> Execute a command in a shell.
    search <term>               Search for appropriate module.
    exit                        Exit ISAF.
    """

    module_help = """
    Modules Commands:
    run                                 Run the selected module.
    back                                De-Select the current module.
    set <option> <value>                Set an option for the selected module.
    unset <option> <value>              Unset an option for the selected module.
    gset <option name> <option value>   Set a global option for all of the modules.
    gunset <option name>                Unset a global option.
    show [info|options|devices]         Print information, options, or target devices for a module.
    check                               Check if a given target is vulnerable to a selected module's exploit.
    """

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        s='s'
