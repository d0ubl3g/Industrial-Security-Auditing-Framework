import itertools
import os
import sys
import traceback
from collections import Counter

from colorama import Fore, Style

import Utils
from Base import Clients
from Base import Exploits
from Exceptions.ISAFExceptions import ISAFException
from Interpreters.BaseInterpreter import BaseInterpreter
from Utils.Printer import PrinterThread


class ISAFInterpreter(BaseInterpreter):
    history_file = os.path.expanduser("~/.isaf_history")
    global_help = Style.BRIGHT + """
    ISAF Commands:""" + Style.NORMAL + """
    help                                Print this help menu.
    use <module>                        Select a module for usage.
    exec <shell command> <args>         Execute a system command.
    search <term>                       Search for appropriate module.
    show all                            Show all available modules.
    update                              Update ISAF.
    exit                                Exit ISAF.
    """

    module_help = Style.BRIGHT + """
    Modules Commands:""" + Style.NORMAL + """
    run                                 Run the selected module.
    back                                De-Select the current module.
    set <option> <value>                Set an option for the selected module.
    unset <option> <value>              Unset an option for the selected module.
    gset <option name> <option value>   Set a global option for all of the modules.
    gunset <option name>                Unset a global option.
    show [info|options|devices]         Print information, options, or target devices for a module.
    check                               Check if a given target is vulnerable to a selected module's exploit.
    """

    def __init__(self, extra_package_path=None):
        super(ISAFInterpreter, self).__init__()
        PrinterThread().start()
        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = 'ISAF'
        self.show_sub_commands = ('info', 'options', 'devices', 'all', 'Credentials', 'Exploits', 'Scanners',
                                  'Discovery')
        self.global_commands = sorted(['use ', 'exec ', 'help', 'exit', 'show ', 'search '])
        self.module_commands = ['run', 'back', 'set ', 'unset ', 'gset ', 'gunset ', 'check', 'connect']
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()
        self.extra_modules_dir = None
        self.extra_modules_dirs = None
        self.extra_modules = []
        self.extra_package_path = extra_package_path
        self.import_extra_package()
        self.modules = Utils.index_modules()
        self.modules += self.extra_modules
        self.modules_count = Counter()
        [self.modules_count.update(module.split('.')) for module in self.modules]
        self.main_modules_dirs = [module for module in os.listdir(Utils.MODULES_DIR) if not module.startswith("__")]
        self.__parse_prompt()

        self.banner = Fore.BLUE + """ 
             ▄█     ▄████████    ▄████████    ▄████████ 
            ███    ███    ███   ███    ███   ███    ███ 
            ███▌   ███    █▀    ███    ███   ███    █▀  
            ███▌   ███          ███    ███  ▄███▄▄▄     
            ███▌ ▀███████████ ▀███████████ ▀▀███▀▀▀     
            ███           ███   ███    ███   ███        
            ███     ▄█    ███   ███    ███   ███        
            █▀    ▄████████▀    ███    █▀    ███""" \
                      + Fore.GREEN + " v{version} \n" \
                      + Fore.LIGHTYELLOW_EX + """
             Industrial Security Auditing Framework
               D0ubl3G <d0ubl3g[at]protonmail.com>\n""" \
                      + Fore.RED + """
                           -> WARNING <-
               ISAF IS IN EARLY DEVELOPMENT PHASE.
            SHOULD NOT USE IN PRODUCTION ENVIRONMENTS.\n""" \
                      + Fore.RESET + Style.BRIGHT + """
        Modules""" + Style.NORMAL + """
           Clients: """ + Fore.GREEN + """{clients_count}""" + Fore.RESET \
                      + """      Exploits: """ + Fore.GREEN + """{exploits_count}""" + Fore.RESET \
                      + """      Discovery: """ + Fore.GREEN + """{discovery_count}""" + Fore.RESET + """ 
           Scanners: """ + Fore.GREEN + """{scanners_count}""" + Fore.RESET \
                      + """     Credentials: """ + Fore.GREEN + """{creds_count}""" + Fore.RESET \
                      + Style.BRIGHT + """\n
        Exploits""" + Style.NORMAL + """
           PLC: """ + Fore.GREEN + """{plc_exploit_count}""" + Fore.RESET \
                      + """          Switch: """ + Fore.GREEN + """{ics_switch_exploits_count}""" + Fore.RESET \
                      + """        Software: """ + Fore.GREEN + """{ics_software_exploits_count}""" + Fore.RESET \
                      + """\n\n"""

        self.banner = self.banner.format(version="0.0.1a", clients_count=self.modules_count['Clients'],
                                         exploits_count=self.modules_count['Exploits'] + self.modules_count[
                                             'extra_exploits'],
                                         discovery_count=self.modules_count['Discovery'] + self.modules_count[
                                             'extra_discovery'],
                                         scanners_count=self.modules_count['Scanners'] + self.modules_count[
                                             'extra_scanners'],
                                         creds_count=self.modules_count['Credentials'] + self.modules_count[
                                             'extra_creds'],
                                         plc_exploit_count=self.modules_count['plcs'],
                                         ics_switch_exploits_count=self.modules_count['ics_switchs'],
                                         ics_software_exploits_count=self.modules_count['ics_software']
                                         )

    def __parse_prompt(self):
        raw_prompt_default_template = Style.BRIGHT + Fore.BLUE + "{host}" + Fore.RESET + " > " + Style.NORMAL
        raw_prompt_template = os.getenv("ISAF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template
        module_prompt_default_template = Style.BRIGHT + Fore.BLUE + "{host}" + Fore.RESET + " (" + Fore.LIGHTBLUE_EX \
                                         + "{module}" + Fore.RESET + Style.NORMAL + ") > "
        module_prompt_template = os.getenv("ISAF_MODULE_PROMPT", module_prompt_default_template).replace('\\033',
                                                                                                         '\033')
        self.module_prompt_template = module_prompt_template if all(
            map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    @property
    def module_metadata(self):
        return getattr(self.current_module, "_{}__info__".format(self.current_module.__class__.__name__))

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname,
                                                          module=self.module_metadata['name'])
            except (AttributeError, KeyError) as e:
                Utils.print_error(e)
                return self.module_prompt_template.format(host=self.prompt_hostname, module="Unknown")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def import_extra_package(self):
        if self.extra_package_path:
            extra_modules_dir = os.path.join(self.extra_package_path, "extra_modules")
            if os.path.isdir(extra_modules_dir):
                self.extra_modules_dir = extra_modules_dir
                self.extra_modules_dirs = [module for module in os.listdir(self.extra_modules_dir) if
                                           not module.startswith("__")]
                self.extra_modules = Utils.index_extra_modules(modules_directory=self.extra_modules_dir)
                print("extra_modules_dir:%s" % self.extra_modules_dir)
                sys.path.append(self.extra_package_path)
                sys.path.append(self.extra_modules_dir)
        else:
            return

    def available_modules_completion(self, text):
        """ Looking for tab completion hints using setup.py entry_points.

        May need optimization in the future!

        :param text: argument of 'use' command
        :return: list of tab completion hints
        """
        text = Utils.pathToDots(text)
        all_possible_matches = filter(lambda x: x.startswith(text), self.modules)
        matches = set()
        for match in all_possible_matches:
            head, sep, tail = match[len(text):].partition('.')
            if not tail:
                sep = ""
            matches.add("".join((text, head, sep)))
        return list(map(Utils.dotsToPath, matches))  # humanize output, replace dots to forward slashes

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        if (self.current_module and Exploits.GLOBAL_OPTS) or (self.current_module and Clients.GLOBAL_OPTS):
            return sorted(itertools.chain(self.module_commands, ('gunset ',)))
        elif self.current_module:
            custom_commands = [command.rsplit("_").pop() for command in dir(self.current_module)
                               if command.startswith("command_")]
            self.module_commands.extend(custom_commands)
            return self.module_commands
        else:
            return self.global_commands

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_use(self, module_path, *args, **kwargs):
        if module_path.startswith("extra_"):
            module_path = Utils.pathToDots(module_path)
        else:
            module_path = Utils.pathToDots(module_path)
            module_path = '.'.join(('Modules', module_path))
        try:
            self.current_module = Utils.import_exploit(module_path)()
        except ISAFException as err:
            Utils.print_error(err)

    @Utils.stopAfter(2)
    def complete_use(self, text, *args, **kwargs):
        if text:
            return self.available_modules_completion(text)
        else:
            if self.extra_modules_dirs:
                return self.main_modules_dirs + self.extra_modules_dirs
            else:
                return self.main_modules_dirs

    @Utils.moduleRequired
    def command_run(self, *args, **kwargs):
        Utils.print_status("Running module...")
        try:
            self.current_module.run()
        except KeyboardInterrupt:
            Utils.print_info()
            Utils.print_error("Operation cancelled by user.")
        except:
            Utils.print_error(traceback.format_exc(sys.exc_info()))

    def command_exploit(self, *args, **kwargs):
        self.command_run()

    def command_connect(self, *args, **kwargs):
        self.command_run()

    @Utils.moduleRequired
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        if key in self.current_module.options:
            setattr(self.current_module, key, value)
            if kwargs.get("glob", False):
                Exploits.GLOBAL_OPTS[key] = value
                Clients.GLOBAL_OPTS[key] = value
            Utils.print_success({key: value})
        else:
            Utils.print_error("You can't set option '{}'.\n"
                              "Available options: {}".format(key, self.current_module.options))

    @Utils.stopAfter(2)
    def complete_set(self, text, *args, **kwargs):
        if text:
            return [' '.join((attr, "")) for attr in self.current_module.options if attr.startswith(text)]
        else:
            return self.current_module.options

    @Utils.moduleRequired
    def command_gset(self, *args, **kwargs):
        kwargs['glob'] = True
        self.command_set(*args, **kwargs)

    @Utils.stopAfter(2)
    def complete_gset(self, text, *args, **kwargs):
        return self.complete_set(text, *args, **kwargs)

    @Utils.moduleRequired
    def command_gunset(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        try:
            del Exploits.GLOBAL_OPTS[key]
            del Clients.GLOBAL_OPTS[key]
        except KeyError:
            Utils.print_error("You can't unset global option '{}'.\n"
                              "Available global options: {}".format(key, Exploits.GLOBAL_OPTS.keys()))
        else:
            Utils.print_success({key: value})

    @Utils.stopAfter(2)
    def complete_gunset(self, text, *args, **kwargs):
        if text:
            return [' '.join((attr, "")) for attr in Exploits.GLOBAL_OPTS.keys() if attr.startswith(text)]
        else:
            return Exploits.GLOBAL_OPTS.keys()

    @Utils.moduleRequired
    def get_opts(self, *args):
        """ Generator returning module's Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key]
                opt_value = getattr(self.current_module, opt_key)
            except (KeyError, AttributeError):
                pass
            else:
                yield opt_key, opt_value, opt_description

    @Utils.moduleRequired
    def _show_info(self, *args, **kwargs):
        Utils.pprint_dict_in_order(
            self.module_metadata,
            ("display_name", "name", "description", "devices", "authors", "references"),
        )
        Utils.print_info()

    @Utils.moduleRequired
    def _show_options(self, *args, **kwargs):
        target_opts = ['target', 'port']
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Value", "Description")

        Utils.print_info(Style.BRIGHT + "\nTarget:" + Style.NORMAL)
        Utils.printTable(headers, *self.get_opts(*target_opts))

        if module_opts:
            Utils.print_info(Style.BRIGHT + "\nModule:" + Style.NORMAL)
            Utils.printTable(headers, *self.get_opts(*module_opts))

        Utils.print_info()

    @Utils.moduleRequired
    def _show_devices(self, *args, **kwargs):  # TODO: cover with tests
        try:
            devices = self.current_module._Exploit__info__['devices']

            Utils.print_info(Style.BRIGHT + "\nDevices:" + Style.NORMAL)
            i = 0
            for device in devices:
                if isinstance(device, dict):
                    Utils.print_info("   {} - {}".format(i, device['name']))
                else:
                    Utils.print_info("   {} - {}".format(i, device))
                i += 1
            Utils.print_info()
        except KeyError:
            Utils.print_info("\nTarget devices not defined.")

    def __show_modules(self, root=''):
        for module in [module for module in self.modules if module.startswith(root)]:
            Utils.print_info(module.replace('.', os.sep))

    def _show_all(self, *args, **kwargs):
        self.__show_modules()

    def _show_scanners(self, *args, **kwargs):
        self.__show_modules('Scanners')

    def _show_exploits(self, *args, **kwargs):
        self.__show_modules('Exploits')

    def _show_creds(self, *args, **kwargs):
        self.__show_modules('Credentials')

    def _show_discovery(self, *args, **kwargs):
        self.__show_modules('Discovery')

    def _show_clients(self, *args, **kwargs):
        self.__show_modules('Clients')

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        try:
            getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
        except AttributeError as e:
            Utils.print_error("Unknown 'show' sub-command '{}'. "
                              "What do you want to show?\n"
                              "Possible choices are: {}".format(sub_command, self.show_sub_commands))

    @Utils.stopAfter(2)
    def complete_show(self, text, *args, **kwargs):
        if text:
            return [command for command in self.show_sub_commands if command.startswith(text)]
        else:
            return self.show_sub_commands

    @Utils.moduleRequired
    def command_check(self, *args, **kwargs):
        try:
            result = self.current_module.check()
        except Exception as error:
            Utils.print_error(error)
        else:
            if result is True:
                Utils.print_success("Target is vulnerable.")
            elif result is False:
                Utils.print_error("Target is not vulnerable.")
            else:
                Utils.print_status("Target could not be verified.")

    def command_help(self, *args, **kwargs):
        Utils.print_info(self.global_help)
        if self.current_module:
            Utils.print_info(self.module_help)

    @staticmethod
    def command_exec(*args, **kwargs):
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        keyword = args[0]

        if not keyword:
            Utils.print_error("Please specify search keyword. e.g. 'search plc'")
            return

        for module in self.modules:
            if keyword.lower() in module.lower():
                module = Utils.dotsToPath(module)
                Utils.print_info(
                    "{}\033[31m{}\033[0m{}".format(*module.partition(keyword))
                )

    def command_exit(self, *args, **kwargs):
        raise EOFError
