
# Nimbo-C2

<p align="center">
  <img alt="Nimbo" src="/assets/nimbo.png">
</p>

- [Nimbo-C2](#nimbo-c2)
- [About](#about)
- [Features](#features)
- [Installation](#installation)
  - [Easy Way](#easy-way)
  - [Easier Way](#easier-way)
- [Usage](#usage)
  - [Main Window](#main-window)
  - [Agent Window](#agent-window)
    - [Windows agent](#windows-agent)
    - [Linux agent](#linux-agent)
- [Limitations \& Warnings](#limitations--warnings)
- [Contribution](#contribution)
- [Credits](#credits)

# About

*Nimbo-C2 is yet another (simple and lightweight) C2 framework.*

![](/assets/ui.png)

Nimbo-C2 agent supports x64 Windows & Linux. It's written in Nim, with some usage of .NET on Windows (by dynamically loading the CLR to the process). Nim is powerful, but interacting with Windows is much easier and robust using Powershell, hence this combination is made. The Linux agent is slimier and capable only of basic commands, including ELF loading using the `memfd` technique.

All server components are written in Python:
- HTTP listener that manages the agents.
- Builder that generates the agent payloads. 
- Nimbo-C2 is the interactive C2 component that rule'em all!

My work wouldn't be possible without the previous great work done by others, listed under credits.

# Features

- Build EXE, DLL, ELF payloads.
- Encrypted implant configuration and strings using [NimProtect](https://github.com/itaymigdal/NimProtect).
- Packing payloads using [UPX](https://github.com/upx/upx) and obfuscate the PE section names (`UPX0`, `UPX1`) to make detection and unpacking harder.
- Encrypted HTTP communication (AES in CBC mode, key hardcoded in the agent and configurable by the `config.jsonc`).
- Auto-completion in the C2 Console for convenient interaction.  
- In-memory Powershell commands execution.
- File download and upload commands.
- Built-in discovery commands.
- Screenshot taking, clipboard stealing, audio recording, and keylogger.
- ETW & AMSI patching using indirect syscalls.
- LSASS and SAM hives dumping. 
- Shellcode injection using indirect syscalls.
- Inline .NET assemblies execution.
- Persistence capabilities.
- UAC bypass methods.
- ELF loading using `memfd` in 2 modes.
- And more !

# Installation

## Easy Way

1. Clone the repository and `cd` in
```
git clone https://github.com/itaymigdal/Nimbo-C2
cd Nimbo-C2
```
2. Build the docker image
```
docker build -t nimbo-dependencies .
```
3. `cd` again into the source files and run the docker image interactively, expose port 80 and mount Nimbo-C2 directory to the container (so you can easily access all project files, modify `config.jsonc`, download and upload files from agents, etc.). For Linux replace `${pwd}` with `$(pwd)`.
```
cd Nimbo-C2
docker run -it --rm -p 80:80 -v ${pwd}:/Nimbo-C2 -w /Nimbo-C2 nimbo-dependencies
```
## Easier Way

```
git clone https://github.com/itaymigdal/Nimbo-C2
cd Nimbo-C2/Nimbo-C2
docker run -it --rm -p 80:80 -v ${pwd}:/Nimbo-C2 -w /Nimbo-C2 itaymigdal/nimbo-dependencies
```

# Usage

First, edit `config.jsonc` for your needs.

Then run with: `python3 Nimbo-C2.py`

Use the `help` command for each screen, and tab completion.

Also, check the [examples](/examples) directory.

## Main Window

```
Nimbo-C2 > help

    --== Agent ==--
    agent list                    ->  list active agents
    agent interact <agent-id>     ->  interact with the agent
    agent remove <agent-id>       ->  remove agent data

    --== Builder ==--
    build exe                     ->  build exe agent (-h for help)
    build dll                     ->  build dll agent (-h for help)
    build elf                     ->  build elf agent (-h for help)

    --== Listener ==--
    listener start                ->  start the listener
    listener stop                 ->  stop the listener
    listener status               ->  print the listener status

    --== General ==--
    cls                           ->  clear the screen
    help                          ->  print this help message
    exit                          ->  exit Nimbo-C2
```

## Agent Window

### Windows agent
```
Nimbo-C2 [d337c406] > help

    --== Send Commands ==--
    cmd <shell-command>                    ->  execute a shell command 
    iex <powershell-scriptblock>           ->  execute in-memory powershell command
    
    --== File Stuff ==--
    download <remote-file>                 ->  download a file from the agent (wrap path with quotes)
    upload <local-file> <remote-path>      ->  upload a file to the agent (wrap paths with quotes)
    
    --== Discovery Stuff ==--
    pstree                                 ->  show process tree
    checksec                               ->  check for security products
    software                               ->  check for installed software
    modules                                ->  check process loaded modules
    
    --== Collection Stuff ==--
    clipboard                              ->  retrieve clipboard
    screenshot                             ->  retrieve screenshot
    audio <record-time>                    ->  record audio
    keylog start                           ->  start keylogger
    keylog dump                            ->  retrieve captured keystrokes
    keylog stop                            ->  retrieve captured keystrokes and stop keylogger
    
    --== Post Exploitation Stuff ==--
    lsass direct                           ->  dump lsass.exe directly (elevation required)
    lsass comsvcs                          ->  dump lsass.exe using rundll32 and comsvcs.dll (elevation required)
    sam                                    ->  dump sam,security,system hives using reg.exe (elevation required)
    shellc <raw-shellcode-file> <pid>      ->  inject shellcode to a remote process using indirect syscalls
    assembly <local-assembly> <args>       ->  execute .net assembly (pass all args as a single quoted string)
    
    --== Evasion Stuff ==--
    patch amsi                             ->  patch amsi using indirect syscalls
    patch etw                              ->  patch etw using indirect syscalls
    
    --== Persistence Stuff ==--
    persist run <command> <key-name>       ->  set run key (will try first hklm, then hkcu)
    persist spe <command> <process-name>   ->  persist using silent process exit technique (elevation required)
    
    --== Privesc Stuff ==--
    uac fodhelper <command> <keep/die>     ->  elevate session using the fodhelper uac bypass technique
    uac sdclt <command> <keep/die>         ->  elevate session using the sdclt uac bypass technique
    
    --== Interaction stuff ==--
    msgbox <title> <text>                  ->  pop a message box in a new thread
    speak <text>                           ->  speak using 'sapi.spvoice' com interface
    
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
```
### Linux agent
```
Nimbo-2 [51a33cb9] > help

    --== Send Commands ==--
    cmd <shell-command>                    ->  execute a terminal command 
    
    --== File Stuff ==--
    download <remote-file>                 ->  download a file from the agent (wrap path with quotes)
    upload <local-file> <remote-path>      ->  upload a file to the agent (wrap paths with quotes)
    
    --== Post Exploitation Stuff ==--
    memfd <mode> <elf-file> <commandline>  ->  load elf in-memory using the memfd_create syscall
                                               implant mode: load the elf as a child process and return
                                               task mode: load the elf as a child process, wait on it, and get its output when it's done
                                               (pass the whole commandline as a single string using quotes)
    
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
```

# Limitations & Warnings
- Even though the HTTP communication is encrypted, the 'user-agent' header is in plain text and it carries the real agent id, which some products may flag it suspicious.
- `audio`, `lsass` and `sam` commands temporarily save artifacts to disk before exfiltrate and delete them.
- Cleaning the `persist` commands should be done manually.
- Specify whether to keep or kill the initiating agent process in the `uac` commands. `die` flag may leave you with no active agent (if the unelevated agent thinks that the UAC bypass was successful, and it wasn't), `keep` should leave you with 2 active agents probing the C2, then you should manually kill the unelevated.

# Contribution
This software may be buggy or unstable in some use cases as it not being fully and constantly tested.
Feel free to open issues, PR's, and contact me for any reason at ([Gmail](itaymigdal9@gmail.com) | [Linkedin](https://www.linkedin.com/in/itay-migdal-b91821116/) | [Twitter](https://twitter.com/0xTheBruter)).

# Credits
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) - Great resource that taught me a lot about leveraging Nim for implant tasks. Some of Nimbo-C2 agent capabilities are basically wrappers around OffensiveNim modified examples.
- [Python-Prompt-Toolkit-3](https://github.com/prompt-toolkit/python-prompt-toolkit) - Awesome library for developing python CLI applications. Developed the Nimbo-C2 interactive console using this.
- [ascii-image-converter](https://github.com/TheZoraiz/ascii-image-converter) - For the awsome Nimbo ascii art.
- [NimlineWhispers3](https://github.com/klezVirus/NimlineWhispers3) - For the Nim indirect syscalls.
- All those random people from Github & Stackoverflow that I copy & pasted their code :kissing_heart:.


  
