
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

**Warning: Nimbo-C2 is meant to be run only within the provided Docker container**

## Easy Way

> Note that installing this way may cause problems or incompatibility in the future as the Docker image now doesn't enforces languages and libraries versions, so consider skipping to the next method. 

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

 > Here we're using the already built, tested and stored Docker image - **recommended**.

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
```

## Agent Window

### Windows agent
```
Nimbo-C2 [d337c406] > help

    --== Send Commands ==--
    cmd <shell-command>                    ->  Execute a shell command 
    iex <powershell-scriptblock>           ->  Execute in-memory powershell command
    
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
    sam                                    ->  Dump sam,security,system hives using reg.exe (elevation required)
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
    critical <true/false>                  -> Set agent process as critical (BSOD on termination) (elevation required)
    
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
```
### Linux agent
```
Nimbo-2 [51a33cb9] > help

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
```

# Limitations & Warnings
- Even though the HTTP communication is encrypted, the 'user-agent' header is in plain text and it carries the real agent id, which some products may flag it suspicious.
- `audio`, `lsass` (except the Evil Lsass Twin method) and `sam` commands temporarily save artifacts to disk before exfiltrate and delete them.
- Cleaning the `persist` commands should be done manually.

# Contribution
This software may be buggy or unstable in some use cases as it not being fully and constantly tested.
Feel free to open issues, PR's, and contact me for any reason at ([Gmail](itaymigdal9@gmail.com) | [Linkedin](https://www.linkedin.com/in/itay-migdal-b91821116/) | [Twitter](https://twitter.com/0xTheBruter)).

# Credits
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) - Great resource that taught me a lot about leveraging Nim for implant tasks. Some of Nimbo-C2 agent capabilities are basically wrappers around OffensiveNim modified examples.
- [Python-Prompt-Toolkit-3](https://github.com/prompt-toolkit/python-prompt-toolkit) - Awesome library for developing python CLI applications. Developed the Nimbo-C2 interactive console using this.
- [ascii-image-converter](https://github.com/TheZoraiz/ascii-image-converter) - For the awesome Nimbo ascii art.
- [NimlineWhispers3](https://github.com/klezVirus/NimlineWhispers3) - For the Nim indirect syscalls.
- [EvilLsassTwin](https://github.com/RePRGM/Nimperiments/tree/main/EvilLsassTwin) - Great method to dump lsass evasively.
- All those random people from Github & Stackoverflow that I copy & pasted their code :kissing_heart:.


  
