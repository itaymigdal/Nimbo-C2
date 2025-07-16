import winim
import winim/lean
import winim/inc/windef
import winim/inc/winbase


proc set_privilege*(lpszPrivilege:string): bool=
    # inits
    var tp : TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    # open current process token
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &HTtoken)
    # get current privilege
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        return false
    # enable privilege
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    # set privilege
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
        return false
    # success
    return true


proc is_elevated*(): bool =
    var isElevated: bool
    var token: HANDLE

    if OpenProcessToken(cast[HANDLE](-1), TOKEN_QUERY, addr token) != 0:
        var elevation: TOKEN_ELEVATION
        var token_check: DWORD = cast[DWORD](sizeof TOKEN_ELEVATION)
        if GetTokenInformation(token, tokenElevation, addr elevation, cast[DWORD](sizeof elevation), addr token_check) != 0:
            isElevated = if elevation.TokenIsElevated != 0: true else: false
    CloseHandle(token)
    return isElevated


proc is_user_admin*(): bool =

    var hToken: HANDLE
    var tokenGroups: ptr TOKEN_GROUPS
    var dwSize: DWORD = 0
    var sidAdministrators: PSID
    var sidAuthority: SID_IDENTIFIER_AUTHORITY

    sidAuthority.Value = SECURITY_NT_AUTHORITY

    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr hToken) == 0:
        return false

    defer: CloseHandle(hToken)

    discard GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS(2), nil, 0, addr dwSize)

    if dwSize == 0:
        return false

    tokenGroups = cast[ptr TOKEN_GROUPS](alloc(dwSize))
    if tokenGroups == nil:
        return false

    defer: dealloc(tokenGroups)

    if GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS(2), tokenGroups, dwSize, addr dwSize) == 0:
        return false

    if AllocateAndInitializeSid(addr sidAuthority, 2,
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, addr sidAdministrators) == 0:
        return false

    defer: FreeSid(sidAdministrators)

    if tokenGroups.GroupCount > 0:
        let groups = cast[ptr UncheckedArray[SID_AND_ATTRIBUTES]](addr tokenGroups.Groups[0])
        for i in 0..<tokenGroups.GroupCount:
            if EqualSid(groups[i].Sid, sidAdministrators) != 0:
                return true

    return false
