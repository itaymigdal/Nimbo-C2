import winim


proc set_privilege*(lpszPrivilege: string): bool =
    # inits
    var tp: TOKEN_PRIVILEGES
    var prevTp: TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    var returnLength: DWORD
    
    # open current process token
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, &HTtoken)
    
    # get current privilege
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        CloseHandle(HTtoken)
        return false
    
    # setup privilege structure to check current state
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    # use AdjustTokenPrivileges to check current state (without actually changing)
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), &prevTp, &returnLength) == 0:
        CloseHandle(HTtoken)
        return false
    
    # check if privilege was already enabled
    if (prevTp.Privileges[0].Attributes and SE_PRIVILEGE_ENABLED) != 0:
        CloseHandle(HTtoken)
        return true  # already enabled, no need to adjust again
    
    # privilege was not enabled, the call above already enabled it
    # cleanup and success
    CloseHandle(HTtoken)
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
