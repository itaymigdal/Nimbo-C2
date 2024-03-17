import priv
import nimprotect

proc RtlSetProcessIsCritical(bNew: bool, pbOld: ptr bool, bNeedScb: bool): cint {.stdcall, dynlib: protectString("ntdll"), importc: protectString("RtlSetProcessIsCritical").}


proc set_critical*(is_critical: bool): cint =
    if not is_elevated() or not set_privilege(protectString("SeDebugPrivilege")):
        return 1
    return RtlSetProcessIsCritical(is_critical, nil, false)
