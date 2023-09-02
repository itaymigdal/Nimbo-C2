import winim
import nimprotect

let elevated_mutex_name = protectString("Global\\na2283577")

proc is_elevated_mutex_enabled*(): bool =
    var mutex = OpenMutex(MUTEX_ALL_ACCESS, false, elevated_mutex_name)
    if mutex == 0 and GetLastError() == ERROR_ACCESS_DENIED:
        return true
    CloseHandle(mutex)
    return false

proc create_elevated_mutex*(): HANDLE =
    var mutex = CreateMutex(nil, false, elevated_mutex_name)
    if mutex == 0:
        return 0
    return mutex

