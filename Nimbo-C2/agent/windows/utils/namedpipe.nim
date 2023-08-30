import winim
import helpers
import nimprotect

var pipe_s: HANDLE
var pipe_c: HANDLE
var pipe_name = protectString("\\\\.\\pipe\\") & get_random_string(10)
var timeout = 5


proc np_server*() =
    pipe_s = CreateNamedPipe(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE,
        1,
        0,
        0,
        0,
        NULL
    )

    if not bool(pipe_s) or pipe_s == INVALID_HANDLE_VALUE:
        quit(1)

    try:
        discard ConnectNamedPipe(pipe_s, NULL)

    finally:
        CloseHandle(pipe_s)


proc np_client_try_connect*(): bool =

    for i in countup(1, timeout * 2):
        pipe_c = CreateFile(
            pipe_name,
            GENERIC_READ or GENERIC_WRITE, 
            FILE_SHARE_READ or FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0
        )

        if pipe_c == INVALID_HANDLE_VALUE:
            Sleep(500)
            continue
        else:
            return true
        
        return false

        