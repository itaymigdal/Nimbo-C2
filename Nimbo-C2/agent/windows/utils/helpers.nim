import winim
import random


proc `+`*[S: SomeInteger](p: pointer, offset: S): pointer =
  return cast[pointer](cast[ByteAddress](p) +% int(offset))


proc to_string*(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)


proc to_string*(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))


func to_bytes*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))


proc get_pid*(pname: string): int =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.to_string == pname:
                return int(entry.th32ProcessID)

    return 0


proc get_random_string*(length: int): string =
  var rand_string: string
  for _ in .. length:
    add(rand_string, char(rand(int('A') .. int('z'))))
    return rand_string
