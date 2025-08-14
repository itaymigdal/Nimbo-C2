import wAuto/[registry, common]
import winim
import nimprotect

proc registry_read*(key: string, value: string): string =
    return $regRead(key, value)

proc registry_delete*(key: string): bool =
    return regDelete(key)

proc registry_delete*(key: string, value: string): bool =
    return regDelete(key, value)

proc registry_write*(key: string): bool =
    return regWrite(key)

proc registry_write*(key: string, value: string, data: string): bool =
    return regWrite(key, value, data)

proc registry_write*(key: string, value: string, data: DWORD): bool =
    return regWrite(key, value, data)

proc registry_iterate_keys*(key: string): string =
    result = ""
    for subkey in regKeys(key):
        result.add(protectString("[+] ") & subkey & "\n")

proc registry_iterate_values*(key: string): string =
    result = ""
    for val in regValues(key):
        result.add(protectString("[+] ") & val.name & protectString(" (") & $val.kind & protectString(")\n"))