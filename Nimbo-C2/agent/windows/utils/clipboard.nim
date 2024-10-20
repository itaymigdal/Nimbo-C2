import std/[strutils]
import winim

proc get_clipboard*(): string =
    defer: discard CloseClipboard()
    
    if OpenClipboard(0):
        # Check for CF_TEXT
        let textData = GetClipboardData(CF_TEXT)
        if textData != 0:
            let text = cast[cstring](GlobalLock(textData))
            defer: discard GlobalUnlock(textData)
            if text != nil:
                return ($text).replace("\c", "")
        
        # Check for CF_HDROP
        let hdropData = GetClipboardData(CF_HDROP)
        if hdropData != 0:
            let dropFiles = cast[HDROP](GlobalLock(hdropData))
            defer: discard GlobalUnlock(hdropData)
            if dropFiles != 0:
                result = "Copied files:\n"
                let fileCount = DragQueryFile(dropFiles, cast[UINT](0xFFFFFFFF), nil, 0)
                var buffer: array[MAX_PATH, WCHAR]
                for i in 0 ..< fileCount:
                    let pathLength = DragQueryFileW(dropFiles, i, cast[LPWSTR](addr buffer[0]), MAX_PATH.UINT32)
                    if pathLength > 0:
                        result.add($cast[WideCString](addr buffer[0]))
                        result.add("\n")
                return result.strip()

    return ""
