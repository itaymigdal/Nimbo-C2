import std/[strutils]
import winim

proc get_clipboard*(): string =
  # finally close
  defer: discard CloseClipboard()
  # try to read clipboard
  if OpenClipboard(0):
    let data = GetClipboardData(1)
    if data != 0:
      let text = cast[cstring](GlobalLock(data))
      discard GlobalUnlock(data)
      if text != NULL:
        # replace bad chars
        var sanitized_text = ($text).replace("\c", "")
        return sanitized_text
