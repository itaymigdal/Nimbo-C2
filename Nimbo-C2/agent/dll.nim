import main

proc NimMain() {.cdecl, importc.}

proc DLL_EXPORT_NAME() : void {.stdcall, exportc, dynlib.} =
    NimMain()
    nimbo_main()
