import main

proc NimMain() {.cdecl, importc.}

proc DllRegisterServer() : void {.stdcall, exportc, dynlib.} =
    NimMain()
    nimbo_main()
