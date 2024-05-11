import winim, pixie
import winim/inc/windef
when not defined(release):
    import std/strformat

type
    RectPhysical = object
        left : int32
        top  : int32
        right : int32
        bottom : int32

type
    MyMonInfo = object
        hMon : HMONITOR
        hdcMon : HDC
        rectLogical  : windef.RECT
        rectPhysical : RectPhysical
        scaleFactor : float64 #//DEVICE_SCALE_FACTOR unreliable
        w : int32
        h : int32
        
var virtMonitors: seq[MyMonInfo]

when not defined(release):
    proc PPrint(): void 
proc EnumDisplayMonitorsCallback(hMon: HMONITOR,hdcMon: HDC,rectLogical: LPRECT,lparam: LPARAM): WINBOOL {.stdcall.}

# ---------------------------------------------------------------------------------------
        
# DEBUG OUTPUT
# - print monitor info
when not defined(release):
    proc PPrint(): void =
        echo ""
        echo &"""                 | {"left":<12}| {"top":<12}| {"right":<12}| {"bottom":<12}"""
        echo "----------------------------------------------------------------"

        var cntr : int = 0
        for mon in virtMonitors:
            echo &"Disp {cntr} : {mon.w}x{mon.h}, (scale: {mon.scaleFactor})"
            echo &"   > Logical :  | {mon.rectLogical.left:<12}| {mon.rectLogical.top:<12}| {mon.rectLogical.right:<12}| {mon.rectLogical.bottom:<12}"
            echo &"   > Physical:  | {mon.rectPhysical.left:<12}| {mon.rectPhysical.top:<12}| {mon.rectPhysical.right:<12}| {mon.rectPhysical.bottom:<12}"
            inc(cntr)
        echo ""

proc EnumDisplayMonitorsCallback(hMon: HMONITOR,hdcMon: HDC,rectLogical: LPRECT,lparam: LPARAM): WINBOOL {.stdcall.} =

    # used to account for scaling ratio between the virtual resolution and real resolution
    #[
    var scale : DEVICE_SCALE_FACTOR
    discard GetScaleFactorForMonitor(hMon, addr scale)
   \-->    seems to be legacy winapi, which has not been updated with latest windows 
            scaling/color modes. should not be relied on for anything more than boolean
            "is scaled/virtualized?".
    ]#

    # acquiring physical width & height of the monitor, rather than virtual dimensions.
    var miex : MONITORINFOEXA
    miex.struct1.cbSize = DWORD sizeof(miex)
    discard GetMonitorInfoA(hMon, cast[LPMONITORINFO](addr miex))

    var dm : DEVMODEA
    dm.dmSize = WORD sizeof(dm)
    dm.dmDriverExtra = 0
    discard EnumDisplaySettingsA(cast[LPCSTR](addr miex.szDevice), ENUM_CURRENT_SETTINGS, cast[LPDEVMODEA](addr dm))
    var 
        cxPhysical : int32 = dm.dmPelsWidth
        cyPhysical : int32 = dm.dmPelsHeight

    # calculate scale factor, knowing virtual and physical monitor dimensions.
    # assuming square pixels, so vertical scale factor same as horizontal scale factor (:
    var cxLogical = rectLogical.right - rectLogical.left
    var scaleFactor : float64 = float64(cxPhysical) / float64(cxLogical) #float64 = nim's alternative to type 'double'

    var tmpMyMonInfo : MyMonInfo
    tmpMyMonInfo.hMon = hMon
    tmpMyMonInfo.hdcMon = hdcMon
    tmpMyMonInfo.rectLogical = rectLogical[]
    tmpMyMonInfo.scaleFactor = scaleFactor
    tmpMyMonInfo.w = cxPhysical
    tmpMyMonInfo.h = cyPhysical

    virtMonitors.insert(tmpMyMonInfo)

    return TRUE

# ---------------------------------------------------------------------------------------

proc get_screenshot*(): string =

    # enumerating conencted virtual monitors
    var hdc : HDC = 0               # If this parameter is NULL, the hdc parameter passed to the callback function will be NULL, and the visible region of interest is the virtual screen that encompasses all the displays on the desktop.
    var lprcClip : LPRECT = nil     # If hdc is NULL, the coordinates are virtual-screen coordinates.
    var lpfnEnum : MONITORENUMPROC = EnumDisplayMonitorsCallback    # callback
    var dwData: LPARAM

    discard EnumDisplayMonitors(hdc, lprcClip, lpfnEnum, dwData)

    # correcting physical left/top coordinates
    # ( --> relative to main display )
    var mainMonScaleFactor : float64 = virtMonitors[0].scaleFactor
    for idx in countup(0, virtMonitors.len - 1):
        var
            # odd behavior of Windef.Rect - multiply by this/main monitor's scale factor, whichever is lower.
            monLeftRel2Main : int32 = int32(float64(virtMonitors[idx].rectLogical.left) * min(mainMonScaleFactor, virtMonitors[idx].scaleFactor))
            monTopRel2Main : int32 = int32(float64(virtMonitors[idx].rectLogical.top) * min(mainMonScaleFactor, virtMonitors[idx].scaleFactor))

        var tmpRectPhysical : RectPhysical
        tmpRectPhysical.left = monLeftRel2Main
        tmpRectPhysical.top  = monTopRel2Main
        tmpRectPhysical.right  = monLeftRel2Main + virtMonitors[idx].w
        tmpRectPhysical.bottom = monTopRel2Main + virtMonitors[idx].h

        virtMonitors[idx].rectPhysical = tmpRectPhysical

    # DEBUG OUTPUT
    when not defined(release):
        PPrint()

    # calc coordinates for shifting of screenshots, each in relation to the others.
    # for this, finding the leftmost/topmost coordinates

    # DEBUG OUTPUT
    when not defined(release):
        echo "[+] calculating left/top-most pixel coordinates for relative image positioning."

    var
        leftMost : int32 = 0
        topMost  : int32 = 0
        rightMost : int32 = 0
        bottomMost: int32 = 0
    for mon in virtMonitors:
        if mon.rectPhysical.left < leftMost:
            leftMost = mon.rectPhysical.left
        if mon.rectPhysical.top < topMost:
            topMost = mon.rectPhysical.top
        if mon.rectPhysical.right > rightMost:
            rightMost = mon.rectPhysical.right
        if mon.rectPhysical.bottom > bottomMost:
            bottomMost = mon.rectPhysical.bottom

    # DEBUG OUTPUT
    when not defined(release):
        echo &" \\--> saved values: ({leftMost= }, {topMost= }, {rightMost= }, {bottomMost= })"
        echo ""

    # combining screenshots into ONE 'virtual screen' final bitmap
    # getting size of virtual screen (in pixels). The virtual screen is the bounding rectangle of all display monitors.

    # DEBUG OUTPUT
    when not defined(release):
        echo "[+] creating image in size of bounding rectangle of all display monitors."

    var hScreen = GetDC(cast[HWND](nil))
    var 
        vBoundingRectW: int32  = rightMost - leftMost #GetSystemMetrics(SM_CXVIRTUALSCREEN)
        vBoundingRectH: int32 = bottomMost - topMost  #GetSystemMetrics(SM_CYVIRTUALSCREEN)

        hCaptureDC : HDC = CreateCompatibleDC(hScreen)
        hBitmap = CreateCompatibleBitmap(hScreen, int32 vBoundingRectW, int32 vBoundingRectH)

    # DEBUG OUTPUT
    when not defined(release):
        echo &" \\--> Detected Physical Bounding dimensions: {vBoundingRectW} x {vBoundingRectH}"
        echo ""

    discard SelectObject(hCaptureDC, hBitmap)

    # position all screenshots in the final bitmap

    # DEBUG OUTPUT
    when not defined(release):
        echo "[+] taking screenshots of detected monitors, and positioning relatively to left/top-most coordinates."

    for idx, mon in virtMonitors:
        var 
            x :int32 = mon.rectPhysical.left - leftMost
            y :int32 = mon.rectPhysical.top - topMost
            cx :int32 = mon.w
            cy :int32 = mon.h
            x1 :int32 = mon.rectPhysical.left #mon.rectLogical.left
            y1 :int32 = mon.rectPhysical.top #mon.rectLogical.top

        # DEBUG OUTPUT
        # - print monitor info
        when not defined(release):
            echo &"  > Disp {idx}"
            echo &"\t{x = },"
            echo &"\t{y = },"
            echo &"\t{cx= },"
            echo &"\t{cy= },"
            echo &"\t{x1= },"
            echo &"\t{y1= }"

        discard BitBlt(hCaptureDC, x, y, cx, cy, hScreen#[mon.hdcMon]#, x1, y1, SRCCOPY)

    # setup bmi structure

    # DEBUG OUTPUT
    when not defined(release):
        echo ""
        echo "[+] constructing bit-map from 'Image' object."

    var mybmi: BITMAPINFO
    mybmi.bmiHeader.biSize = int32 sizeof(mybmi)
    mybmi.bmiHeader.biWidth = vBoundingRectW
    mybmi.bmiHeader.biHeight = vBoundingRectH
    mybmi.bmiHeader.biPlanes = 1
    mybmi.bmiHeader.biBitCount = 32
    mybmi.bmiHeader.biCompression = BI_RGB
    mybmi.bmiHeader.biSizeImage = vBoundingRectW * vBoundingRectH * 4

    # DEBUG OUTPUT
    when not defined(release):
        echo &" \\--> using values:\n   {mybmi.bmiHeader.biSize= },\n   {mybmi.bmiHeader.biWidth= },\n   {mybmi.bmiHeader.biHeight= },\n   {mybmi.bmiHeader.biPlanes= },\n   {mybmi.bmiHeader.biBitCount= },\n   {mybmi.bmiHeader.biCompression= },\n   {mybmi.bmiHeader.biSizeImage= }"
        echo ""

    # create an image
    var finalImage = newImage(vBoundingRectW, vBoundingRectH)

    # copy data from bmi structure to the flippy image
    discard CreateDIBSection(hCaptureDC, addr mybmi, DIB_RGB_COLORS, cast[ptr pointer](unsafeAddr finalImage.data[0]), 0, 0)
    discard GetDIBits(hCaptureDC, hBitmap, 0, vBoundingRectH, cast[ptr pointer](unsafeAddr finalImage.data[0]), addr mybmi, DIB_RGB_COLORS)

    # for some reason windows bitmaps are flipped? flip it back

    # DEBUG OUTPUT
    when not defined(release):
        echo "[+] flipping image vertically."

    finalImage.flipVertical()

    # for some reason windows uses BGR, convert it to RGB

    # DEBUG OUTPUT
    when not defined(release):
        echo "[+] recoding colors (BGR -> RGB)."

    for i in 0 ..< finalImage.height * finalImage.width:
        swap finalImage.data[i].r, finalImage.data[i].b

    # delete data [they are not needed anymore]
    DeleteObject hCaptureDC
    DeleteObject hBitmap

    # convert to more efficient image format
    # Pixie does not support more size-efficient JPEG format

    # DEBUG OUTPUT
    when not defined(release):
        var debugFileName = ".\\combined_screenshot.png"
        echo fmt"[+] saving bit-map to file: '{debugFileName}'"
        finalImage.writeFile(debugFileName)
    else:
        var image_stream = encodeImage(finalImage, PngFormat)
        return image_stream