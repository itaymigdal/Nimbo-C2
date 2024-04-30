import winim, pixie
import winim/inc/windef
when not defined(release):
    import std/strformat

type
    MyPhysicalDimensions = object
        w : int32
        h : int32

type
    MyMonInfo = object
        hMon : HMONITOR
        hdcMon : HDC
        rectLogical : windef.RECT
        dimPhysical : MyPhysicalDimensions
        scaleFactor : float64 #//DEVICE_SCALE_FACTOR unreliable
        
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
        echo &"""{"":<8}| {"scaleFactor":<12}| {"physical Dimensions":<20}| {"rect.left":<12}| {"rect.top":<12}| {"rect.right":<12}| {"rect.bottom":<12}"""
        echo "----------------------------------------------------------------------------------------------------"

        var cntr : int = 0
        for mon in virtMonitors:
            var formattedPhysicalDimensions = fmt"{mon.dimPhysical.w} x {mon.dimPhysical.h}"
            var formattedLine = fmt"Disp {cntr}  | {mon.scaleFactor:<12}| {formattedPhysicalDimensions:<20}| {mon.rectLogical.left:<12}| {mon.rectLogical.top:<12}| {mon.rectLogical.right:<12}| {mon.rectLogical.bottom:<12}"
            echo formattedLine
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

    var tmpPhysicalDimensions : MyPhysicalDimensions
    tmpPhysicalDimensions.w = cxPhysical
    tmpPhysicalDimensions.h = cyPhysical

    # calculate scale factor, knowing virtual and physical monitor dimensions.
    # assuming square pixels, so vertical scale factor same as horizontal scale factor (:
    var cxLogical = rectLogical.right - rectLogical.left
    var scaleFactor : float64 = float64(cxPhysical) / float64(cxLogical) #float64 = nim's alternative to type 'double'

    var tmpMyMonInfo : MyMonInfo
    tmpMyMonInfo.hMon = hMon
    tmpMyMonInfo.hdcMon = hdcMon
    tmpMyMonInfo.rectLogical = rectLogical[]
    tmpMyMonInfo.dimPhysical = tmpPhysicalDimensions
    tmpMyMonInfo.scaleFactor = scaleFactor

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
    #var retval = EnumDisplayMonitors(hdc, lprcClip, lpfnEnum, dwData)
    #if retval == 0:
    #    echo fmt"[!] ERROR in 'EnumDisplayMonitors' - ({GetLastError()})" 

    # DEBUG OUTPUT
    # - print monitor info
    when not defined(release):
        PPrint()

    var hScreen = GetDC(cast[HWND](nil))

    # combining screenshots into ONE 'virtual screen' final bitmap
    # getting size of virtual screen (in pixels). The virtual screen is the bounding rectangle of all display monitors.
    var 
        nScreenWidth: int32  = GetSystemMetrics(SM_CXVIRTUALSCREEN)
        nScreenHeight: int32 = GetSystemMetrics(SM_CYVIRTUALSCREEN)

        hCaptureDC : HDC = CreateCompatibleDC(hScreen)
        hBitmap = CreateCompatibleBitmap(hScreen, int32 nScreenWidth, int32 nScreenHeight)

    discard SelectObject(hCaptureDC, hBitmap)

    # calc coordinates for shifting of screenshots, each in relation to the others.
    # for this, finding the leftmost/topmost coordinates
    var
        leftMost : int32 = 0
        topMost  : int32 = 0
    for mon in virtMonitors:
        if mon.rectLogical.left < leftMost:
            leftMost = mon.rectLogical.left
        if mon.rectLogical.top < topMost:
            topMost = mon.rectLogical.top

    # position all screenshots in the final bitmap
    for idx, mon in virtMonitors:
        var 
            x :int32 = mon.rectLogical.left - leftMost
            y :int32 = mon.rectLogical.top - topMost
            cx :int32 = mon.dimPhysical.w #int32((mon.rectLogical.right - mon.rectLogical.left) * int32(mon.scaleFactor) / 100)
            cy :int32 = mon.dimPhysical.h #int32((mon.rectLogical.bottom - mon.rectLogical.top) * int32(mon.scaleFactor) / 100)
            x1 :int32 = mon.rectLogical.left
            y1 :int32 = mon.rectLogical.top

        discard BitBlt(hCaptureDC, x, y, cx, cy, hScreen#[mon.hdcMon]#, x1, y1, SRCCOPY)

    # setup bmi structure
    var mybmi: BITMAPINFO
    mybmi.bmiHeader.biSize = int32 sizeof(mybmi)
    mybmi.bmiHeader.biWidth = nScreenWidth
    mybmi.bmiHeader.biHeight = nScreenHeight
    mybmi.bmiHeader.biPlanes = 1
    mybmi.bmiHeader.biBitCount = 32
    mybmi.bmiHeader.biCompression = BI_RGB
    mybmi.bmiHeader.biSizeImage = nScreenWidth * nScreenHeight * 4

    # create an image
    var finalImage = newImage(nScreenWidth, nScreenHeight)

    # copy data from bmi structure to the flippy image
    discard CreateDIBSection(hCaptureDC, addr mybmi, DIB_RGB_COLORS, cast[ptr pointer](unsafeAddr finalImage.data[0]), 0, 0)
    discard GetDIBits(hCaptureDC, hBitmap, 0, nScreenHeight, cast[ptr pointer](unsafeAddr finalImage.data[0]), addr mybmi, DIB_RGB_COLORS)

    # for some reason windows bitmaps are flipped? flip it back
    finalImage.flipVertical()

    # for some reason windows uses BGR, convert it to RGB
    for i in 0 ..< finalImage.height * finalImage.width:
        swap finalImage.data[i].r, finalImage.data[i].b

    # delete data [they are not needed anymore]
    DeleteObject hCaptureDC
    DeleteObject hBitmap

    # convert to more efficient image format
    # Pixie does not support more size-efficient JPEG format

    # DEBUG OUTPUT
    when not defined(release):
        finalImage.writeFile("combined_screenshot.png")
    else:
        var image_stream = encodeImage(finalImage, PngFormat)
        return image_stream