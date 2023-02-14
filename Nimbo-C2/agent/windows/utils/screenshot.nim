import pixie
import winim
import winim/inc/windef

proc get_screenshot*(): string =

    # get size of the main screen
    var screenRect: windef.Rect
    GetClientRect GetDesktopWindow(), addr screenRect
    let
        x = screenRect.left
        y = screenRect.top
        w = (screenRect.right - screenRect.left)
        h = (screenRect.bottom - screenRect.top)

    # create an image
    var image = newImage(w, h)

    # copy screen data to bitmap
    var
        hScreen = GetDC(cast[HWND](nil))
        hDC = CreateCompatibleDC(hScreen)
        hBitmap = CreateCompatibleBitmap(hScreen, int32 w, int32 h)

    discard SelectObject(hDC, hBitmap)
    discard BitBlt(hDC, 0, 0, int32 w, int32 h, hScreen, int32 x, int32 y, SRCCOPY)

    # setup bmi structure
    var mybmi: BITMAPINFO
    mybmi.bmiHeader.biSize = int32 sizeof(mybmi)
    mybmi.bmiHeader.biWidth = w
    mybmi.bmiHeader.biHeight = h
    mybmi.bmiHeader.biPlanes = 1
    mybmi.bmiHeader.biBitCount = 32
    mybmi.bmiHeader.biCompression = BI_RGB
    mybmi.bmiHeader.biSizeImage = w * h * 4

    # copy data from bmi structure to the flippy image
    discard CreateDIBSection(hdc, addr mybmi, DIB_RGB_COLORS, cast[ptr pointer](unsafeAddr image.data[0]), 0, 0)
    discard GetDIBits(hdc, hBitmap, 0, h, cast[ptr pointer](unsafeAddr image.data[0]), addr mybmi, DIB_RGB_COLORS)

    # for some reason windows bitmaps are flipped? flip it back
    image.flipVertical()

    # for some reason windows uses BGR, convert it to RGB
    for i in 0 ..< image.height * image.width:
        swap image.data[i].r, image.data[i].b

    # delete data [they are not needed anymore]
    DeleteObject hdc
    DeleteObject hBitmap

    var image_stream = encodeImage(image, PngFormat)
    return image_stream
