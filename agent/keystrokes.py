"""Keystroke-timing watch for newly connected keyboards (BadUSB / keystroke-injection detection).

When a new device presents a keyboard, the agent records WHEN its keys go down for a short window
and reports only timing statistics. Key codes are never read or stored: what was typed is not
needed (and not ours to collect) to see that something typed 600 keys a second with machine-
regular gaps. People type with roughly 80-250 ms between keys and a lot of variation.

Backends:
  Linux    python-evdev, reading the device's /dev/input/event* node (needs the "input" group or root)
  Windows  the Raw Input API via ctypes, which tags every keystroke with the physical device it came from
Other systems, or a backend that cannot open the device, report nothing; the rest of the agent is unaffected.
"""

import re
import statistics
import sys
import threading
import time

WATCH_SECONDS = 30.0
MAX_KEYS = 2000
BURST_MS = 20.0  # a gap under this is faster than a person can type


def summarize(key_times: list[float], connected_at: float, watched_s: float) -> dict:
    """Timing statistics for key-down times (seconds, any monotonic clock). No key identities."""
    times = sorted(key_times)[:MAX_KEYS]
    gaps = [(b - a) * 1000 for a, b in zip(times, times[1:])]
    out = {"keys": len(times), "watched_s": round(watched_s, 1)}
    if times:
        out["first_key_after_s"] = round(max(times[0] - connected_at, 0.0), 2)
        out["duration_s"] = round(times[-1] - times[0], 3)
    if gaps:
        mean = statistics.fmean(gaps)
        out.update(
            {
                "rate_per_s": round(len(gaps) / max((times[-1] - times[0]), 1e-3), 1),
                "median_gap_ms": round(statistics.median(gaps), 1),
                "min_gap_ms": round(min(gaps), 1),
                "gap_cv": round(statistics.pstdev(gaps) / mean, 3) if mean > 0 else 0.0,  # regularity: 0 = machine-perfect
                "burst_fraction": round(sum(g < BURST_MS for g in gaps) / len(gaps), 3),
            }
        )
    return out


# ---------------------------------------------------------------- Linux (evdev)


def _watch_linux(vendor_id: str, product_id: str, seconds: float) -> list[float] | None:
    try:
        import evdev
        from select import select
    except ImportError:
        return None
    vid, pid = int(vendor_id, 16), int(product_id, 16)
    devices = []
    for path in evdev.list_devices():
        try:
            d = evdev.InputDevice(path)
        except OSError:
            continue
        if d.info.vendor == vid and d.info.product == pid and evdev.ecodes.EV_KEY in d.capabilities():
            devices.append(d)
    if not devices:
        return None
    times: list[float] = []
    deadline = time.monotonic() + seconds
    offset = time.monotonic() - time.time()  # evdev stamps are wall-clock; convert to monotonic
    try:
        while time.monotonic() < deadline and len(times) < MAX_KEYS:
            ready, _, _ = select(devices, [], [], max(deadline - time.monotonic(), 0))
            for d in ready:
                for ev in d.read():
                    if ev.type == evdev.ecodes.EV_KEY and ev.value == 1:  # key down; ev.code (which key) is ignored
                        times.append(ev.timestamp() + offset)
    except OSError:  # unplugged mid-watch
        pass
    return times


# ---------------------------------------------------------------- Windows (Raw Input)

_HID_PATH = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


def _watch_windows(vendor_id: str, product_id: str, seconds: float) -> list[float] | None:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    WM_INPUT, RIM_TYPEKEYBOARD, RIDEV_INPUTSINK, RID_INPUT, RIDI_DEVICENAME, RI_KEY_BREAK = 0x00FF, 1, 0x100, 0x10000003, 0x20000007, 1
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

    class RAWINPUTDEVICE(ctypes.Structure):
        _fields_ = [("usUsagePage", wintypes.USHORT), ("usUsage", wintypes.USHORT), ("dwFlags", wintypes.DWORD), ("hwndTarget", wintypes.HWND)]

    class RAWINPUTHEADER(ctypes.Structure):
        _fields_ = [("dwType", wintypes.DWORD), ("dwSize", wintypes.DWORD), ("hDevice", wintypes.HANDLE), ("wParam", wintypes.WPARAM)]

    class RAWKEYBOARD(ctypes.Structure):
        _fields_ = [("MakeCode", wintypes.USHORT), ("Flags", wintypes.USHORT), ("Reserved", wintypes.USHORT),
                    ("VKey", wintypes.USHORT), ("Message", wintypes.UINT), ("ExtraInformation", wintypes.ULONG)]

    class RAWINPUT(ctypes.Structure):
        _fields_ = [("header", RAWINPUTHEADER), ("keyboard", RAWKEYBOARD)]

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

    user32.DefWindowProcW.restype = LRESULT
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.GetRawInputData.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_void_p, ctypes.POINTER(wintypes.UINT), wintypes.UINT]
    user32.GetRawInputDeviceInfoW.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_void_p, ctypes.POINTER(wintypes.UINT)]

    target = (vendor_id.upper(), product_id.upper())
    names: dict[int, tuple[str, str] | None] = {}
    times: list[float] = []

    def device_ids(handle) -> tuple[str, str] | None:
        if handle not in names:
            size = wintypes.UINT(0)
            user32.GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, None, ctypes.byref(size))
            buf = ctypes.create_unicode_buffer(size.value + 1)
            user32.GetRawInputDeviceInfoW(handle, RIDI_DEVICENAME, buf, ctypes.byref(size))
            m = _HID_PATH.search(buf.value)
            names[handle] = (m[1].upper(), m[2].upper()) if m else None
        return names[handle]

    @WNDPROC
    def proc(hwnd, msg, wparam, lparam):
        if msg == WM_INPUT:
            raw = RAWINPUT()
            size = wintypes.UINT(ctypes.sizeof(raw))
            if user32.GetRawInputData(lparam, RID_INPUT, ctypes.byref(raw), ctypes.byref(size), ctypes.sizeof(RAWINPUTHEADER)) > 0:
                if raw.header.dwType == RIM_TYPEKEYBOARD and not raw.keyboard.Flags & RI_KEY_BREAK:  # key down only
                    if raw.header.hDevice and device_ids(raw.header.hDevice) == target:
                        times.append(time.monotonic())  # MakeCode / VKey (which key) are never kept
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    wc = WNDCLASSW(lpfnWndProc=proc, hInstance=kernel32.GetModuleHandleW(None), lpszClassName=f"TraceForgeKeys{threading.get_ident()}")
    if not user32.RegisterClassW(ctypes.byref(wc)):
        return None
    hwnd = user32.CreateWindowExW(0, wc.lpszClassName, "TraceForge", 0, 0, 0, 0, 0, None, None, wc.hInstance, None)
    rid = RAWINPUTDEVICE(0x01, 0x06, RIDEV_INPUTSINK, hwnd)  # generic desktop / keyboard, even when not focused
    if not hwnd or not user32.RegisterRawInputDevices(ctypes.byref(rid), 1, ctypes.sizeof(rid)):
        return None
    msg = wintypes.MSG()
    deadline = time.monotonic() + seconds
    PM_REMOVE = 1
    try:
        while time.monotonic() < deadline and len(times) < MAX_KEYS:
            while user32.PeekMessageW(ctypes.byref(msg), hwnd, 0, 0, PM_REMOVE):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.005)
    finally:
        user32.DestroyWindow(hwnd)
        user32.UnregisterClassW(wc.lpszClassName, wc.hInstance)
    return times


def watch(vendor_id: str, product_id: str, connected_at: float, seconds: float = WATCH_SECONDS) -> dict | None:
    """Block for up to `seconds` and return timing statistics, or None if this OS/device cannot be watched."""
    started = time.monotonic()
    try:
        if sys.platform.startswith("linux"):
            times = _watch_linux(vendor_id, product_id, seconds)
        elif sys.platform == "win32":
            times = _watch_windows(vendor_id, product_id, seconds)
        else:
            return None
    except Exception as exc:  # a watcher problem must never stop the agent
        print(f"keystroke watch unavailable: {exc.__class__.__name__}: {exc}")
        return None
    if times is None:
        return None
    return summarize(times, connected_at, time.monotonic() - started)


def watch_in_background(vendor_id: str, product_id: str, connected_at: float, report) -> None:
    """Start a watch thread; report(summary) is called when it ends (only if there was any typing)."""

    def run():
        summary = watch(vendor_id, product_id, connected_at)
        if summary and summary["keys"] > 0:
            report(summary)

    threading.Thread(target=run, name=f"keys-{vendor_id}:{product_id}", daemon=True).start()
