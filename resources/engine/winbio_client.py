"""
Windows Biometric Framework (WBF) Client
Komunikasi langsung dengan Hardware Fingerprint USB (ChipSailing / WBDI) via winbio.dll.
Mendukung:
- Deteksi hardware & daftar jari terdaftar (WinBioEnumBiometricUnits, WinBioEnumEnrollments)
- Scan identifikasi & Mode Bebas tanpa registrasi (WinBioIdentify)
- Pendaftaran jari mandiri in-app dengan auto-overwrite & timeout aman (WinBioEnrollBegin/Capture/Commit)
- Hapus template jari spesifik (WinBioDeleteTemplate)
- Native Win32 Foreground Focus Window (WBF Focus Arbitration) agar sensor USB selalu
  menerima sentuhan fisik saat dipanggil dari Electron / Web Browser!
"""

import ctypes
from ctypes import wintypes
import os
import subprocess
import threading
import time

# --- Constants ---
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 1
WINBIO_FLAG_DEFAULT = 0

WINBIO_ID_TYPE_NULL = 0
WINBIO_ID_TYPE_WILDCARD = 1
WINBIO_ID_TYPE_GUID = 2
WINBIO_ID_TYPE_SID = 3

# HRESULT constants (resmi dari winbio.dll FormatMessageW)
S_OK = 0x00000000
WINBIO_I_MORE_DATA = 0x00090001
WINBIO_E_UNKNOWN_ID = 0x80098003        # WinBioIdentify: jari tidak cocok dgn template manapun
WINBIO_E_CANCELED = 0x80098004
WINBIO_E_NO_MATCH = 0x80098005          # WinBioVerify: jari tidak cocok dgn target
WINBIO_E_CAPTURE_ABORTED = 0x80098006
WINBIO_E_ENROLLMENT_IN_PROGRESS = 0x80098007
WINBIO_E_BAD_CAPTURE = 0x80098008
WINBIO_E_DEVICE_BUSY = 0x80098010
WINBIO_E_DATABASE_FULL = 0x80098018
WINBIO_E_DUPLICATE_ENROLLMENT = 0x8009801C
WINBIO_E_DUPLICATE_TEMPLATE = 0x8009802B
WINBIO_E_LOCKOUT = 0x80098047
E_ACCESSDENIED = 0x80070005

HRESULT_MESSAGES = {
    WINBIO_E_UNKNOWN_ID: "Sidik jari belum cocok dengan jari terdaftar di sensor. Tempelkan jari terdaftar lebih rata di tengah sensor.",
    WINBIO_E_CANCELED: "Operasi sensor dibatalkan.",
    WINBIO_E_NO_MATCH: "Sidik jari terdeteksi, namun belum terdaftar di Windows Biometrics.",
    WINBIO_E_CAPTURE_ABORTED: "Pembacaan sidik jari terhenti. Silakan tempelkan jari lagi.",
    WINBIO_E_ENROLLMENT_IN_PROGRESS: "Pendaftaran sebelumnya masih berjalan. Silakan coba lagi.",
    WINBIO_E_BAD_CAPTURE: "Kualitas sentuhan sidik jari kurang jelas. Tempelkan jari lebih rata.",
    WINBIO_E_DEVICE_BUSY: "Sensor sedang sibuk digunakan proses lain (Device Busy). Tutup aplikasi sidik jari lain lalu coba lagi.",
    WINBIO_E_DATABASE_FULL: "Memori database sidik jari Windows penuh (maksimal 10 jari per akun Windows).",
    WINBIO_E_DUPLICATE_ENROLLMENT: "Slot jari ini sudah terdaftar di Windows Biometrics.",
    WINBIO_E_DUPLICATE_TEMPLATE: "Sidik jari ini sudah pernah didaftarkan sebelumnya di Windows Biometrics! Gunakan tombol 'Scan Jari Terdaftar' atau pilih jari lain.",
    WINBIO_E_LOCKOUT: "Sensor terkunci sementara karena terlalu banyak percobaan gagal.",
    E_ACCESSDENIED: "Akses ditolak oleh Windows Biometrics (E_ACCESSDENIED). Jalankan aplikasi/bridge sebagai Administrator atau aktifkan Windows Hello terlebih dahulu.",
}

# SubFactor Map (ANSI 381 Finger Position)
SUBFACTOR_NAMES = {
    0x00: ("Jari Bebas (Tanpa Registrasi)", "Unregistered Finger"),
    0x01: ("Ibu Jari Kanan", "Right Thumb"),
    0x02: ("Jari Telunjuk Kanan", "Right Index Finger"),
    0x03: ("Jari Tengah Kanan", "Right Middle Finger"),
    0x04: ("Jari Manis Kanan", "Right Ring Finger"),
    0x05: ("Jari Kelingking Kanan", "Right Little Finger"),
    0x06: ("Ibu Jari Kiri", "Left Thumb"),
    0x07: ("Jari Telunjuk Kiri", "Left Index Finger"),
    0x08: ("Jari Tengah Kiri", "Left Middle Finger"),
    0x09: ("Jari Manis Kiri", "Left Ring Finger"),
    0x0A: ("Jari Kelingking Kiri", "Left Little Finger"),
    0xFF: ("Jari Mana Saja", "Any Finger"),
}

REJECT_REASONS = {
    1: "Jari terlalu tinggi pada sensor (Too High)",
    2: "Jari terlalu rendah pada sensor (Too Low)",
    3: "Jari terlalu ke kiri (Too Left)",
    4: "Jari terlalu ke kanan (Too Right)",
    5: "Jari diangkat terlalu cepat (Too Fast)",
    6: "Gerakan jari terlalu lambat (Too Slow)",
    7: "Kualitas sensor/sidik jari kurang jelas (Poor Quality / Sensor Kotor)",
    8: "Posisi jari miring (Too Skewed)",
    9: "Sentuhan terlalu singkat (Too Short)",
    10: "Gagal menggabungkan sampel (Merge Failure)",
}

DEBUG_LOG_PATH = os.path.join(os.path.expanduser(r"~\.fingerprint_code_app"), "biometric_debug.log")


def _log_debug(msg: str):
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG_PATH), exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [PID {os.getpid()}] {msg}\n")
    except Exception:
        pass


# --- C Structures (Sesuai winbio_types.h Windows SDK) ---
class WINBIO_VERSION(ctypes.Structure):
    _fields_ = [
        ("MajorVersion", wintypes.DWORD),
        ("MinorVersion", wintypes.DWORD),
    ]


class WINBIO_UNIT_SCHEMA(ctypes.Structure):
    _fields_ = [
        ("UnitId", wintypes.ULONG),
        ("PoolType", wintypes.ULONG),
        ("BiometricFactor", wintypes.ULONG),
        ("SensorSubType", wintypes.ULONG),
        ("Capabilities", wintypes.ULONG),
        ("DeviceInstanceId", wintypes.WCHAR * 256),
        ("Description", wintypes.WCHAR * 256),
        ("Manufacturer", wintypes.WCHAR * 256),
        ("Model", wintypes.WCHAR * 256),
        ("SerialNumber", wintypes.WCHAR * 256),
        ("FirmwareVersion", WINBIO_VERSION),
    ]


PWINBIO_UNIT_SCHEMA = ctypes.POINTER(WINBIO_UNIT_SCHEMA)


class AccountSidStruct(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("Data", ctypes.c_ubyte * 68),
    ]


class WINBIO_IDENTITY_UNION(ctypes.Union):
    _fields_ = [
        ("Null", wintypes.ULONG),
        ("Wildcard", wintypes.ULONG),
        ("TemplateGuid", ctypes.c_ubyte * 16),
        ("AccountSid", AccountSidStruct),
    ]


class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [
        ("Type", wintypes.ULONG),
        ("Value", WINBIO_IDENTITY_UNION),
    ]


# --- Win32 APIs ---
winbio = None
advapi32 = None
kernel32 = None

try:
    winbio = ctypes.WinDLL("winbio.dll")
    advapi32 = ctypes.WinDLL("advapi32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    WinBioEnumBiometricUnits = winbio.WinBioEnumBiometricUnits
    WinBioEnumBiometricUnits.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(PWINBIO_UNIT_SCHEMA),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    WinBioEnumBiometricUnits.restype = wintypes.LONG

    WinBioOpenSession = winbio.WinBioOpenSession
    WinBioOpenSession.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    WinBioOpenSession.restype = wintypes.LONG

    WinBioCloseSession = winbio.WinBioCloseSession
    WinBioCloseSession.argtypes = [wintypes.HANDLE]
    WinBioCloseSession.restype = wintypes.LONG

    WinBioCancel = winbio.WinBioCancel
    WinBioCancel.argtypes = [wintypes.HANDLE]
    WinBioCancel.restype = wintypes.LONG

    WinBioFree = winbio.WinBioFree
    WinBioFree.argtypes = [wintypes.LPVOID]
    WinBioFree.restype = wintypes.LONG

    WinBioIdentify = winbio.WinBioIdentify
    WinBioIdentify.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(WINBIO_IDENTITY),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(wintypes.ULONG),
    ]
    WinBioIdentify.restype = wintypes.LONG

    # Enrollment APIs
    WinBioEnrollBegin = winbio.WinBioEnrollBegin
    WinBioEnrollBegin.argtypes = [wintypes.HANDLE, ctypes.c_ubyte, wintypes.ULONG]
    WinBioEnrollBegin.restype = wintypes.LONG

    WinBioEnrollCapture = winbio.WinBioEnrollCapture
    WinBioEnrollCapture.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    WinBioEnrollCapture.restype = wintypes.LONG

    WinBioEnrollCommit = winbio.WinBioEnrollCommit
    WinBioEnrollCommit.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(WINBIO_IDENTITY),
        ctypes.POINTER(wintypes.BOOLEAN),
    ]
    WinBioEnrollCommit.restype = wintypes.LONG

    WinBioEnrollDiscard = winbio.WinBioEnrollDiscard
    WinBioEnrollDiscard.argtypes = [wintypes.HANDLE]
    WinBioEnrollDiscard.restype = wintypes.LONG

    WinBioEnumEnrollments = winbio.WinBioEnumEnrollments
    WinBioEnumEnrollments.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        ctypes.POINTER(WINBIO_IDENTITY),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    WinBioEnumEnrollments.restype = wintypes.LONG

    WinBioDeleteTemplate = winbio.WinBioDeleteTemplate
    WinBioDeleteTemplate.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        ctypes.POINTER(WINBIO_IDENTITY),
        ctypes.c_ubyte,
    ]
    WinBioDeleteTemplate.restype = wintypes.LONG

    ConvertSidToStringSidW = advapi32.ConvertSidToStringSidW
    ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    ConvertSidToStringSidW.restype = wintypes.BOOL

    ConvertStringSidToSidW = advapi32.ConvertStringSidToSidW
    ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    ConvertStringSidToSidW.restype = wintypes.BOOL

    GetLengthSid = advapi32.GetLengthSid
    GetLengthSid.argtypes = [ctypes.c_void_p]
    GetLengthSid.restype = wintypes.DWORD

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [wintypes.HLOCAL]
    LocalFree.restype = wintypes.HLOCAL

except Exception as ex:
    winbio = None
    print(f"Error loading winbio.dll: {ex}")


# =====================================================================
# NATIVE WIN32 FOREGROUND FOCUS WINDOW (ZERO EXTERNAL DEPENDENCIES)
# Windows Biometric Framework (WbioSrvc) HANYA mengirim sentuhan sensor
# ke proses yang memiliki FOREGROUND WINDOW aktif. Jendela kecil ini
# otomatis mengambil fokus saat scan/enroll, lalu menutup & mengembalikan
# fokus ke Healing POS / Browser begitu sentuhan selesai terbaca.
# =====================================================================

class BiometricFocusWindow:
    _class_counter = 0
    _class_lock = threading.Lock()

    def __init__(self, title="Tempelkan Jari ke Sensor USB", subtitle="Menunggu sentuhan pada sensor ChipSailing...", show_progress=False, on_cancel=None):
        self.title_text = title
        self.subtitle_text = subtitle
        self.show_progress = show_progress
        self.progress_pct = 0
        self.on_cancel = on_cancel
        self._hwnd = None
        self._prev_fg = None
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._thread = None
        self._has_focus = False
        self._fg_pid = 0
        self._wndproc_ref = None
        self._text_lock = threading.Lock()

    def start(self):
        self._thread = threading.Thread(target=self._run_ui, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.5)
        # Beri waktu singkat agar WbioSrvc mencatat perubahan fokus jendela
        time.sleep(0.15)
        return self._has_focus

    def update(self, title=None, subtitle=None, progress=None):
        with self._text_lock:
            if title is not None:
                self.title_text = str(title)
            if subtitle is not None:
                self.subtitle_text = str(subtitle)
            if progress is not None:
                self.progress_pct = max(0, min(100, int(progress)))
        hwnd = self._hwnd
        if hwnd:
            try:
                user32 = ctypes.WinDLL("user32")
                user32.InvalidateRect.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.BOOL]
                user32.InvalidateRect(hwnd, None, True)
            except Exception:
                pass

    def close(self):
        hwnd = self._hwnd
        if hwnd:
            try:
                user32 = ctypes.WinDLL("user32")
                user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, ctypes.c_ssize_t]
                user32.PostMessageW(hwnd, 0x8002, 0, 0)  # WM_APP + 2
            except Exception:
                pass
        self._closed.wait(timeout=1.5)

    def _run_ui(self):
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            LRESULT = ctypes.c_ssize_t
            WPARAM = ctypes.c_size_t
            LPARAM = ctypes.c_ssize_t
            WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)

            class WNDCLASSEXW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.UINT),
                    ("style", wintypes.UINT),
                    ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE),
                    ("hIcon", wintypes.HANDLE),
                    ("hCursor", wintypes.HANDLE),
                    ("hbrBackground", wintypes.HANDLE),
                    ("lpszMenuName", wintypes.LPCWSTR),
                    ("lpszClassName", wintypes.LPCWSTR),
                    ("hIconSm", wintypes.HANDLE),
                ]

            class PAINTSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("hdc", wintypes.HDC),
                    ("fErase", wintypes.BOOL),
                    ("rcPaint", wintypes.RECT),
                    ("fRestore", wintypes.BOOL),
                    ("fIncUpdate", wintypes.BOOL),
                    ("rgbReserved", ctypes.c_byte * 32),
                ]

            class MSG(ctypes.Structure):
                _fields_ = [
                    ("hwnd", wintypes.HWND),
                    ("message", wintypes.UINT),
                    ("wParam", WPARAM),
                    ("lParam", LPARAM),
                    ("time", wintypes.DWORD),
                    ("pt", wintypes.POINT),
                ]

            # Explicit 64-bit prototypes
            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
            user32.DefWindowProcW.restype = LRESULT
            user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
            user32.RegisterClassExW.restype = wintypes.ATOM
            user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
            user32.CreateWindowExW.argtypes = [
                wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
            ]
            user32.CreateWindowExW.restype = wintypes.HWND
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.UpdateWindow.argtypes = [wintypes.HWND]
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            user32.PostQuitMessage.argtypes = [ctypes.c_int]
            user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
            user32.GetMessageW.restype = wintypes.BOOL
            user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
            user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
            user32.GetSystemMetrics.argtypes = [ctypes.c_int]
            user32.GetSystemMetrics.restype = ctypes.c_int
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
            user32.AttachThreadInput.restype = wintypes.BOOL
            user32.SetForegroundWindow.argtypes = [wintypes.HWND]
            user32.SetForegroundWindow.restype = wintypes.BOOL
            user32.BringWindowToTop.argtypes = [wintypes.HWND]
            user32.SetActiveWindow.argtypes = [wintypes.HWND]
            user32.SetFocus.argtypes = [wintypes.HWND]
            user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
            user32.keybd_event.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, wintypes.DWORD, ctypes.c_size_t]
            user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
            user32.BeginPaint.restype = wintypes.HDC
            user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
            user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            user32.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HANDLE]
            user32.DrawTextW.argtypes = [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.RECT), wintypes.UINT]
            user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
            user32.LoadCursorW.restype = wintypes.HANDLE

            gdi32.CreateSolidBrush.argtypes = [wintypes.COLORREF]
            gdi32.CreateSolidBrush.restype = wintypes.HANDLE
            gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
            gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
            gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.COLORREF]
            gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]
            gdi32.SelectObject.restype = wintypes.HANDLE
            gdi32.CreateFontW.argtypes = [
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
            ]
            gdi32.CreateFontW.restype = wintypes.HANDLE

            k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
            k32.GetModuleHandleW.restype = wintypes.HMODULE
            k32.GetCurrentThreadId.restype = wintypes.DWORD

            # Brushes & Fonts (BGR hex colors)
            br_bg = gdi32.CreateSolidBrush(0x002A170F)      # Dark slate navy (#0f172a)
            br_card = gdi32.CreateSolidBrush(0x003B291E)    # Slate card (#1e293b)
            br_accent = gdi32.CreateSolidBrush(0x00F8BD38)  # Sky blue (#38bdf8)
            br_bar_bg = gdi32.CreateSolidBrush(0x00473628)
            br_bar_fg = gdi32.CreateSolidBrush(0x0081B910)  # Emerald green (#10b981)

            font_title = gdi32.CreateFontW(-20, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI")
            font_sub = gdi32.CreateFontW(-15, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI")
            font_hint = gdi32.CreateFontW(-13, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI")

            WM_DESTROY = 0x0002
            WM_PAINT = 0x000F
            WM_CLOSE = 0x0010
            WM_KEYDOWN = 0x0100
            WM_APP_CLOSE = 0x8002
            VK_ESCAPE = 0x1B

            self_ref = self

            def wndproc(hwnd, msg, wparam, lparam):
                if msg == WM_PAINT:
                    ps = PAINTSTRUCT()
                    hdc = user32.BeginPaint(hwnd, ctypes.byref(ps))
                    try:
                        rc = wintypes.RECT()
                        user32.GetClientRect(hwnd, ctypes.byref(rc))
                        user32.FillRect(hdc, ctypes.byref(rc), br_bg)

                        # Top accent strip
                        top_rc = wintypes.RECT(0, 0, rc.right, 5)
                        user32.FillRect(hdc, ctypes.byref(top_rc), br_accent)

                        # Inner card
                        card_rc = wintypes.RECT(16, 18, rc.right - 16, rc.bottom - 16)
                        user32.FillRect(hdc, ctypes.byref(card_rc), br_card)

                        gdi32.SetBkMode(hdc, 1)  # TRANSPARENT

                        with self_ref._text_lock:
                            t_txt = self_ref.title_text
                            s_txt = self_ref.subtitle_text
                            pct = self_ref.progress_pct
                            show_p = self_ref.show_progress

                        # Title
                        old_font = gdi32.SelectObject(hdc, font_title)
                        gdi32.SetTextColor(hdc, 0x00F8BD38)  # Sky blue
                        trc = wintypes.RECT(28, 30, rc.right - 28, 66)
                        user32.DrawTextW(hdc, t_txt, -1, ctypes.byref(trc), 0x0001 | 0x0010)  # DT_CENTER | DT_WORDBREAK

                        # Subtitle
                        gdi32.SelectObject(hdc, font_sub)
                        gdi32.SetTextColor(hdc, 0x00FFFFFF)
                        src = wintypes.RECT(28, 68, rc.right - 28, 122)
                        user32.DrawTextW(hdc, s_txt, -1, ctypes.byref(src), 0x0001 | 0x0010)

                        # Optional progress bar
                        if show_p:
                            bar_left, bar_right = 40, rc.right - 40
                            bar_top, bar_bot = 128, 146
                            bg_rc = wintypes.RECT(bar_left, bar_top, bar_right, bar_bot)
                            user32.FillRect(hdc, ctypes.byref(bg_rc), br_bar_bg)
                            fill_w = int((bar_right - bar_left) * (pct / 100.0))
                            if fill_w > 0:
                                fg_rc = wintypes.RECT(bar_left, bar_top, bar_left + fill_w, bar_bot)
                                user32.FillRect(hdc, ctypes.byref(fg_rc), br_bar_fg)

                        # Hint footer
                        gdi32.SelectObject(hdc, font_hint)
                        gdi32.SetTextColor(hdc, 0x00B8A394)
                        hrc = wintypes.RECT(28, rc.bottom - 44, rc.right - 28, rc.bottom - 20)
                        user32.DrawTextW(hdc, "Sensor USB ChipSailing Aktif  |  Tekan ESC atau tutup untuk batal", -1, ctypes.byref(hrc), 0x0001)

                        gdi32.SelectObject(hdc, old_font)
                    finally:
                        user32.EndPaint(hwnd, ctypes.byref(ps))
                    return 0

                if msg == WM_KEYDOWN and wparam == VK_ESCAPE:
                    if callable(self_ref.on_cancel):
                        try:
                            self_ref.on_cancel()
                        except Exception:
                            pass
                    user32.DestroyWindow(hwnd)
                    return 0

                if msg == WM_CLOSE:
                    if callable(self_ref.on_cancel):
                        try:
                            self_ref.on_cancel()
                        except Exception:
                            pass
                    user32.DestroyWindow(hwnd)
                    return 0

                if msg == WM_APP_CLOSE:
                    user32.DestroyWindow(hwnd)
                    return 0

                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0

                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            self._wndproc_ref = WNDPROC(wndproc)
            hinst = k32.GetModuleHandleW(None)

            with BiometricFocusWindow._class_lock:
                BiometricFocusWindow._class_counter += 1
                cls_name = f"HealingBioFocusWnd_{os.getpid()}_{BiometricFocusWindow._class_counter}"

            wc = WNDCLASSEXW()
            wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wc.style = 0x0003  # CS_HREDRAW | CS_VREDRAW
            wc.lpfnWndProc = self._wndproc_ref
            wc.hInstance = hinst
            wc.hCursor = user32.LoadCursorW(None, ctypes.c_void_p(32512))  # IDC_ARROW
            wc.hbrBackground = br_bg
            wc.lpszClassName = cls_name
            user32.RegisterClassExW(ctypes.byref(wc))

            # Center window on primary monitor
            w, h = 480, 210
            sw = user32.GetSystemMetrics(0) or 1366
            sh = user32.GetSystemMetrics(1) or 768
            x = max(20, (sw - w) // 2)
            y = max(20, (sh - h) // 2)

            self._prev_fg = user32.GetForegroundWindow()
            prev_pid = wintypes.DWORD()
            prev_tid = user32.GetWindowThreadProcessId(self._prev_fg, ctypes.byref(prev_pid)) if self._prev_fg else 0
            cur_tid = k32.GetCurrentThreadId()

            WS_EX_TOPMOST = 0x00000008
            WS_POPUP_CAPTION = 0x10C80000  # WS_VISIBLE | WS_CAPTION | WS_SYSMENU

            hwnd = user32.CreateWindowExW(
                WS_EX_TOPMOST,
                cls_name,
                "Healing POS - Sensor Sidik Jari USB",
                WS_POPUP_CAPTION,
                x, y, w, h,
                None, None, hinst, None,
            )
            self._hwnd = hwnd

            if hwnd:
                # Rebut foreground focus agar WbioSrvc mengirim sentuhan jari ke proses ini
                attached = False
                if prev_tid and prev_tid != cur_tid:
                    attached = bool(user32.AttachThreadInput(prev_tid, cur_tid, True))
                try:
                    user32.ShowWindow(hwnd, 5)  # SW_SHOW
                    user32.SetWindowPos(hwnd, -1, x, y, w, h, 0x0040)  # HWND_TOPMOST | SWP_SHOWWINDOW
                    user32.BringWindowToTop(hwnd)
                    ok_fg = bool(user32.SetForegroundWindow(hwnd))
                    if not ok_fg:
                        # Synthetic Alt-tap fallback untuk Windows foreground lock
                        user32.keybd_event(0x12, 0, 0, 0)
                        user32.keybd_event(0x12, 0, 2, 0)
                        user32.SetForegroundWindow(hwnd)
                    user32.SetActiveWindow(hwnd)
                    user32.SetFocus(hwnd)
                    user32.UpdateWindow(hwnd)
                finally:
                    if attached:
                        user32.AttachThreadInput(prev_tid, cur_tid, False)

                fg_now = user32.GetForegroundWindow()
                fg_pid = wintypes.DWORD()
                if fg_now:
                    user32.GetWindowThreadProcessId(fg_now, ctypes.byref(fg_pid))
                self._fg_pid = int(fg_pid.value)
                self._has_focus = (self._fg_pid == os.getpid())
                _log_debug(f"FocusWindow ready: hwnd={hwnd} prev_fg={self._prev_fg} fg_now={fg_now} fg_pid={self._fg_pid} has_focus={self._has_focus}")

            self._ready.set()

            msg = MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # Cleanup GDI & restore previous foreground window
            self._hwnd = None
            for obj in (br_bg, br_card, br_accent, br_bar_bg, br_bar_fg, font_title, font_sub, font_hint):
                try:
                    gdi32.DeleteObject(obj)
                except Exception:
                    pass
            try:
                user32.UnregisterClassW(cls_name, hinst)
            except Exception:
                pass
            if self._prev_fg:
                try:
                    user32.SetForegroundWindow(self._prev_fg)
                except Exception:
                    pass
        except Exception as e:
            _log_debug(f"FocusWindow exception: {e}")
            self._ready.set()
        finally:
            self._closed.set()


_CACHED_USER_SID = None


def get_current_user_sid() -> str:
    """Mengambil Windows Account SID pengguna saat ini (di-cache agar cepat dan konsisten)."""
    global _CACHED_USER_SID
    if _CACHED_USER_SID:
        return _CACHED_USER_SID
    try:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        out = subprocess.check_output(
            ["whoami", "/user"],
            text=True,
            creationflags=creation_flags,
            timeout=5,
        )
        for line in out.splitlines():
            for part in line.strip().split():
                if part.startswith("S-1-5-"):
                    _CACHED_USER_SID = part
                    return part
    except Exception:
        pass
    return "S-1-5-21-1278886982-1043087625-1810549722-1001"


def build_sid_identity(sid_str: str = None) -> WINBIO_IDENTITY:
    """Membangun struktur WINBIO_IDENTITY bertipe SID dari string SID Windows."""
    ident = WINBIO_IDENTITY()
    if not advapi32 or not kernel32:
        return ident
    sid_text = sid_str or get_current_user_sid()
    psid = ctypes.c_void_p()
    if ConvertStringSidToSidW(sid_text, ctypes.byref(psid)):
        try:
            sid_len = int(GetLengthSid(psid))
            if 0 < sid_len <= 68:
                ident.Type = WINBIO_ID_TYPE_SID
                ident.Value.AccountSid.Size = sid_len
                raw = (ctypes.c_ubyte * sid_len).from_address(psid.value)
                for i in range(sid_len):
                    ident.Value.AccountSid.Data[i] = raw[i]
        finally:
            LocalFree(psid)
    return ident


def describe_hresult(hr_unsigned: int) -> str:
    return HRESULT_MESSAGES.get(
        hr_unsigned,
        f"Kode status WinBio: 0x{hr_unsigned:08X}",
    )


class WinBioHardwareManager:
    def __init__(self):
        self.session = None
        self._lock = threading.Lock()
        self._op_lock = threading.Lock()
        self._active_worker = None
        self._cancel_requested = False
        self._timed_out = False

    def list_devices(self):
        """Mendeteksi semua perangkat biometrik yang terpasang di sistem."""
        devices = []
        if not winbio:
            return devices

        schema_array = PWINBIO_UNIT_SCHEMA()
        unit_count = ctypes.c_size_t()

        hr = WinBioEnumBiometricUnits(
            WINBIO_TYPE_FINGERPRINT,
            ctypes.byref(schema_array),
            ctypes.byref(unit_count),
        )

        if hr == 0 and unit_count.value > 0:
            try:
                for i in range(unit_count.value):
                    unit = schema_array[i]
                    devices.append({
                        "unit_id": int(unit.UnitId),
                        "pool_type": int(unit.PoolType),
                        "capabilities": int(unit.Capabilities),
                        "description": str(unit.Description),
                        "manufacturer": str(unit.Manufacturer),
                        "model": str(unit.Model),
                        "device_instance_id": str(unit.DeviceInstanceId),
                        "firmware_version": f"{unit.FirmwareVersion.MajorVersion}.{unit.FirmwareVersion.MinorVersion}",
                    })
            finally:
                WinBioFree(schema_array)
        return devices

    def open_session(self):
        """Membuka sesi biometrik sistem baru."""
        if not winbio:
            return False
        with self._lock:
            if self.session is not None:
                return True
            sess = wintypes.HANDLE()
            hr = WinBioOpenSession(
                WINBIO_TYPE_FINGERPRINT,
                WINBIO_POOL_SYSTEM,
                WINBIO_FLAG_DEFAULT,
                None,
                0,
                None,
                ctypes.byref(sess),
            )
            if hr == 0:
                self.session = sess
                return True
            _log_debug(f"WinBioOpenSession failed hr=0x{hr & 0xFFFFFFFF:08X}")
            return False

    def close_session(self):
        """Menutup sesi biometrik."""
        with self._lock:
            if self.session is not None:
                try:
                    WinBioCloseSession(self.session)
                except Exception:
                    pass
                self.session = None

    def _cancel_session_handle(self):
        """Memanggil WinBioCancel pada handle sesi aktif tanpa mengubah flag user-cancel."""
        with self._lock:
            if self.session is not None:
                try:
                    WinBioCancel(self.session)
                except Exception:
                    pass

    def cancel_scan(self):
        """Membatalkan pemindaian atau pendaftaran yang sedang berjalan (dipicu oleh pengguna)."""
        self._cancel_requested = True
        self._cancel_session_handle()

    def _sid_to_string(self, sid_pointer):
        """Mengonversi SID biner ke string SID Windows."""
        str_sid = wintypes.LPWSTR()
        if ConvertSidToStringSidW(sid_pointer, ctypes.byref(str_sid)):
            result = str(str_sid.value)
            LocalFree(str_sid)
            return result
        return ""

    def _extract_identity_sid(self, identity: WINBIO_IDENTITY) -> str:
        sid_str = ""
        if identity.Type == WINBIO_ID_TYPE_SID:
            sid_ptr = ctypes.byref(identity.Value.AccountSid.Data)
            sid_str = self._sid_to_string(sid_ptr)
        elif identity.Type == WINBIO_ID_TYPE_GUID:
            guid_bytes = bytes(identity.Value.TemplateGuid)
            sid_str = guid_bytes.hex()
        return sid_str

    def list_enrollments(self, unit_id: int = None):
        """Mengembalikan daftar sub_factor (1-10) yang saat ini sudah terdaftar pada sensor."""
        enrolled = []
        if not winbio:
            return enrolled
        devs = self.list_devices()
        if not devs:
            return enrolled
        uid = int(unit_id) if unit_id is not None else int(devs[0]["unit_id"])

        sess = wintypes.HANDLE()
        hr_open = WinBioOpenSession(
            WINBIO_TYPE_FINGERPRINT,
            WINBIO_POOL_SYSTEM,
            WINBIO_FLAG_DEFAULT,
            None,
            0,
            None,
            ctypes.byref(sess),
        )
        if hr_open != 0:
            return enrolled

        try:
            identity = build_sid_identity()
            if identity.Type != WINBIO_ID_TYPE_SID:
                return enrolled
            sub_arr = ctypes.POINTER(ctypes.c_ubyte)()
            sub_cnt = ctypes.c_size_t()
            hr = WinBioEnumEnrollments(
                sess,
                wintypes.ULONG(uid),
                ctypes.byref(identity),
                ctypes.byref(sub_arr),
                ctypes.byref(sub_cnt),
            )
            if hr == 0 and sub_cnt.value > 0:
                try:
                    for i in range(sub_cnt.value):
                        sf = int(sub_arr[i])
                        sf_id, sf_en = SUBFACTOR_NAMES.get(sf, (f"Jari {sf}", f"Finger {sf}"))
                        enrolled.append({
                            "sub_factor": sf,
                            "sub_factor_name": sf_id,
                            "sub_factor_name_en": sf_en,
                        })
                finally:
                    WinBioFree(sub_arr)
        finally:
            try:
                WinBioCloseSession(sess)
            except Exception:
                pass
        return enrolled

    def get_next_available_slot(self, unit_id: int = None, excluded_slots=None) -> int:
        """Mencari nomor slot (1-254) pertama yang masih kosong pada sensor (1 orang = 1 jari)."""
        used = set()
        if excluded_slots:
            for s in excluded_slots:
                try:
                    used.add(int(s))
                except Exception:
                    pass
        try:
            for e in self.list_enrollments(unit_id):
                used.add(int(e["sub_factor"]))
        except Exception:
            pass
        for slot in range(1, 255):
            if slot not in used:
                return slot
        return 1

    def delete_enrollment(self, sub_factor: int, unit_id: int = None):
        """Menghapus template sidik jari untuk slot sub_factor tertentu (1-254) dari Windows Biometrics."""
        if not winbio:
            return {"success": False, "message": "winbio.dll tidak tersedia."}
        sf = int(sub_factor)
        if sf < 1 or sf > 254:
            return {"success": False, "message": "Nomor slot sidik jari tidak valid (1-254)."}
        devs = self.list_devices()
        if not devs:
            return {"success": False, "status": "NO_HARDWARE", "message": "Sensor USB tidak terdeteksi."}
        uid = int(unit_id) if unit_id is not None else int(devs[0]["unit_id"])

        sess = wintypes.HANDLE()
        hr_open = WinBioOpenSession(
            WINBIO_TYPE_FINGERPRINT,
            WINBIO_POOL_SYSTEM,
            WINBIO_FLAG_DEFAULT,
            None,
            0,
            None,
            ctypes.byref(sess),
        )
        if hr_open != 0:
            hr_u = hr_open & 0xFFFFFFFF
            return {"success": False, "message": f"Gagal membuka sesi WinBio: {describe_hresult(hr_u)}"}

        try:
            identity = build_sid_identity()
            if identity.Type != WINBIO_ID_TYPE_SID:
                return {"success": False, "message": "Gagal membaca SID akun Windows saat ini."}
            hr = WinBioDeleteTemplate(
                sess,
                wintypes.ULONG(uid),
                ctypes.byref(identity),
                ctypes.c_ubyte(sf),
            )
            hr_u = hr & 0xFFFFFFFF
            if hr_u in (S_OK, WINBIO_E_NO_MATCH, 0x8009801B):
                return {"success": True, "status": "SUCCESS", "message": f"Template sidik jari slot #{sf} berhasil dibersihkan."}
            return {"success": False, "status": "ERROR", "hresult": hex(hr_u), "message": describe_hresult(hr_u)}
        finally:
            try:
                WinBioCloseSession(sess)
            except Exception:
                pass

    def _start_timeout_watcher(self, timeout_seconds: float, active_flag: list):
        """Thread pengawas timeout: memanggil WinBioCancel secara aman tanpa mengubah _cancel_requested."""
        def timer_func():
            deadline = time.time() + max(1.0, float(timeout_seconds))
            while active_flag[0] and time.time() < deadline:
                time.sleep(0.15)
            if active_flag[0] and not self._cancel_requested:
                self._timed_out = True
                self._cancel_session_handle()

        t = threading.Thread(target=timer_func, daemon=True)
        t.start()
        return t

    def scan_fingerprint_async(self, on_result, timeout_seconds=30, allow_unregistered=False, use_focus_window=False):
        """
        Menjalankan proses scan sidik jari di background thread.
        use_focus_window=True: menampilkan jendela Win32 foreground sementara agar WbioSrvc
        mengirim sentuhan sensor USB meskipun dipanggil dari Electron / Web Browser.
        """
        self.cancel_scan()

        def worker():
            with self._op_lock:
                devs = self.list_devices()
                if not devs:
                    on_result({
                        "status": "NO_HARDWARE",
                        "message": "Hardware scanner sidik jari USB tidak terdeteksi. Silakan colokkan kabel scanner USB.",
                    })
                    return

                focus_win = None
                if use_focus_window:
                    focus_win = BiometricFocusWindow(
                        title="TEMPELKAN JARI KE SENSOR USB",
                        subtitle="Mode Bebas (Sentuh jari mana saja)..." if allow_unregistered else "Sentuhkan jari terdaftar pada scanner USB ChipSailing...",
                        show_progress=False,
                        on_cancel=self.cancel_scan,
                    )
                    focus_win.start()

                try:
                    self.close_session()
                    if not self.open_session():
                        on_result({
                            "status": "ERROR",
                            "message": "Gagal membuka sesi Windows Biometric. Pastikan layanan Windows Biometric Service aktif.",
                        })
                        return

                    self._cancel_requested = False
                    self._timed_out = False
                    unit_id = wintypes.ULONG()
                    identity = WINBIO_IDENTITY()
                    sub_factor = ctypes.c_ubyte()
                    reject_detail = wintypes.ULONG()

                    timer_active = [True]
                    self._start_timeout_watcher(timeout_seconds, timer_active)

                    max_attempts = 1 if allow_unregistered else 5
                    attempt = 0
                    last_hr_unsigned = 0
                    last_reject = 0

                    _log_debug(f"WinBioIdentify start (timeout={timeout_seconds}, allow_unreg={allow_unregistered}, max_attempts={max_attempts}, focus_win={use_focus_window})")
                    try:
                        while attempt < max_attempts:
                            attempt += 1
                            unit_id.value = 0
                            sub_factor.value = 0
                            reject_detail.value = 0
                            identity = WINBIO_IDENTITY()

                            hr = WinBioIdentify(
                                self.session,
                                ctypes.byref(unit_id),
                                ctypes.byref(identity),
                                ctypes.byref(sub_factor),
                                ctypes.byref(reject_detail),
                            )
                            hr_unsigned = hr & 0xFFFFFFFF
                            last_hr_unsigned = hr_unsigned
                            last_reject = int(reject_detail.value)
                            _log_debug(f"WinBioIdentify attempt {attempt}/{max_attempts}: hr=0x{hr_unsigned:08X} unit={unit_id.value} sf={sub_factor.value} reject={last_reject} idType={identity.Type}")

                            if hr_unsigned == S_OK:
                                sf = int(sub_factor.value)
                                sf_id, sf_en = SUBFACTOR_NAMES.get(sf, ("Jari Lain", "Other Finger"))
                                sid_str = self._extract_identity_sid(identity) or get_current_user_sid()
                                if focus_win:
                                    focus_win.update(title="SIDIK JARI DITERIMA!", subtitle=f"Teridentifikasi: {sf_id}")
                                on_result({
                                    "status": "SUCCESS",
                                    "sub_factor": sf,
                                    "sub_factor_name": sf_id,
                                    "sub_factor_name_en": sf_en,
                                    "sid": sid_str,
                                    "unit_id": int(unit_id.value),
                                    "reject_detail": last_reject,
                                    "is_unregistered": False,
                                    "message": f"Sidik jari berhasil dikenali: {sf_id}",
                                })
                                return

                            if hr_unsigned in (WINBIO_E_UNKNOWN_ID, WINBIO_E_NO_MATCH):
                                if allow_unregistered:
                                    on_result({
                                        "status": "SUCCESS",
                                        "sub_factor": 0,
                                        "sub_factor_name": "Jari Bebas (Tanpa Registrasi)",
                                        "sub_factor_name_en": "Unregistered Finger",
                                        "sid": "ANONYMOUS_TOUCH_SID",
                                        "unit_id": int(unit_id.value) if unit_id.value else int(devs[0]["unit_id"]),
                                        "reject_detail": 0,
                                        "is_unregistered": True,
                                        "message": "Sentuhan jari terdeteksi! (Mode Bebas Tanpa Registrasi)",
                                    })
                                    return
                                # ChipSailing sering mengembalikan 0x80098003 saat sentuhan awal kurang rata -> auto retry
                                if attempt < max_attempts and not self._cancel_requested and not self._timed_out:
                                    if focus_win:
                                        focus_win.update(
                                            title="COBA TEMPELKAN LAGI",
                                            subtitle=f"Sentuhan belum cocok ({attempt}/{max_attempts}). Angkat lalu tempelkan jari rata di tengah sensor...",
                                        )
                                    time.sleep(0.25)
                                    continue
                                on_result({
                                    "status": "NO_MATCH",
                                    "hresult": hex(hr_unsigned),
                                    "message": "Sidik jari terdeteksi, namun tidak cocok dengan jari terdaftar mana pun. Pastikan jari sudah didaftarkan dan tempelkan rata di tengah sensor.",
                                })
                                return

                            if hr_unsigned in (WINBIO_E_BAD_CAPTURE, WINBIO_E_CAPTURE_ABORTED) or last_reject > 0:
                                reason = REJECT_REASONS.get(last_reject, "Kualitas scan sidik jari kurang jelas.")
                                if attempt < max_attempts and not self._cancel_requested and not self._timed_out:
                                    if focus_win:
                                        focus_win.update(
                                            title="POSISI JARI KURANG PAS",
                                            subtitle=f"{reason} ({attempt}/{max_attempts}). Tempelkan lagi...",
                                        )
                                    time.sleep(0.25)
                                    continue
                                on_result({
                                    "status": "REJECTED",
                                    "reject_detail": last_reject,
                                    "message": f"Sensor mendeteksi sentuhan, namun: {reason}",
                                })
                                return

                            if hr_unsigned == WINBIO_E_CANCELED:
                                if self._timed_out:
                                    on_result({
                                        "status": "TIMEOUT",
                                        "message": f"Waktu scan habis ({timeout_seconds} detik). Tidak ada sentuhan yang cocok pada sensor.",
                                    })
                                else:
                                    on_result({
                                        "status": "CANCELED",
                                        "message": "Pemindaian dibatalkan.",
                                    })
                                return

                            on_result({
                                "status": "ERROR",
                                "hresult": hex(hr_unsigned),
                                "message": describe_hresult(hr_unsigned),
                            })
                            return
                    except Exception as e:
                        _log_debug(f"WinBioIdentify exception: {e}")
                        on_result({
                            "status": "ERROR",
                            "message": f"Exception saat identifikasi: {e}",
                        })
                        return
                    finally:
                        timer_active[0] = False
                        self.close_session()
                finally:
                    if focus_win is not None:
                        focus_win.close()

        t = threading.Thread(target=worker, daemon=True)
        self._active_worker = t
        t.start()

    def enroll_fingerprint_async(self, sub_factor: int, unit_id: int, on_progress, timeout_seconds=90, overwrite=True, use_focus_window=False):
        """
        Mendaftarkan jari baru LANGSUNG di dalam aplikasi (In-App Enrollment)
        tanpa perlu membuka Windows Hello Settings.
        """
        self.cancel_scan()

        def worker():
            with self._op_lock:
                devs = self.list_devices()
                if not devs:
                    on_progress({
                        "status": "NO_HARDWARE",
                        "progress": 0,
                        "message": "Hardware scanner sidik jari USB tidak terdeteksi. Silakan colokkan kabel scanner USB.",
                    })
                    return

                uid = int(unit_id) if unit_id else int(devs[0]["unit_id"])
                sf = int(sub_factor) if sub_factor is not None else 0
                if sf < 1 or sf > 254:
                    sf = self.get_next_available_slot(uid)
                sf_label = f"Sidik Jari (Slot #{sf})"

                if overwrite:
                    try:
                        existing = [e["sub_factor"] for e in self.list_enrollments(uid)]
                        if sf in existing:
                            self.delete_enrollment(sf, uid)
                    except Exception:
                        pass

                focus_win = None
                if use_focus_window:
                    focus_win = BiometricFocusWindow(
                        title="DAFTARKAN SIDIK JARI KARYAWAN",
                        subtitle="Tempelkan 1 jari ke sensor USB berulang kali sampai 100%...",
                        show_progress=True,
                        on_cancel=self.cancel_scan,
                    )
                    focus_win.start()

                self.close_session()
                if not self.open_session():
                    if focus_win is not None:
                        focus_win.close()
                    on_progress({
                        "status": "ERROR",
                        "progress": 0,
                        "message": "Gagal membuka sesi Windows Biometric untuk pendaftaran.",
                    })
                    return

                self._cancel_requested = False
                self._timed_out = False
                enroll_started = False
                timer_active = [True]

                try:
                    hr_begin = WinBioEnrollBegin(self.session, ctypes.c_ubyte(sf), wintypes.ULONG(uid))
                    hr_begin_u = hr_begin & 0xFFFFFFFF
                    _log_debug(f"WinBioEnrollBegin sf={sf} uid={uid} hr=0x{hr_begin_u:08X}")
                    if hr_begin_u != S_OK:
                        on_progress({
                            "status": "DUPLICATE_FINGER" if hr_begin_u == WINBIO_E_DUPLICATE_ENROLLMENT else "ERROR",
                            "progress": 0,
                            "hresult": hex(hr_begin_u),
                            "message": f"Gagal memulai pendaftaran: {describe_hresult(hr_begin_u)}",
                        })
                        return

                    enroll_started = True
                    self._start_timeout_watcher(timeout_seconds, timer_active)

                    if focus_win:
                        focus_win.update(progress=10, subtitle="Tempelkan jari Anda ke sensor untuk sampel pertama...")
                    on_progress({
                        "status": "IN_PROGRESS",
                        "progress": 10,
                        "message": "Tempelkan jari Anda ke sensor untuk sampel pertama...",
                        "samples_needed": 4,
                    })

                    samples_captured = 0
                    reject_detail = wintypes.ULONG()

                    while True:
                        if self._cancel_requested:
                            on_progress({"status": "CANCELED", "progress": 0, "message": "Pendaftaran dibatalkan."})
                            return

                        if self._timed_out:
                            on_progress({"status": "TIMEOUT", "progress": 0, "message": f"Waktu pendaftaran habis ({timeout_seconds} detik)."})
                            return

                        reject_detail.value = 0
                        hr_cap = WinBioEnrollCapture(self.session, ctypes.byref(reject_detail))
                        hr_unsigned = hr_cap & 0xFFFFFFFF
                        _log_debug(f"WinBioEnrollCapture hr=0x{hr_unsigned:08X} reject={reject_detail.value} samples={samples_captured}")

                        if hr_unsigned == WINBIO_I_MORE_DATA:
                            samples_captured += 1
                            pct = min(10 + (8 * samples_captured), 95)
                            msg = f"Sampel #{samples_captured} terbaca! Angkat dan tempelkan jari lagi..."
                            if focus_win:
                                focus_win.update(progress=pct, subtitle=msg)
                            on_progress({
                                "status": "IN_PROGRESS",
                                "progress": pct,
                                "message": msg,
                                "samples_needed": max(1, 12 - samples_captured),
                            })

                        elif hr_unsigned == S_OK:
                            identity = WINBIO_IDENTITY()
                            is_new = wintypes.BOOLEAN()
                            hr_commit = WinBioEnrollCommit(self.session, ctypes.byref(identity), ctypes.byref(is_new))
                            hr_commit_u = hr_commit & 0xFFFFFFFF
                            _log_debug(f"WinBioEnrollCommit hr=0x{hr_commit_u:08X} idType={identity.Type} isNew={is_new.value}")

                            if hr_commit_u == S_OK:
                                enroll_started = False
                                sid_str = self._extract_identity_sid(identity) or get_current_user_sid()
                                sf_id, sf_en = SUBFACTOR_NAMES.get(sf, (f"Sidik Jari #{sf}", f"Finger Slot #{sf}"))
                                if focus_win:
                                    focus_win.update(progress=100, subtitle="Pendaftaran jari berhasil disimpan!")
                                on_progress({
                                    "status": "SUCCESS",
                                    "progress": 100,
                                    "sid": sid_str,
                                    "sub_factor": sf,
                                    "sub_factor_name": f"Sidik Jari (Slot #{sf})",
                                    "sub_factor_name_en": sf_en,
                                    "is_new": bool(is_new.value),
                                    "message": "Pendaftaran jari berhasil disimpan ke Windows Biometrics!",
                                })
                            elif hr_commit_u in (WINBIO_E_DUPLICATE_ENROLLMENT, WINBIO_E_DUPLICATE_TEMPLATE):
                                on_progress({
                                    "status": "DUPLICATE_FINGER",
                                    "progress": 0,
                                    "hresult": hex(hr_commit_u),
                                    "message": describe_hresult(hr_commit_u),
                                })
                            else:
                                on_progress({
                                    "status": "ERROR",
                                    "progress": 0,
                                    "hresult": hex(hr_commit_u),
                                    "message": f"Gagal menyimpan template: {describe_hresult(hr_commit_u)}",
                                })
                            return

                        elif hr_unsigned == WINBIO_E_CANCELED:
                            if self._timed_out:
                                on_progress({"status": "TIMEOUT", "progress": 0, "message": f"Waktu pendaftaran habis ({timeout_seconds} detik)."})
                            else:
                                on_progress({"status": "CANCELED", "progress": 0, "message": "Pendaftaran dibatalkan."})
                            return

                        elif hr_unsigned == WINBIO_E_BAD_CAPTURE or reject_detail.value > 0:
                            reason = REJECT_REASONS.get(int(reject_detail.value), "Kualitas sentuhan kurang jelas.")
                            msg = f"Sentuhan kurang sempurna: {reason}. Coba tempelkan lagi..."
                            pct = min(15 + (20 * samples_captured), 90)
                            if focus_win:
                                focus_win.update(progress=pct, subtitle=msg)
                            on_progress({
                                "status": "RETRY",
                                "progress": pct,
                                "message": msg,
                            })

                        elif hr_unsigned in (WINBIO_E_DUPLICATE_ENROLLMENT, WINBIO_E_DUPLICATE_TEMPLATE):
                            on_progress({
                                "status": "DUPLICATE_FINGER",
                                "progress": 0,
                                "hresult": hex(hr_unsigned),
                                "message": describe_hresult(hr_unsigned),
                            })
                            return

                        else:
                            on_progress({
                                "status": "ERROR",
                                "progress": 0,
                                "hresult": hex(hr_unsigned),
                                "message": f"Error pendaftaran: {describe_hresult(hr_unsigned)}",
                            })
                            return

                except Exception as e:
                    _log_debug(f"Enroll exception: {e}")
                    on_progress({"status": "ERROR", "progress": 0, "message": f"Exception: {e}"})
                finally:
                    timer_active[0] = False
                    if enroll_started and self.session is not None:
                        try:
                            WinBioEnrollDiscard(self.session)
                        except Exception:
                            pass
                    self.close_session()
                    if focus_win is not None:
                        focus_win.close()

        t = threading.Thread(target=worker, daemon=True)
        self._active_worker = t
        t.start()
