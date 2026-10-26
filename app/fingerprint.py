"""Generator spójnych profili fingerprintu przeglądarki.

Profil jest deterministyczny względem ziarna (seed): to samo ziarno => ten sam
"komputer". Dzięki temu konto zalogowane w profilu A zawsze widzi ten sam fingerprint,
a profil B wygląda jak zupełnie inne urządzenie.

Wynikowy słownik trafia (jako JSON) do rozszerzenia z browser-image/fpext oraz do
launchera. Wersja Chrome jest wstawiana dopiero w przeglądarce (placeholder %MAJOR%),
bo tylko ona wie, jaki Chromium faktycznie działa w obrazie.
"""
import hashlib
import random
import re
import secrets

OS_FAMILIES = ("windows", "mac", "linux")

_OS = {
    "windows": {
        "platform": "Win32",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "ch_platform": "Windows",
        "ch_platform_version": "10.0.0",
        "screens": [(1920, 1080), (1366, 768), (1536, 864), (2560, 1440), (1600, 900)],
        "taskbar": 40,
        "gpus": [
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ],
        "cores": [4, 6, 8, 12, 16],
        "memory": [4, 8, 8],
    },
    "mac": {
        "platform": "MacIntel",
        "ua_os": "Macintosh; Intel Mac OS X 10_15_7",
        "ch_platform": "macOS",
        "ch_platform_version": "14.5.0",
        "screens": [(1440, 900), (1512, 982), (1728, 1117), (2560, 1600)],
        "taskbar": 25,
        "gpus": [
            ("Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"),
            ("Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"),
        ],
        "cores": [8, 10],
        "memory": [8, 8],
    },
    "linux": {
        "platform": "Linux x86_64",
        "ua_os": "X11; Linux x86_64",
        "ch_platform": "Linux",
        "ch_platform_version": "6.5.0",
        "screens": [(1920, 1080), (1920, 1200), (2560, 1440)],
        "taskbar": 0,
        "gpus": [
            ("Google Inc. (Intel)", "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)"),
            ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon Graphics (renoir, LLVM 15.0.7, DRM 3.49), OpenGL 4.6)"),
        ],
        "cores": [4, 8, 12],
        "memory": [8, 8],
    },
}

RESOLUTIONS = ("1280x720", "1366x768", "1600x900", "1920x1080")
LANGS = ("pl-PL", "en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "it-IT", "cs-CZ", "uk-UA")

_RES_RE = re.compile(r"^(\d{3,4})x(\d{3,4})$")
_LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Z]{2})?$")
_TZ_RE = re.compile(r"^[A-Za-z_]+(/[A-Za-z0-9_+\-]+){0,2}$")


def new_seed():
    return secrets.token_hex(8)


def parse_resolution(value):
    m = _RES_RE.match(value or "")
    if not m:
        return None
    w, h = int(m.group(1)), int(m.group(2))
    return (w, h) if 640 <= w <= 3840 and 480 <= h <= 2160 else None


def valid_lang(value):
    return bool(_LANG_RE.match(value or ""))


def valid_timezone(value):
    if not _TZ_RE.match(value or ""):
        return False
    try:
        import zoneinfo
        return value in zoneinfo.available_timezones()
    except Exception:  # brak bazy stref - zostaje walidacja regexem
        return True


def _int_seed(seed, label):
    return int.from_bytes(hashlib.sha256(f"{seed}:{label}".encode()).digest()[:4], "big")


def generate(seed, os_family="windows", lang="pl-PL", timezone="Europe/Warsaw",
             resolution="1280x720"):
    """Zwraca słownik konfiguracji fingerprintu (serializowalny do JSON)."""
    if os_family not in _OS:
        raise ValueError("nieznany system")
    spec = _OS[os_family]
    rnd = random.Random(_int_seed(seed, "base"))
    win_w, win_h = parse_resolution(resolution) or (1280, 720)

    # ekran musi być co najmniej tak duży jak okno przeglądarki
    screens = [s for s in spec["screens"] if s[0] >= win_w and s[1] >= win_h] or [(win_w, win_h)]
    sw, sh = rnd.choice(screens)
    vendor, renderer = rnd.choice(spec["gpus"])
    base = lang.split("-")[0]
    languages = [lang] + ([base] if base != lang else [])
    if base != "en":
        languages += ["en-US", "en"]

    return {
        "seed": seed,
        "os": os_family,
        "uaTemplate": (f"Mozilla/5.0 ({spec['ua_os']}) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/%MAJOR%.0.0.0 Safari/537.36"),
        "platform": spec["platform"],
        "chPlatform": spec["ch_platform"],
        "chPlatformVersion": spec["ch_platform_version"],
        "languages": languages,
        "timezone": timezone,
        "hardwareConcurrency": rnd.choice(spec["cores"]),
        "deviceMemory": rnd.choice(spec["memory"]),
        "screen": {
            "width": sw, "height": sh,
            "availWidth": sw, "availHeight": sh - spec["taskbar"],
            "colorDepth": 24,
        },
        "webgl": {"vendor": vendor, "renderer": renderer},
        "noise": {
            "canvas": _int_seed(seed, "canvas"),
            "audio": _int_seed(seed, "audio"),
            "webgl": _int_seed(seed, "webgl"),
            "devices": _int_seed(seed, "devices"),
        },
    }


def summary(fp):
    """Krótki opis do wyświetlenia na karcie profilu."""
    if not fp:
        return ""
    s = fp.get("screen", {})
    gpu = fp.get("webgl", {}).get("renderer", "")
    m = re.search(r"ANGLE \([^,]+, ([^,)]+)", gpu)
    return (f"{fp.get('os')} · {fp.get('hardwareConcurrency')} rdz. · {fp.get('deviceMemory')} GB · "
            f"{s.get('width')}x{s.get('height')} · {re.sub(r' Direct3D11.*$', '', m.group(1)) if m else gpu}")
