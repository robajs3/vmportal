"""Wirtualne przeglądarki: sesje = kontenery neko+Chromium zarządzane przez Dockera.

Jeden profil (persistentny katalog Chromium w wolumenie Dockera) = co najwyżej jeden
kontener. Kontener można zatrzymać (RAM wraca do puli, profil zostaje) i uruchomić
ponownie. Wszystkie sesje dzielą jedną pulę RAM (BROWSER_POOL_RAM_MB) niezależnie
od tego, który użytkownik je uruchomił.

Moduł nie zna Flaska ani bazy - dostaje zwykłe słowniki, dzięki czemu łatwo go testować.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone

try:  # w testach można podstawić własnego klienta
    import docker
    from docker.errors import APIError, ImageNotFound, NotFound
except ImportError:  # pragma: no cover
    docker = None
    APIError = ImageNotFound = NotFound = Exception

import requests

import fingerprint as fpmod

# --- konfiguracja (zmienne środowiskowe) -----------------------------------------------
DOCKER_HOST = os.environ.get("BROWSER_DOCKER_HOST", "tcp://docker-proxy:2375")
IMAGE = os.environ.get("BROWSER_IMAGE", "vmportal-browser:latest")
RUNNER_IMAGE = os.environ.get("BROWSER_RUNNER_IMAGE", "vmportal-runner:latest")
NETWORK = os.environ.get("BROWSER_NETWORK", "vmportal_br_net")
EXT_VOLUME = os.environ.get("BROWSER_EXT_VOLUME", "vmportal_br_extensions")
EXT_LOCAL_DIR = os.environ.get("BROWSER_EXT_LOCAL_DIR", "/data/extensions")
POOL_RAM_MB = int(os.environ.get("BROWSER_POOL_RAM_MB", "4096"))
OVERCOMMIT = float(os.environ.get("BROWSER_OVERCOMMIT", "1.5"))
MAX_SESSION_RAM_MB = int(os.environ.get("BROWSER_MAX_RAM_MB", "2048"))
MIN_SESSION_RAM_MB = 384
DEFAULT_SESSION_RAM_MB = int(os.environ.get("BROWSER_DEFAULT_RAM_MB", "768"))
RTC_PORT_MIN = int(os.environ.get("BROWSER_RTC_PORT_MIN", "52000"))
RTC_PORT_MAX = int(os.environ.get("BROWSER_RTC_PORT_MAX", "52099"))
PUBLIC_IP = os.environ.get("BROWSER_PUBLIC_IP", "")
FPS = os.environ.get("BROWSER_FPS", "15")
PATH_PREFIX = "/br"          # ścieżka sesji w nginx: /br/<public_id>/
MAX_SCRIPT_BYTES = 64 * 1024
MAX_RUN_SECONDS = int(os.environ.get("BROWSER_MAX_RUN_SECONDS", "3600"))
MAX_LOG_BYTES = 64 * 1024

LABEL = "vmbr.managed"
STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
STORE_ID_RE = re.compile(r"^[a-p]{32}$")
_STORE_URL_ID = re.compile(r"/([a-p]{32})(?:[/?#]|$)")
PROXY_RE = re.compile(r"^(https?|socks5|socks4)://[A-Za-z0-9.\-]+:\d{2,5}$")
PID_RE = re.compile(r"^[0-9a-f]{12}$")


class BrowserError(Exception):
    pass


class PoolFull(BrowserError):
    pass


# --- proste funkcje pomocnicze -----------------------------------------------------------
def container_name(pid):
    return f"vmbr-{pid}"


def volume_name(pid):
    return f"vmbr-prof-{pid}"


def session_password(secret, pid, role="admin"):
    """Hasła do neko wyliczane z SECRET_KEY - nie trzeba ich przechowywać w bazie."""
    return hmac.new(secret.encode(), f"vmbr:{pid}:{role}".encode(), hashlib.sha256).hexdigest()[:32]


def parse_store_id(text):
    """Przyjmuje samo ID (32 znaki a-p) albo URL ze sklepu Chrome Web Store."""
    text = (text or "").strip()
    if STORE_ID_RE.match(text):
        return text
    m = _STORE_URL_ID.search(text)
    return m.group(1) if m else None


def build_policy(store_ids):
    ids = sorted(set(store_ids))
    if not ids:
        return {}
    return {
        "ExtensionInstallForcelist": [f"{i};{STORE_UPDATE_URL}" for i in ids],
        "ExtensionInstallAllowlist": ids,
    }


def _b64(obj):
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def build_env(profile, secret):
    """Zmienne środowiskowe kontenera: konfiguracja neko + parametry launchera (BR_*)."""
    pid = profile["public_id"]
    fp = profile.get("fp")
    port = profile["rtc_port"]
    ram = profile["ram_mb"]
    langs = (fp or {}).get("languages") or [profile.get("lang") or "pl-PL"]

    env = {
        # neko
        "NEKO_SERVER_PATH_PREFIX": f"{PATH_PREFIX}/{pid}",
        "NEKO_SERVER_METRICS": "false",
        "NEKO_SESSION_COOKIE_ENABLED": "false",   # token zamiast ciasteczka (nginx i tak wycina Cookie)
        "NEKO_SESSION_IMPLICIT_HOSTING": "true",  # kontrolę przejmuje ten, kto kliknie w ekran (bez ręcznego "Take control")
        "NEKO_MEMBER_PROVIDER": "multiuser",
        "NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD": session_password(secret, pid, "admin"),
        "NEKO_MEMBER_MULTIUSER_USER_PASSWORD": session_password(secret, pid, "user"),
        "NEKO_DESKTOP_SCREEN": f"{profile['resolution']}@{FPS}",
        "NEKO_WEBRTC_UDPMUX": str(port),
        "NEKO_WEBRTC_TCPMUX": str(port),
        # launcher
        "BR_TZ": profile["timezone"],
        "BR_LANG": langs[0],
        "BR_ACCEPT_LANG": ",".join(langs),
        "BR_WEBGL": "1" if profile.get("webgl", True) else "0",
        "BR_RENDERERS": "3" if ram >= 1024 else "2",
        "BR_V8_MB": "512" if ram >= 1024 else "256",
        "BR_START_URL": profile.get("start_url") or "about:blank",
    }
    if PUBLIC_IP:
        env["NEKO_WEBRTC_NAT1TO1"] = PUBLIC_IP
    if fp:
        env["BR_FP_B64"] = _b64(fp)
        env["BR_UA"] = fp["uaTemplate"]
    if profile.get("proxy"):
        env["BR_PROXY"] = profile["proxy"]

    exts = profile.get("extensions") or []
    policy = build_policy([e["ext_id"] for e in exts if e["kind"] == "store"])
    if policy:
        env["BR_POLICY_B64"] = _b64(policy)
    dirs = [f"/extensions/{e['dirname']}" for e in exts if e["kind"] == "upload"]
    if dirs:
        env["BR_EXT_DIRS"] = " ".join(dirs)
    return env


# --- rozpakowywanie wgranych wtyczek -----------------------------------------------------
MAX_EXT_BYTES = 80 * 1024 * 1024
MAX_EXT_FILES = 5000


def _crx_to_zip(data):
    """CRX2/CRX3 = nagłówek + zwykły ZIP."""
    if data[:4] != b"Cr24":
        return data
    version = int.from_bytes(data[4:8], "little")
    if version == 3:
        hdr = int.from_bytes(data[8:12], "little")
        return data[12 + hdr:]
    if version == 2:
        pub, sig = int.from_bytes(data[8:12], "little"), int.from_bytes(data[12:16], "little")
        return data[16 + pub + sig:]
    raise BrowserError("Nieobsługiwana wersja pliku CRX.")


def unpack_extension(data, dest_dir):
    """Rozpakowuje .zip/.crx do dest_dir (bezpiecznie, bez zip-slip). Zwraca manifest."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(_crx_to_zip(data)))
    except zipfile.BadZipFile:
        raise BrowserError("To nie jest poprawny plik ZIP/CRX.")
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if not infos or len(infos) > MAX_EXT_FILES or sum(i.file_size for i in infos) > MAX_EXT_BYTES:
        raise BrowserError("Archiwum puste albo zbyt duże.")

    # manifest.json w korzeniu albo w jedynym katalogu najwyższego poziomu
    names = [i.filename for i in infos]
    prefix = ""
    if "manifest.json" not in names:
        tops = {n.split("/", 1)[0] for n in names if "/" in n}
        if len(tops) == 1 and f"{next(iter(tops))}/manifest.json" in names:
            prefix = next(iter(tops)) + "/"
        else:
            raise BrowserError("Brak manifest.json w archiwum.")

    os.makedirs(dest_dir, exist_ok=True)
    root = os.path.realpath(dest_dir)
    for info in infos:
        if not info.filename.startswith(prefix):
            continue
        rel = info.filename[len(prefix):]
        target = os.path.realpath(os.path.join(root, rel))
        if not target.startswith(root + os.sep):
            raise BrowserError("Niedozwolona ścieżka w archiwum.")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            out.write(src.read())
    try:
        manifest = json.load(open(os.path.join(root, "manifest.json"), encoding="utf-8-sig"))
    except (ValueError, OSError):
        raise BrowserError("manifest.json jest nieprawidłowy.")
    if manifest.get("manifest_version") not in (2, 3):
        raise BrowserError("Nieobsługiwana wersja manifestu wtyczki.")
    return manifest


# --- orkiestrator ------------------------------------------------------------------------
def _iso_to_epoch(text):
    try:
        return datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


class Orchestrator:
    def __init__(self, client=None, secret=""):
        self.secret = secret
        self._client = client

    @property
    def client(self):
        if self._client is None:
            if docker is None:
                raise BrowserError("Brak biblioteki docker w obrazie aplikacji.")
            self._client = docker.DockerClient(base_url=DOCKER_HOST, timeout=60)
        return self._client

    # --- stan ---
    def _managed(self):
        try:
            return self.client.containers.list(all=True, filters={"label": f"{LABEL}=1"})
        except Exception as exc:
            raise BrowserError(f"Docker niedostępny: {exc}")

    def sessions(self):
        """Mapa public_id -> {state, ram_mb, rtc_port} dla wszystkich kontenerów sesji."""
        out = {}
        for c in self._managed():
            lb = c.labels or {}
            out[lb.get("vmbr.pid")] = {
                "state": c.status,  # created/running/restarting/exited/...
                "ram_mb": int(lb.get("vmbr.ram_mb", "0") or 0),
                "rtc_port": int(lb.get("vmbr.rtc_port", "0") or 0),
            }
        return out

    def pool(self):
        sess = self.sessions()
        live = [s for s in sess.values() if s["state"] in ("running", "restarting", "created")]
        used = sum(s["ram_mb"] for s in live)
        return {
            "budget_mb": int(POOL_RAM_MB * OVERCOMMIT),
            "physical_mb": POOL_RAM_MB,
            "reserved_mb": used,
            "sessions": len(live),
            "ports_free": (RTC_PORT_MAX - RTC_PORT_MIN + 1) - len(live),
        }

    def state_of(self, pid, sessions=None):
        sessions = self.sessions() if sessions is None else sessions
        s = sessions.get(pid)
        return s["state"] if s else "stopped"

    # --- start / stop ---
    def start(self, profile):
        """Uruchamia kontener profilu. Wołać pod blokadą (advisory lock) - sprawdza pulę i porty."""
        pid = profile["public_id"]
        sess = self.sessions()
        if pid in sess:
            if sess[pid]["state"] == "running":
                return
            self._remove(pid)  # martwy kontener po poprzednim uruchomieniu
            sess.pop(pid)

        live = [s for s in sess.values() if s["state"] in ("running", "restarting", "created")]
        budget = int(POOL_RAM_MB * OVERCOMMIT)
        used = sum(s["ram_mb"] for s in live)
        if used + profile["ram_mb"] > budget:
            raise PoolFull(
                f"Pula pamięci jest pełna: zarezerwowane {used} MB z {budget} MB, "
                f"ta sesja potrzebuje {profile['ram_mb']} MB. Zatrzymaj inną sesję.")
        taken = {s["rtc_port"] for s in sess.values()}
        port = next((p for p in range(RTC_PORT_MIN, RTC_PORT_MAX + 1) if p not in taken), None)
        if port is None:
            raise PoolFull("Brak wolnych portów WebRTC.")

        prof = dict(profile, rtc_port=port)
        ram = profile["ram_mb"]
        try:
            self.client.containers.run(
                IMAGE,
                name=container_name(pid),
                hostname=f"br-{pid}",
                detach=True,
                environment=build_env(prof, self.secret),
                labels={LABEL: "1", "vmbr.pid": pid, "vmbr.profile_id": str(profile["id"]),
                        "vmbr.ram_mb": str(ram), "vmbr.rtc_port": str(port)},
                network=NETWORK,
                mem_limit=f"{ram}m",
                memswap_limit=f"{ram}m",                 # bez swapa - przewidywalne zużycie
                mem_reservation=f"{max(MIN_SESSION_RAM_MB // 2, ram // 2)}m",
                nano_cpus=int(float(profile.get("cpus") or 1.0) * 1e9),
                shm_size="256m",
                pids_limit=1024,
                tmpfs={"/tmp": "size=192m,mode=1777"},
                ports={f"{port}/udp": port, f"{port}/tcp": port},
                volumes={
                    volume_name(pid): {"bind": "/home/neko/.config/chromium", "mode": "rw"},
                    EXT_VOLUME: {"bind": "/extensions", "mode": "ro"},
                },
                restart_policy={"Name": "unless-stopped"} if profile.get("background") else {"Name": "no"},
            )
        except ImageNotFound:
            raise BrowserError(f"Brak obrazu {IMAGE}. Zbuduj go: docker compose --profile build build")
        except APIError as exc:
            raise BrowserError(f"Nie udało się uruchomić sesji: {getattr(exc, 'explanation', None) or exc}")

    def _remove(self, pid):
        try:
            self.client.containers.get(container_name(pid)).remove(force=True)
        except NotFound:
            pass

    def stop(self, pid):
        """Zatrzymuje sesję (łagodnie, żeby Chromium zapisał karty i ciasteczka) i zwalnia RAM."""
        try:
            c = self.client.containers.get(container_name(pid))
        except NotFound:
            return
        try:
            c.update(restart_policy={"Name": "no"})
            c.stop(timeout=30)
        except APIError:
            pass
        self.kill_runners(pid)
        self._remove(pid)

    def delete_profile_data(self, pid):
        self.stop(pid)
        try:
            self.client.volumes.get(volume_name(pid)).remove(force=True)
        except NotFound:
            pass
        except APIError:
            pass

    # --- zasoby ---
    def stats(self, pid):
        try:
            c = self.client.containers.get(container_name(pid))
            st = c.stats(stream=False)
        except NotFound:
            return None
        mem = st.get("memory_stats", {})
        cache = (mem.get("stats") or {})
        used = mem.get("usage", 0) - cache.get("inactive_file", cache.get("cache", 0))
        cpu, pre = st.get("cpu_stats", {}), st.get("precpu_stats", {})
        cpu_d = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
        sys_d = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or [1])
        pct = (cpu_d / sys_d * ncpu * 100.0) if sys_d > 0 and cpu_d >= 0 else 0.0
        return {"mem_mb": round(used / 1048576, 1), "limit_mb": round(mem.get("limit", 0) / 1048576),
                "cpu_pct": round(pct, 1)}

    def viewers(self, pid):
        """Liczba aktywnych widzów (połączonych klientów neko); None gdy nie da się ustalić."""
        base = f"http://{container_name(pid)}:8080{PATH_PREFIX}/{pid}"
        try:
            s = requests.Session()
            r = s.post(f"{base}/api/login", timeout=3,
                       json={"username": "_probe", "password": session_password(self.secret, pid, "admin")})
            if r.status_code != 200:
                return None
            hdr = {}
            token = (r.json() or {}).get("token")
            if token:
                hdr["Authorization"] = f"Bearer {token}"
            lst = s.get(f"{base}/api/sessions", headers=hdr, timeout=3)
            n = None
            if lst.status_code == 200:
                n = sum(1 for x in lst.json() if x.get("state", {}).get("is_connected") and x.get("id") != "_probe"
                        and x.get("profile", {}).get("name") != "_probe")
            s.post(f"{base}/api/logout", headers=hdr, timeout=3)
            return n
        except (requests.RequestException, ValueError):
            return None

    # --- skrypty ---
    def _runners(self, pid=None, all_states=True):
        flt = [f"vmbr.runner=1"] + ([f"vmbr.pid={pid}"] if pid else [])
        return self.client.containers.list(all=all_states, filters={"label": flt})

    def run_script(self, pid, code, timeout):
        if not PID_RE.match(pid):
            raise BrowserError("Nieprawidłowy identyfikator sesji.")
        raw = code.encode("utf-8")
        if not raw.strip():
            raise BrowserError("Skrypt jest pusty.")
        if len(raw) > MAX_SCRIPT_BYTES:
            raise BrowserError(f"Skrypt jest za długi (maks. {MAX_SCRIPT_BYTES // 1024} KB).")
        if self.state_of(pid) != "running":
            raise BrowserError("Sesja nie jest uruchomiona.")
        timeout = max(5, min(int(timeout), MAX_RUN_SECONDS))
        for old in self._runners(pid):
            if old.status == "running":
                raise BrowserError("W tej sesji już działa skrypt. Zatrzymaj go lub poczekaj.")
            old.remove(force=True)
        try:
            c = self.client.containers.run(
                RUNNER_IMAGE,
                name=f"vmbr-run-{pid}-{int(time.time())}",
                detach=True,
                network_mode=f"container:{container_name(pid)}",
                environment={"BR_SCRIPT": base64.b64encode(raw).decode()},
                labels={"vmbr.runner": "1", "vmbr.pid": pid, "vmbr.deadline": str(int(time.time()) + timeout)},
                mem_limit="256m", memswap_limit="256m", pids_limit=128, nano_cpus=int(0.5e9),
                cap_drop=["ALL"], security_opt=["no-new-privileges"],
                read_only=True, tmpfs={"/tmp": "size=64m,mode=1777"}, user="1000",
            )
        except ImageNotFound:
            raise BrowserError(f"Brak obrazu {RUNNER_IMAGE}. Zbuduj go: docker compose --profile build build")
        except APIError as exc:
            raise BrowserError(f"Nie udało się uruchomić skryptu: {getattr(exc, 'explanation', None) or exc}")
        return {"run": c.name, "timeout": timeout}

    def script_status(self, pid):
        """Stan ostatniego skryptu sesji: {status, exit_code, log} albo None."""
        runners = sorted(self._runners(pid), key=lambda c: c.name)
        if not runners:
            return None
        c = runners[-1]
        c.reload()
        st = c.attrs.get("State", {})
        raw = c.logs(tail=1000, stdout=True, stderr=True) or b""
        log = raw[-MAX_LOG_BYTES:].decode("utf-8", "replace")
        status = "running" if st.get("Running") else "finished"
        return {"run": c.name, "status": status, "exit_code": st.get("ExitCode"), "log": log}

    def kill_runners(self, pid):
        for c in self._runners(pid):
            try:
                c.remove(force=True)
            except (APIError, NotFound):
                pass

    def stop_script(self, pid):
        self.kill_runners(pid)

    def sweep_runners(self, keep_finished_s=1800):
        """Ubija skrypty po terminie, sprząta stare zakończone kontenery."""
        now = time.time()
        for c in self._runners():
            try:
                deadline = int((c.labels or {}).get("vmbr.deadline", "0") or 0)
                if c.status == "running" and deadline and now > deadline:
                    c.remove(force=True)
                elif c.status != "running":
                    c.reload()
                    fin = _iso_to_epoch(c.attrs.get("State", {}).get("FinishedAt", ""))
                    if fin and now - fin > keep_finished_s:
                        c.remove(force=True)
            except (APIError, NotFound):
                continue
