"""Warstwa komunikacji z libvirt/KVM (przez socket hosta zamontowany w kontenerze)."""
import os
import re
import secrets
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from xml.sax.saxutils import escape

import libvirt

URI = os.environ.get("LIBVIRT_URI", "qemu:///system")
IMAGES_POOL = os.environ.get("LIBVIRT_IMAGES_POOL", "images")
ISO_POOL = os.environ.get("LIBVIRT_ISO_POOL", "iso")
NETWORK = os.environ.get("LIBVIRT_NETWORK", "default")
VNC_LISTEN = os.environ.get("VNC_LISTEN", "0.0.0.0")
VNC_PORT_MIN = int(os.environ.get("VNC_PORT_MIN", "5910"))
VNC_PORT_MAX = int(os.environ.get("VNC_PORT_MAX", "5999"))

# nazwa: male litery, cyfry, myslnik; 3-32 znaki
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")

STATE_NAMES = {
    0: "unknown", 1: "running", 2: "running", 3: "paused",
    4: "shutting-down", 5: "stopped", 6: "crashed", 7: "suspended",
}


class LibvirtError(Exception):
    pass


@contextmanager
def connection():
    try:
        conn = libvirt.open(URI)
    except libvirt.libvirtError as exc:
        raise LibvirtError(f"Nie można połączyć się z libvirt: {exc}") from exc
    if conn is None:
        raise LibvirtError("Nie można połączyć się z libvirt.")
    try:
        yield conn
    except libvirt.libvirtError as exc:
        raise LibvirtError(str(exc)) from exc
    finally:
        conn.close()


def domain_states():
    """Zwraca {nazwa_vm: stan}."""
    with connection() as conn:
        return {d.name(): STATE_NAMES.get(d.state()[0], "unknown") for d in conn.listAllDomains(0)}


def list_isos():
    """Zwraca posortowaną listę nazw plików ISO z puli ISO_POOL."""
    with connection() as conn:
        try:
            pool = conn.storagePoolLookupByName(ISO_POOL)
            pool.refresh(0)
            return sorted(v.name() for v in pool.listAllVolumes(0) if v.name().lower().endswith(".iso"))
        except libvirt.libvirtError:
            return []


# sygnatura w obrazie ISO: "CD001" (ISO 9660) lub "BEA01" (czysty UDF) pod offsetem 0x8001
_ISO_SIG_OFFSET = 0x8001
_ISO_SIGNATURES = (b"CD001", b"BEA01")


def _read_fill(src, n):
    """Czyta dokładnie n bajtów (lub mniej, jeśli strumień się skończy)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = src.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


class _HeadThenStream:
    """Oddaje najpierw już przeczytany początek pliku, potem resztę strumienia
    i zlicza, ile bajtów poszło do libvirt."""

    def __init__(self, head, rest):
        self.head = head
        self.rest = rest
        self.sent = 0

    def read(self, n):
        if self.head:
            out, self.head = self.head[:n], self.head[n:]
        else:
            out = _read_fill(self.rest, n)
        self.sent += len(out)
        return out


def upload_iso(name, src, size):
    """Wgrywa obraz ISO do puli ISO_POOL, strumieniując go prosto z `src` (obiekt z .read())
    przez protokół libvirt - kontener nie potrzebuje dostępu do katalogu z ISO.
    `size` to dokładny rozmiar pliku w bajtach (Content-Length)."""
    if not name.lower().endswith(".iso"):
        raise LibvirtError("Plik musi mieć rozszerzenie .iso.")

    # szybka walidacja zawartości, zanim cokolwiek utworzymy w puli
    head = _read_fill(src, min(size, 64 * 1024))
    sig = head[_ISO_SIG_OFFSET:_ISO_SIG_OFFSET + 5]
    if sig not in _ISO_SIGNATURES:
        raise LibvirtError("Ten plik nie wygląda na obraz ISO (brak sygnatury ISO 9660/UDF).")

    with connection() as conn:
        try:
            pool = conn.storagePoolLookupByName(ISO_POOL)
        except libvirt.libvirtError as exc:
            raise LibvirtError(f"Brak puli ISO „{ISO_POOL}”: {exc}") from exc
        if not pool.isActive():
            raise LibvirtError(f"Pula ISO „{ISO_POOL}” jest nieaktywna.")
        pool.refresh(0)

        if name in {v.name() for v in pool.listAllVolumes(0)}:
            raise LibvirtError(
                f"Plik „{name}” już istnieje w puli ISO - wybierz go z listy albo zmień nazwę pliku."
            )
        available = pool.info()[3]
        if size > available:
            raise LibvirtError(
                f"Za mało miejsca w puli ISO (wolne {available // 1048576} MB, plik ma {size // 1048576} MB)."
            )

        vol = pool.createXML(
            f"<volume><name>{escape(name)}</name>"
            f"<capacity unit='bytes'>{int(size)}</capacity>"
            "<target><format type='raw'/></target></volume>",
            0,
        )
        reader = _HeadThenStream(head, src)
        stream = conn.newStream(0)
        try:
            vol.upload(stream, 0, size, 0)
            stream.sendAll(lambda _st, nbytes, _op: reader.read(nbytes), None)
            stream.finish()
            if reader.sent != size:
                raise LibvirtError("Przesyłanie zostało przerwane - plik jest niekompletny.")
        except Exception:
            # nie zostawiamy w puli uciętych plików
            try:
                stream.abort()
            except libvirt.libvirtError:
                pass
            try:
                vol.delete(0)
            except libvirt.libvirtError:
                pass
            raise
        pool.refresh(0)


def vm_resources(name):
    """Przydział zasobów maszyny + (dla działającej) bieżące zużycie.
    Dane czytane na żywo z libvirt, więc działa też dla maszyn dodanych ręcznie."""
    with connection() as conn:
        dom = conn.lookupByName(name)
        state, max_kib, cur_kib, vcpus, cpu_ns = dom.info()
        active = bool(dom.isActive())

        data = {
            "state": STATE_NAMES.get(state, "unknown"),
            "vcpus": vcpus,
            "ram_max_mb": max_kib // 1024,
            "ram_current_mb": cur_kib // 1024,
            "ram_used_mb": None,       # zajęte w systemie gościa (wymaga virtio-balloon)
            "ram_host_rss_mb": None,   # ile pamięci hosta faktycznie zajmuje proces QEMU
            "cpu_time_ns": cpu_ns,
            "sampled_at": time.time(),
            "disks": [],
        }

        if active:
            try:
                st = dom.memoryStats()
                avail = st.get("available")
                free = st.get("usable", st.get("unused"))
                if avail and free is not None:
                    data["ram_used_mb"] = max(avail - free, 0) // 1024
                if st.get("rss"):
                    data["ram_host_rss_mb"] = st["rss"] // 1024
            except libvirt.libvirtError:
                pass

        root = ET.fromstring(dom.XMLDesc(0))
        for disk in root.findall("./devices/disk[@device='disk']"):
            target = disk.find("target")
            source = disk.find("source")
            if target is None or source is None:
                continue
            dev = target.get("dev")
            path = source.get("file") or source.get("dev")
            if not dev or not path:
                continue
            try:
                capacity, _allocation, physical = dom.blockInfo(path, 0)
            except libvirt.libvirtError:
                continue
            data["disks"].append({"dev": dev, "capacity": capacity, "physical": physical})
        return data


GIB = 1024 ** 3


def _primary_disk_path(dom):
    root = ET.fromstring(dom.XMLDesc(0))
    for src in root.findall("./devices/disk[@device='disk']/source"):
        path = src.get("file") or src.get("dev")
        if path:
            return path
    return None


def update_vm_resources(name, vcpus=None, ram_mb=None, disk_gb=None):
    """Zmienia przydział zasobów WYŁĄCZONEJ maszyny (konfiguracja trwała).
    None = bez zmiany. Dysk można tylko powiększyć (pierwszy dysk maszyny)."""
    with connection() as conn:
        dom = conn.lookupByName(name)
        if dom.isActive():
            raise LibvirtError("Zasoby można zmieniać tylko przy wyłączonej maszynie.")

        # walidacja dysku przed jakąkolwiek zmianą (resize jest nieodwracalny)
        vol = None
        if disk_gb is not None:
            path = _primary_disk_path(dom)
            if not path:
                raise LibvirtError("Nie znaleziono dysku maszyny.")
            try:
                vol = conn.storageVolLookupByPath(path)
            except libvirt.libvirtError as exc:
                raise LibvirtError(
                    "Dysk tej maszyny nie należy do żadnej puli libvirt - nie można go powiększyć z portalu."
                ) from exc
            current_gb = -(-vol.info()[1] // GIB)  # w górę
            if disk_gb < current_gb:
                raise LibvirtError(f"Dysku nie można zmniejszyć (obecnie {current_gb} GB), tylko powiększyć.")
            if disk_gb == current_gb:
                vol = None

        cfg = libvirt.VIR_DOMAIN_AFFECT_CONFIG

        if ram_mb is not None:
            kib = int(ram_mb) * 1024
            if kib >= dom.maxMemory():
                dom.setMemoryFlags(kib, cfg | libvirt.VIR_DOMAIN_MEM_MAXIMUM)  # najpierw limit...
                dom.setMemoryFlags(kib, cfg)                                    # ...potem bieżąca
            else:
                dom.setMemoryFlags(kib, cfg)
                dom.setMemoryFlags(kib, cfg | libvirt.VIR_DOMAIN_MEM_MAXIMUM)

        if vcpus is not None:
            vcpus = int(vcpus)
            if vcpus >= dom.info()[3]:
                dom.setVcpusFlags(vcpus, cfg | libvirt.VIR_DOMAIN_VCPU_MAXIMUM)
                dom.setVcpusFlags(vcpus, cfg)
            else:
                dom.setVcpusFlags(vcpus, cfg)
                dom.setVcpusFlags(vcpus, cfg | libvirt.VIR_DOMAIN_VCPU_MAXIMUM)

        if vol is not None:
            vol.resize(int(disk_gb) * GIB, 0)


def _used_vnc_ports(conn):
    ports = set()
    for dom in conn.listAllDomains(0):
        root = ET.fromstring(dom.XMLDesc(0))
        for g in root.findall("./devices/graphics"):
            try:
                port = int(g.get("port", "-1"))
            except ValueError:
                continue
            if port > 0:
                ports.add(port)
    return ports


def _pick_vnc_port(conn, reserved):
    used = _used_vnc_ports(conn) | set(reserved)
    for port in range(VNC_PORT_MIN, VNC_PORT_MAX + 1):
        if port not in used:
            return port
    raise LibvirtError("Brak wolnych portów VNC w skonfigurowanym zakresie.")


# Profile sprzętowe wybierane w formularzu tworzenia maszyny.
OS_PROFILES = {
    "linux": dict(machine="q35", disk_bus="virtio", disk_dev="vda", cdrom_bus="sata", cdrom_dev="sdb",
                  nic="virtio", clock="utc", balloon="virtio"),
    # Windows nie ma sterowników virtio na instalatorze -> SATA + e1000e
    "windows": dict(machine="q35", disk_bus="sata", disk_dev="sda", cdrom_bus="sata", cdrom_dev="sdb",
                    nic="e1000e", clock="localtime", balloon="virtio"),
    # Starsze Windowsy (XP, 2000, 2003, często 7 bez sterowników): płyta i440fx ("pc"), bo q35 nie ma
    # magistrali IDE; dysk i CD-ROM na IDE, karta rtl8139 (sterownik jest w systemie), bez balloona.
    "windows_legacy": dict(machine="pc", disk_bus="ide", disk_dev="hda", cdrom_bus="ide", cdrom_dev="hdc",
                           nic="rtl8139", clock="localtime", balloon="none"),
}


def _domain_xml(name, vcpus, ram_mb, disk_path, iso_path, os_type, port, vnc_password):
    prof = OS_PROFILES[os_type]
    disk_bus, disk_dev = prof["disk_bus"], prof["disk_dev"]
    nic_model, clock = prof["nic"], prof["clock"]

    cdrom = ""
    if iso_path:
        cdrom = (
            "<disk type='file' device='cdrom'>"
            "<driver name='qemu' type='raw'/>"
            f"<source file='{escape(iso_path, {chr(39): '&apos;'})}'/>"
            f"<target dev='{prof['cdrom_dev']}' bus='{prof['cdrom_bus']}'/><readonly/><boot order='2'/>"
            "</disk>"
        )

    return f"""
<domain type='kvm'>
  <name>{escape(name)}</name>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu>{vcpus}</vcpu>
  <os><type arch='x86_64' machine='{prof['machine']}'>hvm</type></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-passthrough'/>
  <clock offset='{clock}'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{escape(disk_path, {chr(39): '&apos;'})}'/>
      <target dev='{disk_dev}' bus='{disk_bus}'/>
      <boot order='1'/>
    </disk>
    {cdrom}
    <interface type='network'>
      <source network='{escape(NETWORK)}'/>
      <model type='{nic_model}'/>
    </interface>
    <graphics type='vnc' port='{port}' autoport='no' passwd='{vnc_password}'>
      <listen type='address' address='{VNC_LISTEN}'/>
    </graphics>
    <video><model type='vga' vram='16384'/></video>
    <input type='tablet' bus='usb'/>
    <memballoon model='{prof['balloon']}'/>
  </devices>
</domain>
"""


def create_vm(name, vcpus, ram_mb, disk_gb, os_type, iso_name, reserved_ports=()):
    """Tworzy dysk qcow2 + domenę, uruchamia VM. Zwraca dict z danymi do Guacamole."""
    if not NAME_RE.match(name):
        raise LibvirtError("Nieprawidłowa nazwa maszyny.")

    with connection() as conn:
        if name in {d.name() for d in conn.listAllDomains(0)}:
            raise LibvirtError("Maszyna o takiej nazwie już istnieje w libvirt.")

        iso_path = None
        if iso_name:
            pool_iso = conn.storagePoolLookupByName(ISO_POOL)
            pool_iso.refresh(0)
            volumes = {v.name(): v.path() for v in pool_iso.listAllVolumes(0)}
            if iso_name not in volumes:
                raise LibvirtError("Wybrany obraz ISO nie istnieje.")
            iso_path = volumes[iso_name]

        pool = conn.storagePoolLookupByName(IMAGES_POOL)
        vol_xml = (
            f"<volume><name>{escape(name)}.qcow2</name>"
            f"<capacity unit='GiB'>{int(disk_gb)}</capacity>"
            "<target><format type='qcow2'/></target></volume>"
        )
        vol = pool.createXML(vol_xml, 0)
        dom = None
        try:
            port = _pick_vnc_port(conn, reserved_ports)
            vnc_password = secrets.token_hex(4)  # VNC: max 8 znaków
            xml = _domain_xml(name, int(vcpus), int(ram_mb), vol.path(), iso_path, os_type, port, vnc_password)
            dom = conn.defineXML(xml)
            dom.create()
        except Exception:
            try:
                if dom is not None:
                    if dom.isActive():
                        dom.destroy()
                    dom.undefine()
            finally:
                vol.delete(0)
            raise

        return {"name": name, "vnc_port": port, "vnc_password": vnc_password}


def clone_vm(source_name, new_name, reserved_ports=()):
    """Klonuje WYŁĄCZONĄ maszynę: pełna kopia dysków (do puli IMAGES_POOL) + nowa domena
    z nowym UUID, nowymi adresami MAC oraz nowym portem i hasłem VNC.
    Operacja jest synchroniczna - przy dużych dyskach trwa minuty.
    Zwraca dict z danymi do Guacamole i do zapisu w bazie portalu."""
    if not NAME_RE.match(new_name):
        raise LibvirtError("Nieprawidłowa nazwa maszyny.")

    with connection() as conn:
        if new_name in {d.name() for d in conn.listAllDomains(0)}:
            raise LibvirtError("Maszyna o takiej nazwie już istnieje w libvirt.")
        try:
            src = conn.lookupByName(source_name)
        except libvirt.libvirtError as exc:
            raise LibvirtError(f"Maszyna źródłowa „{source_name}” nie istnieje w libvirt.") from exc
        if src.isActive():
            raise LibvirtError("Klonować można tylko wyłączoną maszynę - zamknij ją i spróbuj ponownie.")

        _state, max_kib, _cur_kib, vcpus, _cpu_ns = src.info()
        root = ET.fromstring(src.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE))

        # --- walidacja przed jakąkolwiek zmianą ---------------------------------
        graphics = next((g for g in root.findall("./devices/graphics") if g.get("type") == "vnc"), None)
        if graphics is None:
            raise LibvirtError("Maszyna nie ma konsoli VNC - nie da się jej podpiąć do Guacamole.")

        os_el = root.find("os")
        nvram = os_el.find("nvram") if os_el is not None else None
        if nvram is not None:
            if os_el.get("firmware"):
                os_el.remove(nvram)  # firmware='efi': libvirt sam utworzy nowy NVRAM
            else:
                raise LibvirtError("Klonowanie maszyn UEFI z ręcznie podpiętym NVRAM nie jest obsługiwane.")

        disks = []
        for disk in root.findall("./devices/disk[@device='disk']"):
            source = disk.find("source")
            path = source.get("file") if source is not None else None
            if not path:
                raise LibvirtError("Klonowanie obsługuje tylko dyski plikowe (maszyna ma inny typ dysku).")
            try:
                svol = conn.storageVolLookupByPath(path)
            except libvirt.libvirtError as exc:
                raise LibvirtError(
                    f"Dysk „{path}” nie należy do żadnej puli libvirt - nie można go sklonować z portalu."
                ) from exc
            disks.append((disk, source, svol))
        if not disks:
            raise LibvirtError("Maszyna nie ma żadnego dysku do sklonowania.")

        pool = conn.storagePoolLookupByName(IMAGES_POOL)
        if not pool.isActive():
            raise LibvirtError(f"Pula obrazów „{IMAGES_POOL}” jest nieaktywna.")
        pool.refresh(0)
        needed = sum(svol.info()[2] for _d, _s, svol in disks)  # faktycznie zajęte bajty
        available = pool.info()[3]
        if needed > available:
            raise LibvirtError(
                f"Za mało miejsca w puli „{IMAGES_POOL}” (wolne {available // 1048576} MB, "
                f"kopia dysków potrzebuje ok. {needed // 1048576} MB)."
            )

        # --- kopiowanie dysków --------------------------------------------------
        created = []
        dom = None
        try:
            for i, (disk, source, svol) in enumerate(disks):
                vol_name = f"{new_name}.qcow2" if i == 0 else f"{new_name}-{i}.qcow2"
                capacity = svol.info()[1]
                vol_xml = (
                    f"<volume><name>{escape(vol_name)}</name>"
                    f"<capacity unit='bytes'>{int(capacity)}</capacity>"
                    "<target><format type='qcow2'/></target></volume>"
                )
                new_vol = pool.createXMLFrom(vol_xml, svol, 0)
                created.append(new_vol)

                source.set("file", new_vol.path())
                driver = disk.find("driver")
                if driver is None:
                    driver = ET.SubElement(disk, "driver", name="qemu")
                driver.set("type", "qcow2")
                for bs in disk.findall("backingStore"):
                    disk.remove(bs)

            # --- nowa tożsamość domeny -----------------------------------------
            root.find("name").text = new_name
            for el in root.findall("uuid"):
                root.remove(el)  # nowy UUID nada libvirt
            for iface in root.findall("./devices/interface"):
                for mac in iface.findall("mac"):
                    iface.remove(mac)
            for sec in root.findall("seclabel"):
                root.remove(sec)  # etykiety AppArmor/SELinux przypisze libvirt od nowa

            # port wybieramy dopiero teraz - kopiowanie trwa, a w międzyczasie ktoś mógł zająć port
            port = _pick_vnc_port(conn, reserved_ports)
            vnc_password = secrets.token_hex(4)  # VNC: max 8 znaków
            graphics.set("port", str(port))
            graphics.set("autoport", "no")
            graphics.set("passwd", vnc_password)

            dom = conn.defineXML(ET.tostring(root, encoding="unicode"))
        except Exception:
            try:
                if dom is not None:
                    dom.undefine()
            finally:
                for v in created:
                    try:
                        v.delete(0)
                    except libvirt.libvirtError:
                        pass
            raise

        disk_gb = -(-created[0].info()[1] // GIB)  # pierwszy dysk, w górę
        return {
            "name": new_name,
            "vnc_port": port,
            "vnc_password": vnc_password,
            "vcpus": vcpus,
            "ram_mb": max_kib // 1024,
            "disk_gb": disk_gb,
        }


def power(name, action):
    with connection() as conn:
        dom = conn.lookupByName(name)
        if action == "start":
            if not dom.isActive():
                dom.create()
        elif action == "shutdown":
            dom.shutdown()
        elif action == "reboot":
            dom.reboot(0)
        elif action == "destroy":
            dom.destroy()
        else:
            raise LibvirtError("Nieznana akcja.")


def delete_vm(name):
    """Zatrzymuje, usuwa definicję i dyski (tylko z puli IMAGES_POOL)."""
    with connection() as conn:
        try:
            dom = conn.lookupByName(name)
        except libvirt.libvirtError:
            return  # już nie istnieje

        root = ET.fromstring(dom.XMLDesc(0))
        disk_paths = [
            s.get("file") for s in root.findall("./devices/disk[@device='disk']/source") if s.get("file")
        ]

        if dom.isActive():
            dom.destroy()
        try:
            dom.undefineFlags(
                libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
                | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
                | libvirt.VIR_DOMAIN_UNDEFINE_NVRAM
            )
        except libvirt.libvirtError:
            dom.undefine()

        for path in disk_paths:
            try:
                vol = conn.storageVolLookupByPath(path)
                if vol.storagePoolLookupByVolume().name() == IMAGES_POOL:
                    vol.delete(0)
            except libvirt.libvirtError:
                pass
