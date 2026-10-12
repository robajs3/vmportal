"""Warstwa komunikacji z libvirt/KVM (przez socket hosta zamontowany w kontenerze)."""
import os
import re
import secrets
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


def _domain_xml(name, vcpus, ram_mb, disk_path, iso_path, os_type, port, vnc_password):
    windows = os_type == "windows"
    # Windows nie ma sterowników virtio na instalatorze -> SATA + e1000e
    disk_bus, disk_dev = ("sata", "sda") if windows else ("virtio", "vda")
    nic_model = "e1000e" if windows else "virtio"
    clock = "localtime" if windows else "utc"

    cdrom = ""
    if iso_path:
        cdrom = (
            "<disk type='file' device='cdrom'>"
            "<driver name='qemu' type='raw'/>"
            f"<source file='{escape(iso_path, {chr(39): '&apos;'})}'/>"
            "<target dev='sdb' bus='sata'/><readonly/><boot order='2'/>"
            "</disk>"
        )

    return f"""
<domain type='kvm'>
  <name>{escape(name)}</name>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu>{vcpus}</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
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
    <memballoon model='virtio'/>
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
