"""Klient REST API Guacamole: tworzenie/usuwanie połączeń VNC i nadawanie uprawnień."""
import base64
import os

import requests

INTERNAL_URL = os.environ.get("GUAC_INTERNAL_URL", "http://guacamole:8080/guacamole").rstrip("/")
ADMIN_USER = os.environ.get("GUAC_ADMIN_USER", "guacadmin")
ADMIN_PASSWORD = os.environ.get("GUAC_ADMIN_PASSWORD", "")
PUBLIC_URL = os.environ.get("GUACAMOLE_PUBLIC_URL", "/guacamole/")
TIMEOUT = 10


class GuacError(Exception):
    pass


def _login():
    try:
        r = requests.post(
            f"{INTERNAL_URL}/api/tokens",
            data={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GuacError(f"Brak połączenia z Guacamole: {exc}") from exc
    if r.status_code != 200:
        raise GuacError(
            f"Logowanie do Guacamole nie powiodło się (HTTP {r.status_code}). "
            "Sprawdź GUAC_ADMIN_USER i GUAC_ADMIN_PASSWORD."
        )
    data = r.json()
    return data["authToken"], data.get("dataSource") or "postgresql"


def _logout(token):
    try:
        requests.delete(f"{INTERNAL_URL}/api/tokens/{token}", timeout=TIMEOUT)
    except requests.RequestException:
        pass


def create_connection(name, hostname, port, vnc_password, grant_users=()):
    """Tworzy połączenie VNC. Zwraca identyfikator połączenia (str)."""
    token, ds = _login()
    headers = {"Guacamole-Token": token}
    try:
        body = {
            "parentIdentifier": "ROOT",
            "name": name,
            "protocol": "vnc",
            "parameters": {
                "hostname": hostname,
                "port": str(port),
                "password": vnc_password,
                "clipboard-encoding": "UTF-8",
            },
            "attributes": {},
        }
        r = requests.post(
            f"{INTERNAL_URL}/api/session/data/{ds}/connections",
            json=body, headers=headers, timeout=TIMEOUT,
        )
        if r.status_code not in (200, 201):
            raise GuacError(f"Guacamole odrzuciło utworzenie połączenia (HTTP {r.status_code}): {r.text[:200]}")
        conn_id = str(r.json()["identifier"])

        # Uprawnienia: błędy ignorujemy (np. użytkownik o takiej nazwie nie istnieje w Guacamole)
        for user in {u for u in grant_users if u}:
            try:
                requests.patch(
                    f"{INTERNAL_URL}/api/session/data/{ds}/users/{user}/permissions",
                    json=[{"op": "add", "path": f"/connectionPermissions/{conn_id}", "value": "READ"}],
                    headers=headers, timeout=TIMEOUT,
                )
            except requests.RequestException:
                pass
        return conn_id
    except requests.RequestException as exc:
        raise GuacError(f"Błąd komunikacji z Guacamole: {exc}") from exc
    finally:
        _logout(token)


def delete_connection(conn_id):
    token, ds = _login()
    try:
        requests.delete(
            f"{INTERNAL_URL}/api/session/data/{ds}/connections/{conn_id}",
            headers={"Guacamole-Token": token}, timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GuacError(f"Błąd komunikacji z Guacamole: {exc}") from exc
    finally:
        _logout(token)


def client_url(conn_id, data_source="postgresql"):
    """Bezpośredni link do konsoli danego połączenia."""
    raw = f"{conn_id}\0c\0{data_source}".encode()
    ident = base64.b64encode(raw).decode().rstrip("=")
    base = PUBLIC_URL if PUBLIC_URL.endswith("/") else PUBLIC_URL + "/"
    return f"{base}#/client/{ident}"
