"""Klient REST API Guacamole: tworzenie/usuwanie połączeń VNC i nadawanie uprawnień."""
import base64
import os
from urllib.parse import quote

import requests

INTERNAL_URL = os.environ.get("GUAC_INTERNAL_URL", "http://guacamole:8080/guacamole").rstrip("/")
ADMIN_USER = os.environ.get("GUAC_ADMIN_USER", "guacadmin")
ADMIN_PASSWORD = os.environ["GUAC_ADMIN_PASSWORD"]  # wymagane (.env)
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


def _ensure_user(ds, headers, username):
    """Zakłada konto w Guacamole, jeśli go nie ma (losowe hasło — wejście idzie
    przez nagłówek SSO z nginx, nie przez hasło). Błąd 'już istnieje' ignorujemy."""
    if username == ADMIN_USER:
        return
    r = requests.get(
        f"{INTERNAL_URL}/api/session/data/{ds}/users/{quote(username, safe='')}",
        headers=headers, timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return
    r = requests.post(
        f"{INTERNAL_URL}/api/session/data/{ds}/users",
        json={"username": username, "password": os.urandom(24).hex(), "attributes": {}},
        headers=headers, timeout=TIMEOUT,
    )
    if r.status_code not in (200, 201):
        raise GuacError(f"Nie udało się założyć użytkownika w Guacamole (HTTP {r.status_code}): {r.text[:200]}")


def sync_user(username, conn_ids=()):
    """Zapewnia konto użytkownika w Guacamole i nadaje mu READ do podanych połączeń
    (idempotentne). Konto admina portalu (guacadmin) już istnieje i widzi wszystko."""
    token, ds = _login()
    headers = {"Guacamole-Token": token}
    try:
        _ensure_user(ds, headers, username)
        ops = [
            {"op": "add", "path": f"/connectionPermissions/{cid}", "value": "READ"}
            for cid in conn_ids if cid
        ]
        if ops and username != ADMIN_USER:
            r = requests.patch(
                f"{INTERNAL_URL}/api/session/data/{ds}/users/{quote(username, safe='')}/permissions",
                json=ops, headers=headers, timeout=TIMEOUT,
            )
            if r.status_code not in (200, 204):
                raise GuacError(f"Nie nadano uprawnień w Guacamole (HTTP {r.status_code}): {r.text[:200]}")
    except requests.RequestException as exc:
        raise GuacError(f"Błąd komunikacji z Guacamole: {exc}") from exc
    finally:
        _logout(token)


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
                _ensure_user(ds, headers, user)
                requests.patch(
                    f"{INTERNAL_URL}/api/session/data/{ds}/users/{quote(user, safe='')}/permissions",
                    json=[{"op": "add", "path": f"/connectionPermissions/{conn_id}", "value": "READ"}],
                    headers=headers, timeout=TIMEOUT,
                )
            except (requests.RequestException, GuacError):
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
