"""
sso_client.py — wspólny moduł SSO dla appek podpiętych pod LoginHub.

Skopiuj ten plik do katalogu głównego appki (obok app.py/config.py) i wywołaj
`resolve_local_user_id(app_slug=...)` na początku obsługi żądania (np. w
`@app.before_request`), żeby sprawdzić, czy przeglądarka ma ważne ciasteczko
LoginHub i, jeśli tak, jaki ma dla NIEJ lokalny user_id.

WYMAGA: `pip install requests itsdangerous` (itsdangerous i tak zwykle jest
już zainstalowane jako zależność Flaska/Flask-Login).

Appka NIC nie musi wiedzieć o hashach haseł ani o bazie LoginHub — cała logika
uwierzytelniania zostaje po stronie LoginHub, appka tylko pyta "czy znasz tego
człowieka i jaki ma tu numer".
"""
import os

import requests
from flask import request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

_SALT = "sso-hub-v1"  # MUSI być identyczna wartość co w LoginHub — nie zmieniaj


def _verify_cookie(sso_secret: str, token: str, max_age_seconds: int):
    s = URLSafeTimedSerializer(sso_secret, salt=_SALT)
    try:
        return s.loads(token, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


def resolve_local_user_id(
    app_slug: str,
    cookie_name: str = None,
    sso_secret: str = None,
    hub_internal_url: str = None,
    max_age_days: int = None,
):
    """Zwraca lokalny user_id (int) jeśli przeglądarka ma ważne ciasteczko LoginHub
    ORAZ to konto jest połączone z tą appką w panelu admina. W przeciwnym razie None.

    Wszystkie parametry opcjonalne — domyślnie czytane ze zmiennych środowiskowych:
      SSO_COOKIE_NAME (domyślnie "sso_session")
      SSO_SECRET (WYMAGANE — ten sam string co w .env LoginHub)
      HUB_INTERNAL_URL (domyślnie "http://127.0.0.1:8011" — dla appek systemd;
                         appki dockerowe podłączone do sso_net powinny ustawić
                         "http://hub-web:8000")
      SSO_SESSION_DAYS (domyślnie 30 — musi się zgadzać z LoginHub, inaczej appka
                         mogłaby odrzucać ciasteczko wcześniej/później niż LoginHub)
    """
    cookie_name = cookie_name or os.environ.get("SSO_COOKIE_NAME", "sso_session")
    sso_secret = sso_secret or os.environ.get("SSO_SECRET")
    hub_internal_url = (hub_internal_url or os.environ.get("HUB_INTERNAL_URL", "http://127.0.0.1:8011")).rstrip("/")
    max_age_days = max_age_days or int(os.environ.get("SSO_SESSION_DAYS", "30"))

    if not sso_secret:
        return None  # SSO nieskonfigurowane w tej appce — nie wybuchaj, po prostu nie loguj przez SSO

    token = request.cookies.get(cookie_name)
    if not token:
        return None

    data = _verify_cookie(sso_secret, token, max_age_days * 86400)
    if not data:
        return None

    try:
        resp = requests.get(
            f"{hub_internal_url}/api/resolve",
            params={"app_slug": app_slug, "hub_user_id": data["hub_user_id"]},
            headers={"X-SSO-Api-Key": sso_secret},
            timeout=3,
        )
    except requests.RequestException:
        return None  # LoginHub niedostępny — appka po prostu nie zaloguje przez SSO w tym requeście

    if resp.status_code != 200:
        return None

    payload = resp.json()
    if not payload.get("linked"):
        return None

    return payload["local_user_id"]


def resolve_or_create_local_user(
    app_slug: str,
    create_user,
    cookie_name: str = None,
    sso_secret: str = None,
    hub_internal_url: str = None,
    max_age_days: int = None,
):
    """Jak `resolve_local_user_id`, ale gdy konto z Huba NIE jest jeszcze podłączone
    do tej appki, zamiast zwrócić None od razu automatycznie zakłada tu dla niego
    nowe lokalne konto i zgłasza połączenie do LoginHub — użytkownik nie musi czekać,
    aż admin ręcznie sparuje konta w panelu /admin.

    `create_user` to funkcja appki (Ty ją piszesz, bo tylko appka zna swój model
    User i schemat hasła):

        def create_user(hub_username: str) -> tuple[int, str | None]:
            # 1) załóż nowego usera swoim zwykłym mechanizmem (swoje ORM, swój
            #    hash hasła), z hasłem losowym/nieużywalnym — logowanie i tak
            #    zawsze będzie szło przez SSO;
            # 2) jeśli hub_username koliduje z istniejącym userem lokalnym,
            #    rozwiąż to po swojemu (np. dopisz sufiks);
            # 3) zwróć (nowy_local_user_id, local_username_do_wyswietlenia_w_hubie).

    WAŻNE — idempotencja: jeśli zgłoszenie do Huba (/api/link) nie dojdzie (Hub
    akurat niedostępny), przy KOLEJNYM requeście appka znów nie zobaczy linku i
    `create_user` zostanie wywołane ponownie. Żeby uniknąć duplikatów, warto, żeby
    `create_user` najpierw sprawdzał, czy lokalne konto o takim (deterministycznie
    wyprowadzonym z hub_username) identyfikatorze już istnieje, i wtedy zwracał je
    zamiast tworzyć nowe (czyli "get-or-create", nie "create").

    Zwraca local_user_id (int) albo None — przy None appka po prostu pokazuje swój
    normalny /login, nic się nie psuje.
    """
    cookie_name = cookie_name or os.environ.get("SSO_COOKIE_NAME", "sso_session")
    sso_secret = sso_secret or os.environ.get("SSO_SECRET")
    hub_internal_url = (hub_internal_url or os.environ.get("HUB_INTERNAL_URL", "http://127.0.0.1:8011")).rstrip("/")
    max_age_days = max_age_days or int(os.environ.get("SSO_SESSION_DAYS", "30"))

    if not sso_secret:
        return None

    token = request.cookies.get(cookie_name)
    if not token:
        return None

    data = _verify_cookie(sso_secret, token, max_age_days * 86400)
    if not data:
        return None

    hub_user_id = data["hub_user_id"]

    try:
        resp = requests.get(
            f"{hub_internal_url}/api/resolve",
            params={"app_slug": app_slug, "hub_user_id": hub_user_id},
            headers={"X-SSO-Api-Key": sso_secret},
            timeout=3,
        )
    except requests.RequestException:
        return None  # Hub niedostępny — nie zgadujemy, zwykły /login jako plan B

    if resp.status_code == 200:
        payload = resp.json()
        if payload.get("linked"):
            return payload["local_user_id"]
    elif resp.status_code != 404:
        return None  # nieoczekiwana odpowiedź Huba

    # brak połączenia -> appka sama zakłada tu konto dla tego usera z Huba
    try:
        local_user_id, local_username = create_user(data["username"])
    except Exception:
        return None  # appka nie potrafiła założyć konta — zwykły /login jako plan B

    try:
        requests.post(
            f"{hub_internal_url}/api/link",
            json={
                "app_slug": app_slug,
                "hub_user_id": hub_user_id,
                "local_user_id": local_user_id,
                "local_username": local_username,
            },
            headers={"X-SSO-Api-Key": sso_secret},
            timeout=3,
        )
    except requests.RequestException:
        pass  # appka i tak ma już lokalne konto i zaloguje usera w tym requeście;
        # Hub po prostu nie będzie o nim jeszcze wiedział do następnej udanej próby

    return local_user_id


def login_url(next_path: str, hub_public_prefix: str = "/auth") -> str:
    """Buduje adres logowania w LoginHub z powrotem-linkiem do bieżącej appki."""
    from urllib.parse import quote
    return f"{hub_public_prefix}/login?next={quote(next_path)}"


def clear_sso_cookie(response, cookie_name: str = None):
    """Wywołaj w route'ach /logout appek, żeby wylogowanie było globalne (ze
    wszystkich appek naraz), a nie tylko lokalne — inaczej _sso_autologin
    zaloguje z powrotem przy następnym żądaniu, bo ciasteczko wciąż ważne.

    Użycie:
        response = make_response(redirect(url_for("auth.login")))
        sso_client.clear_sso_cookie(response)
        return response
    """
    cookie_name = cookie_name or os.environ.get("SSO_COOKIE_NAME", "sso_session")
    response.delete_cookie(cookie_name, path="/")
    return response
