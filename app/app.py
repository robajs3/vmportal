import os
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, abort, make_response, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_bcrypt import Bcrypt
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.utils import secure_filename

import guac
import libvirt_manager as lv
import sso_client


class PrefixMiddleware:
    def __init__(self, wsgi_app, prefix_env_var="HTTP_X_SCRIPT_NAME"):
        self.wsgi_app = wsgi_app
        self.prefix_env_var = prefix_env_var

    def __call__(self, environ, start_response):
        script_name = environ.get(self.prefix_env_var, "")
        if script_name:
            environ["SCRIPT_NAME"] = script_name
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith(script_name):
                environ["PATH_INFO"] = path_info[len(script_name):]
        return self.wsgi_app(environ, start_response)


app = Flask(__name__)
app.wsgi_app = PrefixMiddleware(app.wsgi_app)


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Brak wymaganej zmiennej środowiskowej {name} (ustaw ją w .env).")
    return value


def _database_uri():
    """DATABASE_URL, jeśli ustawione; w przeciwnym razie składane z DB_* (hasło jest
    poprawnie cytowane, więc może zawierać znaki specjalne)."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return URL.create(
        "postgresql+psycopg2",
        username=_require_env("DB_USER"),
        password=_require_env("DB_PASSWORD"),
        host=os.environ.get("DB_HOST", "postgres"),
        port=int(os.environ.get("DB_PORT", "5432")),
        database=_require_env("DB_NAME"),
    ).render_as_string(hide_password=False)


app.config["SECRET_KEY"] = _require_env("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = _database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_PATH"] = "/"
# Własne nazwy ciasteczek: appki na tym samym hoście (np. Koloseum) używają domyślnego
# "session" z Path=/ i nadpisywałyby sobie nawzajem sesje (różne SECRET_KEY).
app.config["SESSION_COOKIE_NAME"] = "vmportal_session"
app.config["REMEMBER_COOKIE_NAME"] = "vmportal_remember"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Limity zasobów dla jednej maszyny / jednego użytkownika (zmienne środowiskowe)
LIMITS = {
    "vcpus": int(os.environ.get("MAX_VCPUS", "4")),
    "ram_mb": int(os.environ.get("MAX_RAM_MB", "8192")),
    "disk_gb": int(os.environ.get("MAX_DISK_GB", "100")),
    "vms_per_user": int(os.environ.get("MAX_VMS_PER_USER", "5")),
    "iso_mb": int(os.environ.get("MAX_ISO_MB", "10240")),  # maks. rozmiar wgrywanego ISO
}
MIN_RAM_MB = 512
MIN_DISK_GB = 5

# Adres, pod którym guacd (kontener) widzi serwer VNC hosta
VM_HOST = os.environ.get("VM_HOST", "host.docker.internal")
GUAC_GRANT_USERS = [u.strip() for u in os.environ.get("GUAC_GRANT_USERS", "").split(",") if u.strip()]

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # Czy konto ma dostęp do portalu. Nowe konta (w tym zakładane przez SSO) startują
    # jako FALSE, dopóki admin ich nie zatwierdzi w /admin. Admin (ADMIN_USERNAME)
    # ma dostęp zawsze, niezależnie od tej flagi.
    is_allowed = db.Column(db.Boolean, nullable=False, default=False, server_default="false")

    def set_password(self, raw_password):
        self.password_hash = bcrypt.generate_password_hash(raw_password).decode("utf-8")

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password_hash, raw_password)


class VMInstance(db.Model):
    __tablename__ = "vm_instances"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    guacamole_url = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # --- nowe kolumny (dodawane migracją przy starcie) ---
    owner_id = db.Column(db.Integer)
    libvirt_name = db.Column(db.String(100))
    vcpus = db.Column(db.Integer)
    ram_mb = db.Column(db.Integer)
    disk_gb = db.Column(db.Integer)
    vnc_port = db.Column(db.Integer)
    guac_connection_id = db.Column(db.String(50))
    managed = db.Column(db.Boolean, nullable=False, default=False, server_default="false")


class VMShare(db.Model):
    """Udostępnienie maszyny linkiem: każdy z linkiem i hasłem dostaje konsolę (jedna maszyna).
    Jedno udostępnienie na maszynę. Wiersz istnieje = udostępnienie aktywne."""
    __tablename__ = "vm_shares"
    id = db.Column(db.Integer, primary_key=True)
    vm_id = db.Column(db.Integer, unique=True, nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    guac_user = db.Column(db.String(80), nullable=False)  # konto Guacamole z READ tylko do tej maszyny
    # zmiana hasła podbija wersję i unieważnia już odblokowane sesje
    pw_version = db.Column(db.Integer, nullable=False, default=1, server_default="1")
    failed_attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.Integer)


SHARE_MAX_ATTEMPTS = 5          # tyle błędnych haseł -> blokada linku
SHARE_LOCK_MINUTES = 5
SHARE_MIN_PASSWORD = 8
SHARE_MAX_PASSWORD_BYTES = 72   # limit bcrypt


MIGRATIONS = [
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS owner_id INTEGER",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS libvirt_name VARCHAR(100)",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS vcpus INTEGER",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS ram_mb INTEGER",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS disk_gb INTEGER",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS vnc_port INTEGER",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS guac_connection_id VARCHAR(50)",
    "ALTER TABLE vm_instances ADD COLUMN IF NOT EXISTS managed BOOLEAN NOT NULL DEFAULT FALSE",
    # istniejąca maszyna z seeda: umożliwia podgląd stanu / start / stop
    # dostęp do portalu: istniejące konta zostają dopuszczone (DEFAULT TRUE przy dodawaniu
    # kolumny), a nowe domyślnie nie mają dostępu (DEFAULT FALSE ustawiany zaraz potem)
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_allowed BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE users ALTER COLUMN is_allowed SET DEFAULT FALSE",
    "UPDATE vm_instances SET libvirt_name = name WHERE libvirt_name IS NULL AND name = 'xubuntu-vm1'",
]


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def is_admin():
    return current_user.is_authenticated and current_user.username == os.environ.get("ADMIN_USERNAME")


def has_access():
    """Czy zalogowany user może korzystać z portalu (admin zawsze, reszta wg flagi)."""
    return current_user.is_authenticated and (is_admin() or current_user.is_allowed)


@app.context_processor
def _inject_helpers():
    return {"is_admin": is_admin}


def guac_username(user):
    """Konto w Guacamole dla danego usera portalu: admin wchodzi jako guacadmin,
    reszta na konto o tej samej nazwie co w portalu."""
    if user.username == os.environ.get("ADMIN_USERNAME"):
        return guac.ADMIN_USER
    return user.username


def can_manage(vm):
    return is_admin() or (vm.owner_id is not None and vm.owner_id == current_user.id)


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# --- SSO (LoginHub) -------------------------------------------------------
def _create_vmportal_user(hub_username: str):
    """Zakłada konto w VM Portal dla usera z LoginHub, który nie miał tu jeszcze konta.
    Wołane przez sso_client.resolve_or_create_local_user przy pierwszej wizycie.

    Konto powstaje BEZ dostępu (is_allowed=False) — admin musi je zatwierdzić w /admin.
    Hasło jest losowe i nieznane nikomu, logowanie idzie przez SSO.
    get-or-create po username, żeby ponowne wywołanie nie tworzyło duplikatu.
    """
    username = hub_username[:80]
    existing = User.query.filter_by(username=username).first()
    if existing:
        return existing.id, existing.username

    user = User(username=username, is_allowed=False)
    user.set_password(secrets.token_urlsafe(24))
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        # wyścig z drugim workerem gunicorna — konto już jest
        db.session.rollback()
        user = User.query.filter_by(username=username).first()
        if not user:
            raise
    return user.id, user.username


# publiczne (bez konta) są też strony udostępnienia — zabezpiecza je hasło do linku
_PUBLIC_ENDPOINTS = {"static", "healthz", "share_access", "share_leave", "guac_denied"}
# endpointy dostępne dla zalogowanego, ale jeszcze niezatwierdzonego usera
# guac_auth sam zwraca 401/403 (a nie redirect), bo woła go nginx przez auth_request
_NO_ACCESS_ENDPOINTS = _PUBLIC_ENDPOINTS | {"no_access", "logout", "login", "guac_auth"}


@app.before_request
def _sso_autologin():
    if request.endpoint in _PUBLIC_ENDPOINTS or current_user.is_authenticated:
        return
    if request.endpoint == "guac_auth" and session.get("share_grant"):
        return  # gość z udostępnienia — nie pytamy LoginHub przy każdym żądaniu do Guacamole
    local_id = sso_client.resolve_or_create_local_user(
        app_slug="vmportal", create_user=_create_vmportal_user
    )
    if local_id:
        user = db.session.get(User, local_id)
        if user:
            login_user(user)


@app.before_request
def _require_access():
    """Domyślnie zamknięte: zalogowany user bez zgody admina widzi tylko /no-access."""
    if request.endpoint in _NO_ACCESS_ENDPOINTS or not current_user.is_authenticated:
        return
    if not has_access():
        return redirect(url_for("no_access"))


@login_manager.unauthorized_handler
def _unauthorized():
    # PrefixMiddleware wpisuje prefiks (/vmka1) do SCRIPT_NAME, a nie do request.path —
    # doklejamy go ręcznie, inaczej LoginHub odeśle usera poza appkę.
    return redirect(sso_client.login_url(request.script_root + request.path))


# --- Udostępnianie maszyny linkiem + hasłem --------------------------------
def _share_grant_valid(share):
    """Czy ta sesja przeszła weryfikację hasła dla TEGO udostępnienia (i hasło nie zmieniło się od tamtej pory)."""
    grant = session.get("share_grant")
    return bool(
        share and isinstance(grant, dict)
        and grant.get("sid") == share.id and grant.get("pwv") == share.pw_version
    )


def _session_share():
    """Aktywne udostępnienie odblokowane w tej sesji (albo None, jeśli brak/unieważnione)."""
    grant = session.get("share_grant")
    if not isinstance(grant, dict):
        return None
    share = db.session.get(VMShare, grant.get("sid") or 0)
    return share if _share_grant_valid(share) else None


def _drop_share(vm):
    """Usuwa udostępnienie maszyny (wiersz + konto w Guacamole). Zwraca ostrzeżenie albo None."""
    share = VMShare.query.filter_by(vm_id=vm.id).first()
    if not share:
        return None
    warning = None
    try:
        guac.delete_user(share.guac_user)
    except guac.GuacError as exc:
        warning = f"Nie usunięto konta udostępnienia w Guacamole: {exc}"
    db.session.delete(share)
    db.session.commit()
    return warning


@app.after_request
def _share_headers(resp):
    # token jest w URL-u: nie wyciekaj go w Referer, nie indeksuj, nie cache'uj
    if request.endpoint in ("share_access", "share_leave", "vm_share"):
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/vms/<int:vm_id>/share", methods=["GET", "POST"])
@login_required
def vm_share(vm_id):
    """Panel zarządzania udostępnieniem (tylko właściciel maszyny / admin)."""
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm):
        abort(403)
    share = VMShare.query.filter_by(vm_id=vm.id).first()

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "revoke":
            if share:
                warning = _drop_share(vm)
                flash("Udostępnienie zostało cofnięte — link przestał działać.", "success")
                if warning:
                    flash(warning, "error")
            return redirect(url_for("vm_share", vm_id=vm.id))

        if action != "save":
            abort(400)
        password = request.form.get("password", "")
        if len(password) < SHARE_MIN_PASSWORD:
            flash(f"Hasło musi mieć co najmniej {SHARE_MIN_PASSWORD} znaków.", "error")
            return redirect(url_for("vm_share", vm_id=vm.id))
        if len(password.encode("utf-8")) > SHARE_MAX_PASSWORD_BYTES:
            flash(f"Hasło jest za długie (maks. {SHARE_MAX_PASSWORD_BYTES} bajtów).", "error")
            return redirect(url_for("vm_share", vm_id=vm.id))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        if share:
            # zmiana hasła: stare odblokowane sesje przestają działać, odblokowujemy też link po blokadzie
            share.password_hash = pw_hash
            share.pw_version += 1
            share.failed_attempts = 0
            share.locked_until = None
            db.session.commit()
            flash("Hasło do linku zostało zmienione. Osoby, które już weszły, stracą dostęp przy następnym żądaniu.", "success")
        else:
            if not vm.guac_connection_id:
                flash("Tej maszyny nie da się udostępnić — nie ma połączenia w Guacamole.", "error")
                return redirect(url_for("vm_share", vm_id=vm.id))
            try:
                guac_user = guac.create_share_user(vm.guac_connection_id)
            except guac.GuacError as exc:
                flash(f"Nie udało się włączyć udostępnienia: {exc}", "error")
                return redirect(url_for("vm_share", vm_id=vm.id))
            try:
                db.session.add(VMShare(
                    vm_id=vm.id, token=secrets.token_urlsafe(24), password_hash=pw_hash,
                    guac_user=guac_user, created_by=current_user.id,
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
                try:
                    guac.delete_user(guac_user)
                except guac.GuacError:
                    pass
                raise
            flash("Udostępnienie włączone. Każdy, kto zna link i hasło, może otworzyć konsolę tej maszyny.", "success")
        return redirect(url_for("vm_share", vm_id=vm.id))

    share_path = url_for("share_access", token=share.token) if share else None
    return render_template("share_vm.html", vm=vm, share=share, share_path=share_path,
                           min_len=SHARE_MIN_PASSWORD)


@app.route("/s/<token>", methods=["GET", "POST"])
def share_access(token):
    """Publiczna strona udostępnionej maszyny: formularz hasła, a po nim przycisk konsoli."""
    share = VMShare.query.filter_by(token=token).first()
    vm = db.session.get(VMInstance, share.vm_id) if share else None
    if not share or not vm:
        abort(404)

    if request.method == "POST":
        now = datetime.utcnow()
        if share.locked_until and share.locked_until > now:
            flash("Za dużo błędnych prób. Spróbuj ponownie za kilka minut.", "error")
            return render_template("share_login.html", vm=vm), 429
        password = request.form.get("password", "")
        ok = len(password.encode("utf-8")) <= SHARE_MAX_PASSWORD_BYTES and \
            bcrypt.check_password_hash(share.password_hash, password)
        if not ok:
            share.failed_attempts += 1
            if share.failed_attempts >= SHARE_MAX_ATTEMPTS:
                share.failed_attempts = 0
                share.locked_until = now + timedelta(minutes=SHARE_LOCK_MINUTES)
                app.logger.warning("Udostępnienie VM %s zablokowane po serii błędnych haseł (IP %s)",
                                   vm.id, request.headers.get("X-Real-IP", request.remote_addr))
            db.session.commit()
            flash("Nieprawidłowe hasło.", "error")
            return render_template("share_login.html", vm=vm), 403
        share.failed_attempts = 0
        share.locked_until = None
        db.session.commit()
        session["share_grant"] = {"sid": share.id, "pwv": share.pw_version, "tok": share.token}
        session.permanent = False
        return redirect(url_for("share_access", token=token))

    if not _share_grant_valid(share):
        return render_template("share_login.html", vm=vm)

    state = None
    if vm.libvirt_name:
        try:
            state = lv.domain_states().get(vm.libvirt_name, "unknown")
        except lv.LibvirtError:
            state = None
    return render_template("share_view.html", vm=vm, share=share, state=state)


@app.route("/guac-denied")
def guac_denied():
    """Cel przekierowania z nginx, gdy /_guac_auth zwróci 401 (sesja wygasła / hasło zmienione).
    Gość z udostępnienia wraca na stronę swojego linku (hasło), a nie do LoginHub;
    wszyscy inni - jak dotąd - na dashboard."""
    grant = session.get("share_grant")
    tok = grant.get("tok") if isinstance(grant, dict) else None
    if tok:
        return redirect(url_for("share_access", token=tok))
    return redirect(url_for("dashboard"))


@app.route("/s/<token>/leave")
def share_leave(token):
    session.pop("share_grant", None)
    return redirect(url_for("share_access", token=token))


@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard"))


@app.route("/no-access")
@login_required
def no_access():
    if has_access():
        return redirect(url_for("dashboard"))
    return render_template("no_access.html", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Nieprawidłowa nazwa użytkownika lub hasło.", "error")

    return render_template(
        "login.html", hub_login_url=sso_client.login_url(url_for("dashboard"))
    )


@app.route("/logout")
@login_required
def logout():
    # Globalne wylogowanie: czyścimy ciasteczko SSO i wracamy na ekran logowania LoginHub.
    # Bez tego sso_session nadal byłoby ważne i _sso_autologin zalogowałby usera z powrotem.
    response = make_response(redirect(sso_client.login_url(url_for("dashboard"))))
    sso_client.clear_sso_cookie(response)
    logout_user()
    return response


# --- Panel admina: kto może korzystać z portalu ----------------------------
@app.route("/admin")
@login_required
def admin_panel():
    if not is_admin():
        abort(403)
    users = User.query.order_by(User.is_allowed.asc(), User.username).all()
    vm_counts = dict(
        db.session.query(VMInstance.owner_id, db.func.count(VMInstance.id))
        .filter(VMInstance.owner_id.isnot(None))
        .group_by(VMInstance.owner_id)
        .all()
    )
    admin_name = os.environ.get("ADMIN_USERNAME")
    rows = [
        {
            "user": u,
            "is_admin": u.username == admin_name,
            "allowed": u.username == admin_name or u.is_allowed,
            "vm_count": vm_counts.get(u.id, 0),
        }
        for u in users
    ]
    pending = sum(1 for r in rows if not r["allowed"])
    return render_template("admin.html", rows=rows, pending=pending, user=current_user)


@app.route("/admin/users/<int:user_id>/access", methods=["POST"])
@login_required
def admin_set_access(user_id):
    if not is_admin():
        abort(403)
    target = db.session.get(User, user_id) or abort(404)
    action = request.form.get("action", "")
    if action not in ("grant", "revoke"):
        abort(400)
    if target.username == os.environ.get("ADMIN_USERNAME"):
        flash("Konto administratora ma dostęp zawsze.", "error")
        return redirect(url_for("admin_panel"))
    target.is_allowed = action == "grant"
    db.session.commit()
    flash(
        f"Użytkownik „{target.username}” {'ma teraz dostęp' if target.is_allowed else 'nie ma już dostępu'} do portalu.",
        "success",
    )
    return redirect(url_for("admin_panel"))


@app.route("/dashboard")
@login_required
def dashboard():
    session.pop("share_grant", None)  # zalogowany user wraca do własnego konta w Guacamole
    shared_ids = {sh.vm_id for sh in VMShare.query.all()}
    vms = VMInstance.query.order_by(VMInstance.name).all()
    libvirt_error = None
    try:
        states = lv.domain_states()
    except lv.LibvirtError as exc:
        states = {}
        libvirt_error = str(exc)

    rows = [
        {
            "vm": vm,
            "state": states.get(vm.libvirt_name, "unknown") if vm.libvirt_name else None,
            "can_manage": can_manage(vm),
            "shared": vm.id in shared_ids,
        }
        for vm in vms
    ]
    return render_template(
        "dashboard.html", rows=rows, user=current_user, libvirt_error=libvirt_error
    )


@app.route("/vms/new", methods=["GET", "POST"])
@login_required
def new_vm():
    try:
        isos = lv.list_isos()
    except lv.LibvirtError as exc:
        flash(f"Libvirt jest niedostępny: {exc}", "error")
        return redirect(url_for("dashboard"))

    form = {
        "name": "", "description": "", "vcpus": 2, "ram_mb": 2048,
        "disk_gb": 20, "os_type": "linux", "iso": "",
    }

    if request.method == "POST":
        form["name"] = request.form.get("name", "").strip().lower()
        form["description"] = request.form.get("description", "").strip()[:500]
        form["os_type"] = request.form.get("os_type", "linux")
        form["iso"] = request.form.get("iso", "")
        vcpus = _to_int(request.form.get("vcpus"))
        ram_mb = _to_int(request.form.get("ram_mb"))
        disk_gb = _to_int(request.form.get("disk_gb"))
        form.update(vcpus=vcpus or "", ram_mb=ram_mb or "", disk_gb=disk_gb or "")

        errors = []
        if not lv.NAME_RE.match(form["name"]):
            errors.append("Nazwa: 3–32 znaki, małe litery, cyfry i myślniki, zaczyna się od litery.")
        elif VMInstance.query.filter_by(libvirt_name=form["name"]).first():
            errors.append("Maszyna o takiej nazwie już istnieje.")
        if vcpus is None or not 1 <= vcpus <= LIMITS["vcpus"]:
            errors.append(f"Liczba vCPU: od 1 do {LIMITS['vcpus']}.")
        if ram_mb is None or not MIN_RAM_MB <= ram_mb <= LIMITS["ram_mb"]:
            errors.append(f"RAM: od {MIN_RAM_MB} do {LIMITS['ram_mb']} MB.")
        if disk_gb is None or not MIN_DISK_GB <= disk_gb <= LIMITS["disk_gb"]:
            errors.append(f"Dysk: od {MIN_DISK_GB} do {LIMITS['disk_gb']} GB.")
        if form["os_type"] not in lv.OS_PROFILES:
            errors.append("Nieprawidłowy typ systemu.")
        if form["iso"] and form["iso"] not in isos:
            errors.append("Wybrany obraz ISO nie istnieje.")
        if not is_admin():
            owned = VMInstance.query.filter_by(owner_id=current_user.id, managed=True).count()
            if owned >= LIMITS["vms_per_user"]:
                errors.append(f"Osiągnięto limit {LIMITS['vms_per_user']} maszyn na użytkownika.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("create_vm.html", form=form, isos=isos, limits=LIMITS,
                                   min_ram=MIN_RAM_MB, min_disk=MIN_DISK_GB)

        created = None
        conn_id = None
        try:
            reserved = [v.vnc_port for v in VMInstance.query.filter(VMInstance.vnc_port.isnot(None)).all()]
            created = lv.create_vm(
                form["name"], vcpus, ram_mb, disk_gb, form["os_type"], form["iso"] or None, reserved
            )
            conn_id = guac.create_connection(
                form["name"], VM_HOST, created["vnc_port"], created["vnc_password"],
                grant_users=GUAC_GRANT_USERS + [guac_username(current_user)],
            )
            vm = VMInstance(
                name=form["name"],
                description=form["description"],
                guacamole_url=guac.client_url(conn_id),
                owner_id=current_user.id,
                libvirt_name=form["name"],
                vcpus=vcpus, ram_mb=ram_mb, disk_gb=disk_gb,
                vnc_port=created["vnc_port"],
                guac_connection_id=conn_id,
                managed=True,
            )
            db.session.add(vm)
            db.session.commit()
        except (lv.LibvirtError, guac.GuacError) as exc:
            db.session.rollback()
            # sprzątanie po nieudanej operacji
            if conn_id:
                try:
                    guac.delete_connection(conn_id)
                except guac.GuacError:
                    pass
            if created:
                try:
                    lv.delete_vm(created["name"])
                except lv.LibvirtError:
                    pass
            flash(f"Nie udało się utworzyć maszyny: {exc}", "error")
            return render_template("create_vm.html", form=form, isos=isos, limits=LIMITS,
                                   min_ram=MIN_RAM_MB, min_disk=MIN_DISK_GB)

        flash(f"Maszyna „{form['name']}” została utworzona i uruchomiona. "
              "Otwórz konsolę, aby dokończyć instalację systemu.", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_vm.html", form=form, isos=isos, limits=LIMITS,
                           min_ram=MIN_RAM_MB, min_disk=MIN_DISK_GB)


@app.route("/isos/upload", methods=["POST"])
@login_required
def upload_iso():
    """Wgrywanie własnego ISO do puli ISO (widoczne potem na liście przy tworzeniu maszyn).
    Plik przychodzi jako SUROWE body żądania (nie multipart), a nazwa w ?name=, dzięki czemu
    kilkugigabajtowy obraz płynie strumieniem prosto do libvirt, bez plików tymczasowych."""
    name = secure_filename(request.args.get("name", ""))
    if not name.lower().endswith(".iso") or len(name) > 120:
        return jsonify(error="Nieprawidłowa nazwa pliku - wymagane rozszerzenie .iso."), 400

    size = request.content_length
    if not size:
        return jsonify(error="Brak rozmiaru pliku w żądaniu."), 400
    if size > LIMITS["iso_mb"] * 1024 * 1024:
        return jsonify(error=f"Plik jest za duży (limit {LIMITS['iso_mb']} MB)."), 413

    try:
        lv.upload_iso(name, request.stream, size)
    except lv.LibvirtError as exc:
        return jsonify(error=str(exc)), 400
    except OSError as exc:  # np. klient zerwał połączenie w trakcie wysyłania
        app.logger.warning("Upload ISO '%s' przerwany: %s", name, exc)
        return jsonify(error="Przesyłanie zostało przerwane."), 400

    app.logger.info("Użytkownik %s wgrał ISO '%s' (%d B)", current_user.username, name, size)
    return jsonify(ok=True, name=name)


@app.route("/vms/<int:vm_id>/resources")
@login_required
def vm_resources(vm_id):
    """Przydział (i bieżące zużycie) RAM / CPU / dysku maszyny - odpytywane z dashboardu."""
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm) or not vm.libvirt_name:
        abort(403)
    try:
        return jsonify(lv.vm_resources(vm.libvirt_name))
    except lv.LibvirtError as exc:
        return jsonify(error=str(exc)), 502


@app.route("/vms/<int:vm_id>/power", methods=["POST"])
@login_required
def vm_power(vm_id):
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm) or not vm.libvirt_name:
        abort(403)
    action = request.form.get("action", "")
    if action not in ("start", "shutdown", "reboot", "destroy"):
        abort(400)
    try:
        lv.power(vm.libvirt_name, action)
        flash("Polecenie zostało wysłane.", "success")
    except lv.LibvirtError as exc:
        flash(f"Błąd libvirt: {exc}", "error")
    return redirect(url_for("dashboard"))


@app.route("/vms/<int:vm_id>/edit", methods=["GET", "POST"])
@login_required
def vm_edit(vm_id):
    """Zmiana vCPU / RAM / dysku maszyny - tylko gdy jest wyłączona."""
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm) or not vm.libvirt_name:
        abort(403)

    try:
        cur = lv.vm_resources(vm.libvirt_name)
    except lv.LibvirtError as exc:
        flash(f"Libvirt jest niedostępny: {exc}", "error")
        return redirect(url_for("dashboard"))
    if cur["state"] not in ("stopped", "crashed"):
        flash("Zasoby można zmieniać tylko przy wyłączonej maszynie. Zamknij ją i spróbuj ponownie.", "error")
        return redirect(url_for("dashboard"))

    disk_now = -(-cur["disks"][0]["capacity"] // lv.GIB) if cur["disks"] else None
    form = {"vcpus": cur["vcpus"], "ram_mb": cur["ram_max_mb"], "disk_gb": disk_now or ""}

    def render():
        return render_template("edit_vm.html", vm=vm, form=form, limits=LIMITS, min_ram=MIN_RAM_MB,
                               min_disk=disk_now or MIN_DISK_GB, has_disk=disk_now is not None)

    if request.method == "POST":
        vcpus = _to_int(request.form.get("vcpus"))
        ram_mb = _to_int(request.form.get("ram_mb"))
        disk_gb = _to_int(request.form.get("disk_gb")) if disk_now is not None else None
        form.update(vcpus=vcpus or "", ram_mb=ram_mb or "", disk_gb=disk_gb or "" if disk_now is not None else "")

        errors = []
        if vcpus is None or not 1 <= vcpus <= LIMITS["vcpus"]:
            errors.append(f"Liczba vCPU: od 1 do {LIMITS['vcpus']}.")
        if ram_mb is None or not MIN_RAM_MB <= ram_mb <= LIMITS["ram_mb"]:
            errors.append(f"RAM: od {MIN_RAM_MB} do {LIMITS['ram_mb']} MB.")
        if disk_now is not None:
            if disk_gb is None or not disk_now <= disk_gb <= max(LIMITS["disk_gb"], disk_now):
                errors.append(f"Dysk: od {disk_now} (obecny rozmiar - nie można zmniejszać) do {max(LIMITS['disk_gb'], disk_now)} GB.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render()

        try:
            lv.update_vm_resources(
                vm.libvirt_name,
                vcpus=vcpus if vcpus != cur["vcpus"] else None,
                ram_mb=ram_mb if ram_mb != cur["ram_max_mb"] else None,
                disk_gb=disk_gb if disk_now is not None and disk_gb != disk_now else None,
            )
        except lv.LibvirtError as exc:
            flash(f"Nie udało się zmienić zasobów: {exc}", "error")
            return render()

        vm.vcpus, vm.ram_mb = vcpus, ram_mb
        if disk_now is not None:
            vm.disk_gb = disk_gb
        db.session.commit()
        flash("Zasoby zostały zmienione. Zadziałają po uruchomieniu maszyny."
              + (" Jeśli powiększono dysk, rozszerz partycję w systemie gościa." if disk_now and disk_gb != disk_now else ""),
              "success")
        return redirect(url_for("dashboard"))

    return render()


def _clone_name_suggestion(base):
    """Propozycja nazwy klona zgodna z NAME_RE (3-32 znaki) i wolna w bazie."""
    for i in range(1, 100):
        suffix = "-clone" if i == 1 else f"-clone{i}"
        cand = (base[: 32 - len(suffix)].rstrip("-") + suffix)
        if lv.NAME_RE.match(cand) and not VMInstance.query.filter_by(libvirt_name=cand).first():
            return cand
    return ""


@app.route("/vms/<int:vm_id>/clone", methods=["GET", "POST"])
@login_required
def vm_clone(vm_id):
    """Klonowanie wyłączonej maszyny: pełna kopia dysków + nowa maszyna z własną konsolą."""
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm) or not vm.libvirt_name:
        abort(403)

    try:
        cur = lv.vm_resources(vm.libvirt_name)
    except lv.LibvirtError as exc:
        flash(f"Libvirt jest niedostępny: {exc}", "error")
        return redirect(url_for("dashboard"))
    if cur["state"] not in ("stopped", "crashed"):
        flash("Maszynę można sklonować tylko wtedy, gdy jest wyłączona. Zamknij ją i spróbuj ponownie.", "error")
        return redirect(url_for("dashboard"))

    disk_now = -(-cur["disks"][0]["capacity"] // lv.GIB) if cur["disks"] else None
    specs = {"vcpus": cur["vcpus"], "ram_mb": cur["ram_max_mb"], "disk_gb": disk_now}
    form = {
        "name": _clone_name_suggestion(vm.libvirt_name),
        "description": (f"Klon maszyny {vm.name}")[:500],
    }

    def render():
        return render_template("clone_vm.html", vm=vm, form=form, specs=specs)

    if request.method == "POST":
        form["name"] = request.form.get("name", "").strip().lower()
        form["description"] = request.form.get("description", "").strip()[:500]

        errors = []
        if not lv.NAME_RE.match(form["name"]):
            errors.append("Nazwa: 3–32 znaki, małe litery, cyfry i myślniki, zaczyna się od litery.")
        elif VMInstance.query.filter_by(libvirt_name=form["name"]).first():
            errors.append("Maszyna o takiej nazwie już istnieje.")
        if not is_admin():
            owned = VMInstance.query.filter_by(owner_id=current_user.id, managed=True).count()
            if owned >= LIMITS["vms_per_user"]:
                errors.append(f"Osiągnięto limit {LIMITS['vms_per_user']} maszyn na użytkownika.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render()

        created = None
        conn_id = None
        try:
            reserved = [v.vnc_port for v in VMInstance.query.filter(VMInstance.vnc_port.isnot(None)).all()]
            created = lv.clone_vm(vm.libvirt_name, form["name"], reserved)
            conn_id = guac.create_connection(
                form["name"], VM_HOST, created["vnc_port"], created["vnc_password"],
                grant_users=GUAC_GRANT_USERS + [guac_username(current_user)],
            )
            clone = VMInstance(
                name=form["name"],
                description=form["description"],
                guacamole_url=guac.client_url(conn_id),
                owner_id=current_user.id,
                libvirt_name=form["name"],
                vcpus=created["vcpus"], ram_mb=created["ram_mb"], disk_gb=created["disk_gb"],
                vnc_port=created["vnc_port"],
                guac_connection_id=conn_id,
                managed=True,
            )
            db.session.add(clone)
            db.session.commit()
        except (lv.LibvirtError, guac.GuacError) as exc:
            db.session.rollback()
            # sprzątanie po nieudanej operacji
            if conn_id:
                try:
                    guac.delete_connection(conn_id)
                except guac.GuacError:
                    pass
            if created:
                try:
                    lv.delete_vm(created["name"])
                except lv.LibvirtError:
                    pass
            flash(f"Nie udało się sklonować maszyny: {exc}", "error")
            return render()

        app.logger.info("Użytkownik %s sklonował VM '%s' jako '%s'",
                        current_user.username, vm.libvirt_name, form["name"])
        flash(f"Maszyna „{vm.name}” została sklonowana jako „{form['name']}”. "
              "Klon jest wyłączony - uruchom go przyciskiem Start.", "success")
        return redirect(url_for("dashboard"))

    return render()


@app.route("/vms/<int:vm_id>/delete", methods=["POST"])
@login_required
def vm_delete(vm_id):
    vm = db.session.get(VMInstance, vm_id) or abort(404)
    if not can_manage(vm):
        abort(403)
    try:
        if vm.managed and vm.libvirt_name:
            lv.delete_vm(vm.libvirt_name)
        warning = _drop_share(vm)
        if warning:
            flash(warning, "error")
        if vm.guac_connection_id:
            try:
                guac.delete_connection(vm.guac_connection_id)
            except guac.GuacError as exc:
                flash(f"Nie usunięto połączenia w Guacamole: {exc}", "error")
        db.session.delete(vm)
        db.session.commit()
        flash("Maszyna została usunięta.", "success")
    except lv.LibvirtError as exc:
        db.session.rollback()
        flash(f"Błąd libvirt: {exc}", "error")
    return redirect(url_for("dashboard"))


# --- Guacamole SSO (nginx auth_request) ------------------------------------
_guac_synced = set()  # konta już zsynchronizowane w tym procesie (żeby nie wołać REST przy każdym żądaniu)


@app.route("/_guac_auth")
def guac_auth():
    """Wołane przez nginx (auth_request) przy KAŻDYM żądaniu do /guacamole/.
    200 + X-Guac-User => nginx podaje ten nagłówek Guacamole (rozszerzenie header-auth)
    i user wchodzi bez ekranu logowania. 401 => niezalogowany, 403 => brak zgody admina."""
    # Gość z linkiem udostępnienia: wchodzi na wyizolowane konto z dostępem tylko do jednej maszyny.
    share = _session_share()
    if share:
        return "", 200, {"X-Guac-User": share.guac_user}

    if not current_user.is_authenticated:
        return "", 401
    if not has_access():
        return "", 403

    gname = guac_username(current_user)
    if gname not in _guac_synced:
        try:
            owned = [
                v.guac_connection_id
                for v in VMInstance.query.filter_by(owner_id=current_user.id).all()
                if v.guac_connection_id
            ]
            guac.sync_user(gname, owned)
        except guac.GuacError as exc:
            app.logger.error("Synchronizacja konta Guacamole nie powiodła się: %s", exc)
            return "", 503
        _guac_synced.add(gname)

    return "", 200, {"X-Guac-User": gname}


@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


def wait_for_db_and_init():
    max_retries = 20
    for attempt in range(1, max_retries + 1):
        try:
            with app.app_context():
                db.create_all()

                for stmt in MIGRATIONS:
                    db.session.execute(text(stmt))
                db.session.commit()

                admin_username = os.environ.get("ADMIN_USERNAME")
                admin_password = os.environ.get("ADMIN_PASSWORD")
                if admin_username and admin_password:
                    existing = User.query.filter_by(username=admin_username).first()
                    if not existing:
                        admin = User(username=admin_username)
                        admin.set_password(admin_password)
                        db.session.add(admin)
                        print(f"[init] Utworzono użytkownika administracyjnego '{admin_username}'.")

                guac_base_url = os.environ.get("GUACAMOLE_PUBLIC_URL", "/guacamole/")
                if VMInstance.query.count() == 0:
                    seed_vm = VMInstance(
                        name="xubuntu-vm1",
                        description="Główna maszyna wirtualna Xubuntu",
                        guacamole_url=guac_base_url,
                        libvirt_name="xubuntu-vm1",
                    )
                    db.session.add(seed_vm)
                    print("[init] Dodano domyślny wpis VM 'xubuntu-vm1'.")

                db.session.commit()
            return
        except OperationalError:
            print(f"[init] Baza danych jeszcze niegotowa, próba {attempt}/{max_retries}...")
            time.sleep(3)

    raise RuntimeError("Nie udało się połączyć z bazą danych po wielu próbach.")


wait_for_db_and_init()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
