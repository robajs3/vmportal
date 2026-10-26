"""Podstrona „Przeglądarki”: profile, sesje (kontenery), wtyczki, skrypty.

Podpinana jednym wywołaniem register(...) z app.py - nie rusza istniejących tras maszyn.
Prywatność: profil widzi i otwiera tylko jego właściciel. Admin może sesje zatrzymać/usunąć
(żeby odzyskać pulę RAM), ale nie ma wglądu w obraz ani skrypty (BROWSER_ADMIN_CAN_VIEW=1 to zmienia).
"""
import json
import os
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import text

import browsers as br
import fingerprint as fpmod

ADMIN_CAN_VIEW = os.environ.get("BROWSER_ADMIN_CAN_VIEW", "0") == "1"
MAX_PROFILES_PER_USER = int(os.environ.get("BROWSER_MAX_PROFILES_PER_USER", "10"))
DEFAULT_IDLE_MIN = 30
SWEEP_SECONDS = int(os.environ.get("BROWSER_SWEEP_SECONDS", "60"))
NAME_RE = re.compile(r"^[\w .\-]{1,60}$", re.UNICODE)
URL_RE = re.compile(r"^https?://[^\s]{1,480}$")

DEFAULT_SCRIPT = '''# Dostępne: playwright, browser, context (profil z ciasteczkami i wtyczkami), page
page.goto("https://example.com")
print(page.title())
'''


def register(app, db, orch, is_admin, has_access, User):
    """Rejestruje modele i trasy. Zwraca słownik z modelami (przydatne w testach)."""

    class BrowserProfile(db.Model):
        __tablename__ = "browser_profiles"
        id = db.Column(db.Integer, primary_key=True)
        public_id = db.Column(db.String(12), unique=True, nullable=False)
        owner_id = db.Column(db.Integer, nullable=False, index=True)
        name = db.Column(db.String(60), nullable=False)
        os_family = db.Column(db.String(10), nullable=False, default="windows")
        lang = db.Column(db.String(10), nullable=False, default="pl-PL")
        timezone = db.Column(db.String(60), nullable=False, default="Europe/Warsaw")
        resolution = db.Column(db.String(10), nullable=False, default="1280x720")
        ram_mb = db.Column(db.Integer, nullable=False, default=br.DEFAULT_SESSION_RAM_MB)
        background = db.Column(db.Boolean, nullable=False, default=False)
        idle_minutes = db.Column(db.Integer, nullable=False, default=DEFAULT_IDLE_MIN)
        fp_enabled = db.Column(db.Boolean, nullable=False, default=True)
        fp_seed = db.Column(db.String(32), nullable=False)
        fp_json = db.Column(db.Text, nullable=False, default="{}")
        webgl = db.Column(db.Boolean, nullable=False, default=True)
        proxy = db.Column(db.String(200))
        start_url = db.Column(db.String(500))
        extension_ids = db.Column(db.Text, nullable=False, default="[]")
        last_script = db.Column(db.Text)
        last_viewer_at = db.Column(db.DateTime)
        created_at = db.Column(db.DateTime, server_default=db.func.now())

        @property
        def fp(self):
            try:
                return json.loads(self.fp_json) if self.fp_enabled else None
            except ValueError:
                return None

        @property
        def ext_list(self):
            try:
                return [int(x) for x in json.loads(self.extension_ids or "[]")]
            except (ValueError, TypeError):
                return []

    class BrowserExtension(db.Model):
        __tablename__ = "browser_extensions"
        id = db.Column(db.Integer, primary_key=True)
        owner_id = db.Column(db.Integer, nullable=False, index=True)
        name = db.Column(db.String(120), nullable=False)
        kind = db.Column(db.String(10), nullable=False)       # store | upload
        ext_id = db.Column(db.String(32))                      # ID ze sklepu Chrome
        dirname = db.Column(db.String(32))                     # katalog wgranej wtyczki
        created_at = db.Column(db.DateTime, server_default=db.func.now())

    # ------------------------------------------------------------------ pomocnicze
    def _lock(key):
        """Blokada między workerami gunicorna (tylko Postgres)."""
        if db.engine.dialect.name == "postgresql":
            db.session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})

    def _can_view(p):
        return p.owner_id == current_user.id or (ADMIN_CAN_VIEW and is_admin())

    def _own(profile_id, allow_admin=False):
        p = db.session.get(BrowserProfile, profile_id) or abort(404)
        if _can_view(p) or (allow_admin and is_admin()):
            return p
        abort(403)

    def _extensions_of(p):
        if not p.ext_list:
            return []
        rows = BrowserExtension.query.filter(
            BrowserExtension.id.in_(p.ext_list), BrowserExtension.owner_id == p.owner_id).all()
        return [{"kind": e.kind, "ext_id": e.ext_id, "dirname": e.dirname} for e in rows]

    def _pdict(p):
        return {
            "id": p.id, "public_id": p.public_id, "name": p.name, "ram_mb": p.ram_mb,
            "resolution": p.resolution, "timezone": p.timezone, "lang": p.lang,
            "background": p.background, "webgl": p.webgl, "proxy": p.proxy,
            "start_url": p.start_url, "fp": p.fp, "extensions": _extensions_of(p),
        }

    def _gen_fp(seed, os_family, lang, tz, res):
        return json.dumps(fpmod.generate(seed, os_family, lang, tz, res), separators=(",", ":"))

    def _new_public_id():
        while True:
            pid = secrets.token_hex(6)
            if not BrowserProfile.query.filter_by(public_id=pid).first():
                return pid

    def _form_values(src, owner_id, existing=None):
        """Waliduje formularz profilu. Zwraca (wartości, błędy)."""
        errors = []
        v = {
            "name": src.get("name", "").strip(),
            "os_family": src.get("os_family", "windows"),
            "lang": src.get("lang", "pl-PL").strip(),
            "timezone": src.get("timezone", "Europe/Warsaw").strip(),
            "resolution": src.get("resolution", "1280x720"),
            "background": src.get("background") == "on",
            "fp_enabled": src.get("fp_enabled") == "on",
            "webgl": src.get("webgl") == "on",
            "proxy": src.get("proxy", "").strip() or None,
            "start_url": src.get("start_url", "").strip() or None,
            "regenerate": src.get("regenerate") == "on",
        }
        try:
            v["ram_mb"] = int(src.get("ram_mb", br.DEFAULT_SESSION_RAM_MB))
        except ValueError:
            v["ram_mb"] = 0
        try:
            v["idle_minutes"] = int(src.get("idle_minutes", DEFAULT_IDLE_MIN))
        except ValueError:
            v["idle_minutes"] = -1

        if not NAME_RE.match(v["name"]):
            errors.append("Nazwa: 1–60 znaków (litery, cyfry, spacja, kropka, myślnik, podkreślenie).")
        else:
            dup = BrowserProfile.query.filter_by(owner_id=owner_id, name=v["name"]).first()
            if dup and (not existing or dup.id != existing.id):
                errors.append("Masz już profil o takiej nazwie.")
        if v["os_family"] not in fpmod.OS_FAMILIES:
            errors.append("Nieprawidłowy system udawanego urządzenia.")
        if not fpmod.valid_lang(v["lang"]):
            errors.append("Język w formacie np. pl-PL, en-US.")
        if not fpmod.valid_timezone(v["timezone"]):
            errors.append("Nieznana strefa czasowa (np. Europe/Warsaw).")
        if v["resolution"] not in fpmod.RESOLUTIONS:
            errors.append("Nieprawidłowa rozdzielczość.")
        if not br.MIN_SESSION_RAM_MB <= v["ram_mb"] <= br.MAX_SESSION_RAM_MB:
            errors.append(f"RAM sesji: od {br.MIN_SESSION_RAM_MB} do {br.MAX_SESSION_RAM_MB} MB.")
        if not 0 <= v["idle_minutes"] <= 1440:
            errors.append("Czas bezczynności: 0–1440 minut (0 = nigdy).")
        if v["proxy"] and not br.PROXY_RE.match(v["proxy"]):
            errors.append("Proxy w formacie schemat://host:port (bez loginu i hasła).")
        if v["start_url"] and not URL_RE.match(v["start_url"]):
            errors.append("Strona startowa musi zaczynać się od http:// lub https://.")

        wanted = []
        for raw in src.getlist("ext") if hasattr(src, "getlist") else []:
            try:
                wanted.append(int(raw))
            except ValueError:
                continue
        owned = {e.id for e in BrowserExtension.query.filter_by(owner_id=owner_id).all()}
        v["extension_ids"] = sorted(set(wanted) & owned)
        return v, errors

    def _form_defaults():
        return {
            "name": "", "os_family": "windows", "lang": "pl-PL", "timezone": "Europe/Warsaw",
            "resolution": "1280x720", "ram_mb": br.DEFAULT_SESSION_RAM_MB, "background": False,
            "idle_minutes": DEFAULT_IDLE_MIN, "fp_enabled": True, "webgl": True, "proxy": "",
            "start_url": "", "extension_ids": [],
        }

    def _render_form(form, profile=None):
        exts = BrowserExtension.query.filter_by(owner_id=current_user.id).order_by(BrowserExtension.name).all()
        return render_template(
            "browser_form.html", form=form, profile=profile, exts=exts, os_families=fpmod.OS_FAMILIES,
            resolutions=fpmod.RESOLUTIONS, langs=fpmod.LANGS, limits={
                "min_ram": br.MIN_SESSION_RAM_MB, "max_ram": br.MAX_SESSION_RAM_MB})

    # ------------------------------------------------------------------ lista
    @app.route("/browsers")
    @login_required
    def browsers_list():
        q = BrowserProfile.query
        if not is_admin():
            q = q.filter_by(owner_id=current_user.id)
        profiles = q.order_by(BrowserProfile.name).all()
        err, pool, sessions = None, None, {}
        try:
            sessions = orch.sessions()
            pool = orch.pool()
        except br.BrowserError as exc:
            err = str(exc)
        owners = {u.id: u.username for u in User.query.filter(User.id.in_({p.owner_id for p in profiles})).all()} \
            if profiles else {}
        rows = [{
            "p": p, "mine": p.owner_id == current_user.id, "owner": owners.get(p.owner_id, "?"),
            "state": (sessions.get(p.public_id) or {}).get("state", "stopped"),
            "fp": fpmod.summary(p.fp) if p.fp else "maskowanie wyłączone",
            "n_ext": len(p.ext_list),
            "can_open": _can_view(p),
        } for p in profiles]
        return render_template("browsers.html", rows=rows, pool=pool, error=err, user=current_user)

    # ------------------------------------------------------------------ tworzenie / edycja
    @app.route("/browsers/new", methods=["GET", "POST"])
    @login_required
    def browser_new():
        form = _form_defaults()
        if request.method == "POST":
            v, errors = _form_values(request.form, current_user.id)
            form.update(v)
            if BrowserProfile.query.filter_by(owner_id=current_user.id).count() >= MAX_PROFILES_PER_USER:
                errors.append(f"Limit {MAX_PROFILES_PER_USER} profili na użytkownika.")
            if errors:
                for e in errors:
                    flash(e, "error")
                return _render_form(form)
            seed = fpmod.new_seed()
            p = BrowserProfile(
                public_id=_new_public_id(), owner_id=current_user.id, name=v["name"],
                os_family=v["os_family"], lang=v["lang"], timezone=v["timezone"],
                resolution=v["resolution"], ram_mb=v["ram_mb"], background=v["background"],
                idle_minutes=v["idle_minutes"], fp_enabled=v["fp_enabled"], fp_seed=seed,
                fp_json=_gen_fp(seed, v["os_family"], v["lang"], v["timezone"], v["resolution"]),
                webgl=v["webgl"], proxy=v["proxy"], start_url=v["start_url"],
                extension_ids=json.dumps(v["extension_ids"]), last_script=DEFAULT_SCRIPT,
            )
            db.session.add(p)
            db.session.commit()
            flash(f"Profil „{p.name}” utworzony. Uruchom sesję przyciskiem Start.", "success")
            return redirect(url_for("browsers_list"))
        return _render_form(form)

    @app.route("/browsers/<int:profile_id>/edit", methods=["GET", "POST"])
    @login_required
    def browser_edit(profile_id):
        p = _own(profile_id)
        form = {
            "name": p.name, "os_family": p.os_family, "lang": p.lang, "timezone": p.timezone,
            "resolution": p.resolution, "ram_mb": p.ram_mb, "background": p.background,
            "idle_minutes": p.idle_minutes, "fp_enabled": p.fp_enabled, "webgl": p.webgl,
            "proxy": p.proxy or "", "start_url": p.start_url or "", "extension_ids": p.ext_list,
        }
        if request.method == "POST":
            v, errors = _form_values(request.form, p.owner_id, existing=p)
            form.update(v)
            if errors:
                for e in errors:
                    flash(e, "error")
                return _render_form(form, p)
            if v["regenerate"]:
                p.fp_seed = fpmod.new_seed()
            p.name, p.os_family, p.lang, p.timezone = v["name"], v["os_family"], v["lang"], v["timezone"]
            p.resolution, p.ram_mb, p.background = v["resolution"], v["ram_mb"], v["background"]
            p.idle_minutes, p.fp_enabled, p.webgl = v["idle_minutes"], v["fp_enabled"], v["webgl"]
            p.proxy, p.start_url = v["proxy"], v["start_url"]
            p.extension_ids = json.dumps(v["extension_ids"])
            p.fp_json = _gen_fp(p.fp_seed, p.os_family, p.lang, p.timezone, p.resolution)
            db.session.commit()
            running = orch.state_of(p.public_id) == "running"
            flash("Zapisano." + (" Zmiany zadziałają po restarcie sesji (Stop → Start)." if running else ""), "success")
            return redirect(url_for("browsers_list"))
        return _render_form(form, p)

    # ------------------------------------------------------------------ start / stop / usuń
    @app.route("/browsers/<int:profile_id>/start", methods=["POST"])
    @login_required
    def browser_start(profile_id):
        p = _own(profile_id)
        try:
            _lock(727001)
            orch.start(_pdict(p))
            p.last_viewer_at = datetime.utcnow()
            db.session.commit()
        except br.BrowserError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for("browsers_list"))
        return redirect(url_for("browser_view", profile_id=p.id))

    @app.route("/browsers/<int:profile_id>/stop", methods=["POST"])
    @login_required
    def browser_stop(profile_id):
        p = _own(profile_id, allow_admin=True)
        try:
            orch.stop(p.public_id)
            flash(f"Sesja „{p.name}” zatrzymana — pamięć wróciła do puli, profil zostaje zapisany.", "success")
        except br.BrowserError as exc:
            flash(str(exc), "error")
        return redirect(url_for("browsers_list"))

    @app.route("/browsers/<int:profile_id>/delete", methods=["POST"])
    @login_required
    def browser_delete(profile_id):
        p = _own(profile_id, allow_admin=True)
        try:
            orch.delete_profile_data(p.public_id)
        except br.BrowserError as exc:
            flash(str(exc), "error")
            return redirect(url_for("browsers_list"))
        db.session.delete(p)
        db.session.commit()
        flash("Profil usunięty razem z danymi (ciasteczka, historia).", "success")
        return redirect(url_for("browsers_list"))

    # ------------------------------------------------------------------ podgląd + skrypty
    @app.route("/browsers/<int:profile_id>/view")
    @login_required
    def browser_view(profile_id):
        p = _own(profile_id)
        state = "stopped"
        try:
            state = orch.state_of(p.public_id)
        except br.BrowserError as exc:
            flash(str(exc), "error")
        pwd = br.session_password(app.config["SECRET_KEY"], p.public_id, "admin")
        embed = f"{request.script_root}{br.PATH_PREFIX}/{p.public_id}/"
        return render_template(
            "browser_view.html", p=p, state=state, embed_url=embed, usr=current_user.username, pwd=pwd,
            fp_pretty=json.dumps(p.fp, indent=2, ensure_ascii=False) if p.fp else None,
            script=p.last_script or DEFAULT_SCRIPT, max_run=br.MAX_RUN_SECONDS)

    @app.route("/browsers/<int:profile_id>/status")
    @login_required
    def browser_status(profile_id):
        p = _own(profile_id)
        try:
            state = orch.state_of(p.public_id)
        except br.BrowserError as exc:
            return jsonify(error=str(exc)), 502
        ready = False
        if state == "running":
            try:
                ready = requests.get(f"http://{br.container_name(p.public_id)}:8080{br.PATH_PREFIX}/{p.public_id}/health",
                                     timeout=2).status_code == 200
            except requests.RequestException:
                ready = False
        return jsonify(state=state, ready=ready)

    @app.route("/browsers/<int:profile_id>/resources")
    @login_required
    def browser_resources(profile_id):
        p = _own(profile_id, allow_admin=True)
        try:
            st = orch.stats(p.public_id)
        except Exception as exc:  # noqa: BLE001
            return jsonify(error=str(exc)), 502
        if st is None:
            return jsonify(error="Sesja nie działa."), 404
        return jsonify(st)

    @app.route("/browsers/<int:profile_id>/scripts/run", methods=["POST"])
    @login_required
    def browser_script_run(profile_id):
        p = _own(profile_id)
        data = request.get_json(silent=True) or {}
        code = str(data.get("code", ""))
        try:
            timeout = int(data.get("timeout", 120))
        except (TypeError, ValueError):
            timeout = 120
        try:
            info = orch.run_script(p.public_id, code, timeout)
        except br.BrowserError as exc:
            return jsonify(error=str(exc)), 400
        p.last_script = code
        db.session.commit()
        app.logger.info("Użytkownik %s uruchomił skrypt w profilu %s", current_user.username, p.public_id)
        return jsonify(info)

    @app.route("/browsers/<int:profile_id>/scripts/status")
    @login_required
    def browser_script_status(profile_id):
        p = _own(profile_id)
        try:
            return jsonify(orch.script_status(p.public_id) or {"status": "none", "log": ""})
        except Exception as exc:  # noqa: BLE001
            return jsonify(error=str(exc)), 502

    @app.route("/browsers/<int:profile_id>/scripts/stop", methods=["POST"])
    @login_required
    def browser_script_stop(profile_id):
        p = _own(profile_id)
        orch.stop_script(p.public_id)
        return jsonify(ok=True)

    # ------------------------------------------------------------------ wtyczki
    @app.route("/browsers/extensions")
    @login_required
    def browser_extensions():
        exts = BrowserExtension.query.filter_by(owner_id=current_user.id).order_by(BrowserExtension.name).all()
        return render_template("browser_extensions.html", exts=exts, user=current_user,
                               max_mb=br.MAX_EXT_BYTES // (1024 * 1024))

    @app.route("/browsers/extensions/store", methods=["POST"])
    @login_required
    def browser_extension_store():
        ext_id = br.parse_store_id(request.form.get("store", ""))
        if not ext_id:
            flash("Podaj ID wtyczki (32 litery a–p) albo link ze sklepu Chrome Web Store.", "error")
            return redirect(url_for("browser_extensions"))
        if BrowserExtension.query.filter_by(owner_id=current_user.id, ext_id=ext_id).first():
            flash("Ta wtyczka jest już na liście.", "error")
            return redirect(url_for("browser_extensions"))
        name = request.form.get("name", "").strip()[:120] or ext_id
        db.session.add(BrowserExtension(owner_id=current_user.id, name=name, kind="store", ext_id=ext_id))
        db.session.commit()
        flash("Dodano. Zaznacz ją w profilu i zrestartuj sesję — Chromium pobierze ją ze sklepu.", "success")
        return redirect(url_for("browser_extensions"))

    @app.route("/browsers/extensions/upload", methods=["POST"])
    @login_required
    def browser_extension_upload():
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Wybierz plik .zip lub .crx.", "error")
            return redirect(url_for("browser_extensions"))
        if request.content_length and request.content_length > br.MAX_EXT_BYTES + 1024 * 1024:
            flash("Plik jest za duży.", "error")
            return redirect(url_for("browser_extensions"))
        dirname = secrets.token_hex(6)
        dest = os.path.join(br.EXT_LOCAL_DIR, dirname)
        try:
            manifest = br.unpack_extension(f.read(br.MAX_EXT_BYTES + 1), dest)
        except br.BrowserError as exc:
            shutil.rmtree(dest, ignore_errors=True)
            flash(str(exc), "error")
            return redirect(url_for("browser_extensions"))
        except OSError as exc:
            shutil.rmtree(dest, ignore_errors=True)
            flash(f"Nie udało się zapisać wtyczki: {exc}", "error")
            return redirect(url_for("browser_extensions"))
        name = request.form.get("name", "").strip()[:120]
        mname = str(manifest.get("name", ""))
        if not name:
            name = f.filename[:120] if mname.startswith("__MSG_") or not mname else mname[:120]
        db.session.add(BrowserExtension(owner_id=current_user.id, name=name, kind="upload", dirname=dirname))
        db.session.commit()
        flash("Wtyczka wgrana. Zaznacz ją w profilu i zrestartuj sesję.", "success")
        return redirect(url_for("browser_extensions"))

    @app.route("/browsers/extensions/<int:ext_id>/delete", methods=["POST"])
    @login_required
    def browser_extension_delete(ext_id):
        e = db.session.get(BrowserExtension, ext_id) or abort(404)
        if e.owner_id != current_user.id:
            abort(403)
        for p in BrowserProfile.query.filter_by(owner_id=e.owner_id).all():
            if e.id in p.ext_list:
                p.extension_ids = json.dumps([x for x in p.ext_list if x != e.id])
        if e.kind == "upload" and e.dirname:
            shutil.rmtree(os.path.join(br.EXT_LOCAL_DIR, e.dirname), ignore_errors=True)
        db.session.delete(e)
        db.session.commit()
        flash("Wtyczka usunięta z listy (sesje uruchomione ją jeszcze mają do restartu).", "success")
        return redirect(url_for("browser_extensions"))

    # ------------------------------------------------------------------ auth dla nginx
    _AUTH_RE = re.compile(r"^(?:/[^/]+)?/br/([0-9a-f]{12})(?:[/?]|$)")

    @app.route("/_br_auth")
    def br_auth():
        """Wołane przez nginx (auth_request) przy każdym żądaniu do /br/<id>/."""
        if not current_user.is_authenticated:
            return "", 401
        if not has_access():
            return "", 403
        m = _AUTH_RE.match(request.headers.get("X-Original-URI", ""))
        if not m:
            return "", 400
        p = BrowserProfile.query.filter_by(public_id=m.group(1)).first()
        if not p or not _can_view(p):
            return "", 403
        return "", 200

    # ------------------------------------------------------------------ sweeper
    def sweep_once():
        """Jeden obieg: sprząta skrypty, usypia porzucone sesje, usuwa sieroty."""
        if db.engine.dialect.name == "postgresql":
            got = db.session.execute(text("SELECT pg_try_advisory_xact_lock(727002)")).scalar()
            if not got:
                db.session.rollback()
                return
        orch.sweep_runners()
        sessions = orch.sessions()
        profiles = {p.public_id: p for p in BrowserProfile.query.all()}
        now = datetime.utcnow()
        for pid, s in sessions.items():
            p = profiles.get(pid)
            if p is None:
                orch.stop(pid)                       # sesja usuniętego profilu
                continue
            if s["state"] != "running" or p.background or p.idle_minutes <= 0:
                continue
            n = orch.viewers(pid)
            if n is None:
                continue                             # nie wiemy - nie ubijamy
            if n > 0 or p.last_viewer_at is None:
                p.last_viewer_at = now
            elif now - p.last_viewer_at > timedelta(minutes=p.idle_minutes):
                app.logger.info("Sesja %s bezczynna > %d min - zatrzymuję", pid, p.idle_minutes)
                orch.stop(pid)
        db.session.commit()

    def _loop():
        while True:
            time.sleep(SWEEP_SECONDS)
            try:
                with app.app_context():
                    sweep_once()
            except Exception as exc:  # noqa: BLE001
                app.logger.warning("Sweeper przeglądarek: %s", exc)
                try:
                    with app.app_context():
                        db.session.rollback()
                except Exception:  # noqa: BLE001
                    pass

    if os.environ.get("BROWSER_SWEEP", "1") == "1":
        threading.Thread(target=_loop, name="browser-sweeper", daemon=True).start()

    return {"BrowserProfile": BrowserProfile, "BrowserExtension": BrowserExtension, "sweep_once": sweep_once}
