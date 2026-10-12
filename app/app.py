import os
import time
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import OperationalError


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

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_PATH"] = "/"

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


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


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

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    vms = VMInstance.query.order_by(VMInstance.name).all()
    return render_template("dashboard.html", vms=vms, user=current_user)


@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


def wait_for_db_and_init():
    max_retries = 20
    for attempt in range(1, max_retries + 1):
        try:
            with app.app_context():
                db.create_all()

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
