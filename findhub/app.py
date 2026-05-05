import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4
import hvac

import bcrypt
from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for
from sqlalchemy import and_
from werkzeug.utils import secure_filename

from models import AdminActionLog, AdminUser, MissingPerson, db


ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024


app = Flask(__name__)

def carregar_segredos_vault():
    """
    Busca as credenciais do Vault na inicializacao da aplicacao.
    O token findhub-backend tem permissao so de leitura em findhub/backend/*.
    """
    vault_addr = os.getenv("VAULT_ADDR", "https://192.168.2.50:8200")
    vault_token = os.getenv("VAULT_TOKEN")
    vault_cacert = os.getenv("VAULT_CACERT", "/certs/vault.crt")

    if not vault_token:
        raise RuntimeError("A variavel VAULT_TOKEN e obrigatoria.")

    cliente = hvac.Client(
        url=vault_addr,
        token=vault_token,
        verify=vault_cacert
    )

    if not cliente.is_authenticated():
        raise RuntimeError("Vault: token invalido ou Vault selado.")

    db = cliente.secrets.kv.v2.read_secret_version(
        path="backend/db",
        mount_point="findhub"
    )["data"]["data"]

    app_secrets = cliente.secrets.kv.v2.read_secret_version(
        path="backend/app",
        mount_point="findhub"
    )["data"]["data"]

    return {
        "DB_HOST": db["host"],
        "DB_PORT": db["port"],
        "DB_NAME": db["dbname"],
        "DB_USER": db["user"],
        "DB_PASSWORD": db["password"],
        "SECRET_KEY": app_secrets["secret_key"],
        "ADMIN_PASSWORD": app_secrets["admin_password"],
    }


segredos = carregar_segredos_vault()

secret_key = segredos["SECRET_KEY"]
db_host = segredos["DB_HOST"]
db_port = segredos["DB_PORT"]
db_name = segredos["DB_NAME"]
db_user = segredos["DB_USER"]
db_password = segredos["DB_PASSWORD"]

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = str(Path(__file__).resolve().parent / "static" / "uploads")

if not all([db_host, db_name, db_user, db_password]):
    raise RuntimeError("As variáveis DB_HOST, DB_NAME, DB_USER e DB_PASSWORD são obrigatórias.")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

db.init_app(app)


def _log_action(action: str, record_id=None, details=None):
    admin_username = session.get("admin_username", "system")
    db.session.add(
        AdminActionLog(
            admin_username=admin_username,
            action=action,
            record_id=record_id,
            details=details,
        )
    )
    db.session.commit()


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


@app.route("/")
def index():
    return redirect(url_for("cadastro"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/lgpd")
def lgpd():
    last_updated = datetime.now().strftime("%d/%m/%Y")
    return render_template("lgpd.html", last_updated=last_updated)


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        if not request.form.get("aceite_lgpd"):
            flash("Você precisa aceitar a Política de Privacidade.", "error")
            return redirect(url_for("cadastro"))

        full_name = request.form.get("full_name", "").strip()
        age_raw = request.form.get("age", "").strip()
        disappearance_date_raw = request.form.get("disappearance_date", "").strip()
        last_known_location = request.form.get("last_known_location", "").strip()
        physical_description = request.form.get("physical_description", "").strip()
        reporter_contact = request.form.get("reporter_contact", "").strip()
        photo = request.files.get("photo")

        if not all([
            full_name,
            age_raw,
            disappearance_date_raw,
            last_known_location,
            physical_description,
            reporter_contact,
            photo,
        ]):
            flash("Preencha todos os campos.", "error")
            return redirect(url_for("cadastro"))

        try:
            age = int(age_raw)
            if age < 0 or age > 130:
                raise ValueError
        except ValueError:
            flash("Idade inválida.", "error")
            return redirect(url_for("cadastro"))

        try:
            disappearance_date = datetime.strptime(disappearance_date_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Data inválida.", "error")
            return redirect(url_for("cadastro"))

        if not photo.filename or not _allowed_file(photo.filename):
            flash("Formato de imagem inválido. Use JPG ou PNG.", "error")
            return redirect(url_for("cadastro"))

        extension = secure_filename(photo.filename).rsplit(".", 1)[1].lower()
        photo_filename = f"{uuid4().hex}.{extension}"
        photo_path = Path(app.config["UPLOAD_FOLDER"]) / photo_filename
        photo.save(photo_path)

        missing_person = MissingPerson(
            full_name=full_name,
            age=age,
            disappearance_date=disappearance_date,
            last_known_location=last_known_location,
            physical_description=physical_description,
            photo_filename=photo_filename,
            reporter_contact=reporter_contact,
        )
        db.session.add(missing_person)
        db.session.commit()

        flash("Registro enviado com sucesso.", "success")
        return render_template("cadastro.html", deletion_token=missing_person.deletion_token)

    return render_template("cadastro.html", deletion_token=None)


@app.route("/solicitar-exclusao/<int:person_id>", methods=["POST"])
def solicitar_exclusao(person_id):
    token = request.form.get("token", "").strip()
    reason = request.form.get("reason", "").strip()

    if not token or not reason:
        flash("Preencha o código e a justificativa.", "error")
        return redirect(url_for("busca"))

    person = MissingPerson.query.get(person_id)
    if not person or person.deletion_token != token:
        flash("Código inválido.", "error")
        return redirect(url_for("busca"))

    if person.deletion_requested:
        flash("Já existe uma solicitação de exclusão pendente para este registro.", "error")
        return redirect(url_for("busca"))

    person.deletion_requested = True
    person.deletion_reason = reason
    db.session.commit()

    _log_action("deletion_requested", record_id=person.id, details=f"Solicitação de exclusão: {reason}")
    flash("Solicitação enviada. A equipe administrativa irá analisar seu pedido.", "success")
    return redirect(url_for("busca"))


@app.route("/busca", methods=["GET"])
def busca():
    filters = []

    name = request.args.get("name", "").strip()
    age_raw = request.args.get("age", "").strip()
    location = request.args.get("location", "").strip()
    date_raw = request.args.get("date", "").strip()

    if name:
        filters.append(MissingPerson.full_name.ilike(f"%{name}%"))
    if age_raw:
        try:
            filters.append(MissingPerson.age == int(age_raw))
        except ValueError:
            flash("Filtro de idade inválido.", "error")
    if location:
        filters.append(MissingPerson.last_known_location.ilike(f"%{location}%"))
    if date_raw:
        try:
            filters.append(MissingPerson.disappearance_date == datetime.strptime(date_raw, "%Y-%m-%d").date())
        except ValueError:
            flash("Filtro de data inválido.", "error")

    query = MissingPerson.query
    if filters:
        query = query.filter(and_(*filters))

    people = query.order_by(MissingPerson.disappearance_date.desc()).all()
    return render_template("busca.html", people=people)


def _admin_authenticated() -> bool:
    return bool(session.get("admin_authenticated") and session.get("admin_username"))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST" and request.form.get("form_type") == "login":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = AdminUser.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            session["admin_authenticated"] = True
            session["admin_username"] = username
            flash("Autenticação realizada.", "success")
            _log_action("login", details="Login no painel administrativo")
            return redirect(url_for("admin"))

        flash("Credenciais inválidas.", "error")
        return redirect(url_for("admin"))

    if request.method == "POST" and request.form.get("form_type") == "logout":
        if _admin_authenticated():
            _log_action("logout", details="Logout do painel administrativo")
        session.clear()
        flash("Sessão encerrada.", "success")
        return redirect(url_for("admin"))

    if request.method == "POST" and not _admin_authenticated():
        flash("Faça login para continuar.", "error")
        return redirect(url_for("admin"))

    if request.method == "POST":
        action = request.form.get("action")
        person_id = request.form.get("person_id")

        person = MissingPerson.query.get(person_id)
        if not person:
            flash("Registro não encontrado.", "error")
            return redirect(url_for("admin"))

        if action == "mark_found":
            person.status = "encontrado"
            db.session.commit()
            _log_action("mark_found", record_id=person.id, details=f"{person.full_name} marcado como encontrado")
            flash("Status atualizado para encontrado.", "success")

        elif action == "edit":
            person.full_name = request.form.get("full_name", person.full_name).strip()
            person.age = int(request.form.get("age", person.age))
            person.last_known_location = request.form.get("last_known_location", person.last_known_location).strip()
            date_value = request.form.get("disappearance_date", str(person.disappearance_date))
            person.disappearance_date = datetime.strptime(date_value, "%Y-%m-%d").date()
            person.physical_description = request.form.get("physical_description", person.physical_description).strip()
            person.reporter_contact = request.form.get("reporter_contact", person.reporter_contact).strip()
            db.session.commit()
            _log_action("edit", record_id=person.id, details=f"Registro de {person.full_name} editado")
            flash("Registro atualizado.", "success")

        elif action == "delete":
            photo_path = Path(app.config["UPLOAD_FOLDER"]) / person.photo_filename
            db.session.delete(person)
            db.session.commit()
            if photo_path.exists():
                photo_path.unlink()
            _log_action("delete", record_id=int(person_id), details="Registro excluído")
            flash("Registro excluído.", "success")

        elif action == "approve_deletion":
            photo_path = Path(app.config["UPLOAD_FOLDER"]) / person.photo_filename
            db.session.delete(person)
            db.session.commit()
            if photo_path.exists():
                photo_path.unlink()
            _log_action("approve_deletion", record_id=int(person_id), details=f"Exclusão aprovada: {person.full_name}")
            flash("Exclusão aprovada e registro removido.", "success")

        elif action == "reject_deletion":
            person.deletion_requested = False
            person.deletion_reason = None
            db.session.commit()
            _log_action("reject_deletion", record_id=person.id, details=f"Exclusão rejeitada: {person.full_name}")
            flash("Solicitação de exclusão rejeitada.", "success")

        else:
            flash("Ação inválida.", "error")

        return redirect(url_for("admin"))

    people = MissingPerson.query.order_by(MissingPerson.created_at.desc()).all()
    pending = MissingPerson.query.filter_by(deletion_requested=True).all()
    logs = AdminActionLog.query.order_by(AdminActionLog.created_at.desc()).limit(20).all()

    return render_template(
        "admin.html",
        authenticated=_admin_authenticated(),
        people=people,
        pending=pending,
        logs=logs,
        admin_username=session.get("admin_username"),
    )


with app.app_context():
    db.create_all()

    default_admin_username = os.getenv("ADMIN_USERNAME", "admin")
    default_admin_password = os.getenv("ADMIN_PASSWORD")
    if not default_admin_password:
        raise RuntimeError("A variável ADMIN_PASSWORD é obrigatória.")

    admin_user = AdminUser.query.filter_by(username=default_admin_username).first()
    if not admin_user:
        password_hash = bcrypt.hashpw(default_admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.session.add(AdminUser(username=default_admin_username, password_hash=password_hash))
        db.session.commit()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)