import hashlib
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import bcrypt
from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for
from sqlalchemy import and_
from werkzeug.utils import secure_filename

from models import AdminActionLog, AdminUser, DeletionRequest, MissingPerson, db


ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024

# Número máximo de tentativas de token antes de bloquear o registro
# Depois disso o registrante precisa contatar o admin
TOKEN_MAX_ATTEMPTS = 10

# Tempo de vida do token de exclusão em dias
TOKEN_LIFETIME_DAYS = 365

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("A variável SECRET_KEY é obrigatória.")

app.config["SECRET_KEY"] = secret_key
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = str(Path(__file__).resolve().parent / "static" / "uploads")

db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME")
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")

if not all([db_host, db_name, db_user, db_password]):
    raise RuntimeError("As variáveis DB_HOST, DB_NAME, DB_USER e DB_PASSWORD são obrigatórias.")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# pool_pre_ping: reconecta automaticamente se o PostgreSQL derrubar conexões idle
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
db.init_app(app)


# ─── helpers de segurança ─────────────────────────────────────────────────────

def _hash_token(token: str) -> str:
    """
    Hash do token com scrypt.

    Por que scrypt e não SHA-256?
    SHA-256 é rápido — uma GPU moderna faz bilhões por segundo.
    Se o banco vazar, um atacante com os hashes pode tentar força bruta.
    scrypt é deliberadamente lento e exige muita memória RAM,
    tornando esse ataque caro mesmo com hardware dedicado.

    Parâmetros escolhidos:
    - n=2^14 (16384): custo de CPU/memória. Dobrar n dobra o tempo.
    - r=8, p=1: padrão recomendado pelo RFC 7914.
    - dklen=64: 512 bits de saída, representados em hex (128 chars).
    """
    dk = hashlib.scrypt(
        token.encode(),
        salt=b"findhub-deletion-token",  # salt fixo — ok aqui porque o token já tem 128 bits de entropia
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return dk.hex()


def _verify_token(token_informado: str, token_hash_armazenado: str) -> bool:
    """
    Compara o hash do token informado com o hash armazenado.

    secrets.compare_digest evita timing attacks:
    uma comparação normal (==) retorna False mais rápido quando os primeiros
    caracteres já diferem. Isso permitiria a um atacante medir o tempo de
    resposta e adivinhar caracteres do token um a um.
    compare_digest sempre leva o mesmo tempo, independente de onde a diferença está.
    """
    hash_calculado = _hash_token(token_informado)
    return secrets.compare_digest(hash_calculado, token_hash_armazenado)


def _log_action(action: str, record_id=None, details=None):
    admin_username = session.get("admin_username", "system")
    db.session.add(AdminActionLog(
        admin_username=admin_username,
        action=action,
        record_id=record_id,
        details=details,
    ))
    db.session.commit()


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _admin_authenticated() -> bool:
    return bool(session.get("admin_authenticated") and session.get("admin_username"))


# ─── headers de segurança ─────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


# ─── rotas ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("cadastro"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/lgpd")
def lgpd():
    return render_template("lgpd.html")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    token_gerado = None
    nome_cadastrado = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        age_raw = request.form.get("age", "").strip()
        disappearance_date_raw = request.form.get("disappearance_date", "").strip()
        last_known_location = request.form.get("last_known_location", "").strip()
        physical_description = request.form.get("physical_description", "").strip()
        reporter_contact = request.form.get("reporter_contact", "").strip()
        photo = request.files.get("photo")
        lgpd_consent = request.form.get("lgpd_consent")

        if not all([full_name, age_raw, disappearance_date_raw, last_known_location,
                    physical_description, reporter_contact, lgpd_consent]):
            flash("Para continuar, preencha todos os campos e confirme que leu e concorda com a Política de Privacidade do Findhub.", "error")
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

        foto_enviada = photo and photo.filename
        if foto_enviada:
            if not _allowed_file(photo.filename):
                flash("Formato de imagem inválido. Use JPG ou PNG.", "error")
                return redirect(url_for("cadastro"))
            extension = secure_filename(photo.filename).rsplit(".", 1)[1].lower()
            photo_filename = f"{uuid4().hex}.{extension}"
            photo_path = Path(app.config["UPLOAD_FOLDER"]) / photo_filename
            photo.save(photo_path)
        else:
            photo_filename = "sem_foto.png"

        # Gera token com 128 bits de entropia (32 chars hex)
        # secrets.token_hex usa o gerador criptograficamente seguro do sistema operacional
        token_gerado = secrets.token_hex(16)

        missing_person = MissingPerson(
            full_name=full_name,
            age=age,
            disappearance_date=disappearance_date,
            last_known_location=last_known_location,
            physical_description=physical_description,
            photo_filename=photo_filename,
            reporter_contact=reporter_contact,
            deletion_token_hash=_hash_token(token_gerado),
            deletion_token_expires_at=datetime.utcnow() + timedelta(days=TOKEN_LIFETIME_DAYS),
            deletion_token_attempts=0,
        )
        db.session.add(missing_person)
        db.session.commit()

        nome_cadastrado = full_name
        # Renderiza com o token — ele aparece aqui e nunca mais
        return render_template("cadastro.html", token_gerado=token_gerado, nome_cadastrado=nome_cadastrado)

    return render_template("cadastro.html", token_gerado=None, nome_cadastrado=None)


@app.route("/solicitar-exclusao", methods=["POST"])
def solicitar_exclusao():
    """
    Rota para o registrante solicitar exclusão do próprio registro.

    Segurança aplicada:
    1. Rate limiting no Nginx (config separada) — limita tentativas por IP
    2. Contador de tentativas por registro — bloqueia após TOKEN_MAX_ATTEMPTS
    3. Expiração do token — tokens com mais de 1 ano são recusados
    4. Resposta genérica — não revela se o registro existe ou se o token está errado
    5. compare_digest — evita timing attacks na comparação do hash
    6. scrypt — hash lento, dificulta força bruta mesmo com acesso ao banco
    """
    person_id = request.form.get("person_id", "").strip()
    token_informado = request.form.get("deletion_token", "").strip()
    justification = request.form.get("justification", "").strip()

    MSG_ERRO = "Token inválido, expirado ou registro não encontrado."

    if not all([person_id, token_informado, justification]):
        flash("Preencha todos os campos para solicitar a exclusão.", "error")
        return redirect(url_for("busca"))

    # Valida tamanho mínimo do token (32 chars hex)
    if len(token_informado) != 32:
        flash(MSG_ERRO, "error")
        return redirect(url_for("busca"))

    person = MissingPerson.query.get(person_id)

    # Resposta genérica para não revelar se o registro existe
    if not person or not person.deletion_token_hash:
        flash(MSG_ERRO, "error")
        return redirect(url_for("busca"))

    # Verifica se o token foi bloqueado por muitas tentativas inválidas
    if person.deletion_token_attempts >= TOKEN_MAX_ATTEMPTS:
        flash("Este registro está bloqueado para solicitações de exclusão por token. Entre em contato com o administrador.", "error")
        return redirect(url_for("busca"))

    # Verifica se o token expirou
    if person.deletion_token_expires_at and datetime.utcnow() > person.deletion_token_expires_at:
        flash(MSG_ERRO, "error")
        return redirect(url_for("busca"))

    # Verifica o token — incrementa contador antes de comparar para evitar race conditions
    person.deletion_token_attempts += 1
    db.session.commit()

    if not _verify_token(token_informado, person.deletion_token_hash):
        flash(MSG_ERRO, "error")
        return redirect(url_for("busca"))

    # Token válido — zera o contador de tentativas
    person.deletion_token_attempts = 0
    db.session.commit()

    # Verifica se já existe solicitação pendente
    existente = DeletionRequest.query.filter_by(person_id=person.id, status="pendente").first()
    if existente:
        flash("Já existe uma solicitação de exclusão pendente para este registro.", "error")
        return redirect(url_for("busca"))

    db.session.add(DeletionRequest(person_id=person.id, justification=justification))
    db.session.commit()

    flash("Solicitação de exclusão enviada. O administrador irá analisar em breve.", "success")
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

        if action in ("approve_deletion", "reject_deletion"):
            deletion_id = request.form.get("deletion_id")
            deletion_req = DeletionRequest.query.get(deletion_id)
            if not deletion_req:
                flash("Solicitação não encontrada.", "error")
                return redirect(url_for("admin"))

            if action == "approve_deletion":
                person = MissingPerson.query.get(deletion_req.person_id)
                if person:
                    photo_path = Path(app.config["UPLOAD_FOLDER"]) / person.photo_filename
                    _log_action("delete_via_token", record_id=person.id, details=f"Exclusão aprovada para {person.full_name}")
                    db.session.delete(person)
                deletion_req.status = "aprovado"
                db.session.commit()
                if person and photo_path.exists() and person.photo_filename != "sem_foto.png":
                    photo_path.unlink()
                flash("Solicitação aprovada. Registro excluído.", "success")
            else:
                deletion_req.status = "rejeitado"
                db.session.commit()
                flash("Solicitação rejeitada.", "success")
            return redirect(url_for("admin"))

        # Admin pode desbloquear token de um registro bloqueado por muitas tentativas
        if action == "unlock_token":
            person = MissingPerson.query.get(person_id)
            if person:
                person.deletion_token_attempts = 0
                db.session.commit()
                _log_action("unlock_token", record_id=person.id, details=f"Token de exclusão desbloqueado para {person.full_name}")
                flash("Token desbloqueado.", "success")
            return redirect(url_for("admin"))

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
            if photo_path.exists() and person.photo_filename != "sem_foto.png":
                photo_path.unlink()
            _log_action("delete", record_id=int(person_id), details="Registro excluído pelo admin")
            flash("Registro excluído.", "success")
        else:
            flash("Ação inválida.", "error")

        return redirect(url_for("admin"))

    people = MissingPerson.query.order_by(MissingPerson.created_at.desc()).all()
    logs = AdminActionLog.query.order_by(AdminActionLog.created_at.desc()).limit(20).all()
    deletion_requests = DeletionRequest.query.filter_by(status="pendente").order_by(DeletionRequest.created_at.desc()).all()

    return render_template(
        "admin.html",
        authenticated=_admin_authenticated(),
        people=people,
        logs=logs,
        admin_username=session.get("admin_username"),
        deletion_requests=deletion_requests,
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
