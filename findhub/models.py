from datetime import datetime

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class MissingPerson(db.Model):
    __tablename__ = "missing_people"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False, index=True)
    age = db.Column(db.Integer, nullable=False, index=True)
    disappearance_date = db.Column(db.Date, nullable=False, index=True)
    last_known_location = db.Column(db.String(255), nullable=False, index=True)
    physical_description = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(255), nullable=False)
    reporter_contact = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="desaparecido", index=True)

    # Token de exclusão
    # - hash scrypt do token (nunca o token em texto puro)
    # - expira em 1 ano após o cadastro
    # - contador de tentativas inválidas (bloqueia após 10)
    deletion_token_hash = db.Column(db.String(128), nullable=True)
    deletion_token_expires_at = db.Column(db.DateTime, nullable=True)
    deletion_token_attempts = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class AdminActionLog(db.Model):
    __tablename__ = "admin_action_logs"

    id = db.Column(db.Integer, primary_key=True)
    admin_username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    record_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class DeletionRequest(db.Model):
    __tablename__ = "deletion_requests"

    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey("missing_people.id"), nullable=False)
    justification = db.Column(db.Text, nullable=False)
    # pendente, aprovado, rejeitado
    status = db.Column(db.String(20), nullable=False, default="pendente")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
