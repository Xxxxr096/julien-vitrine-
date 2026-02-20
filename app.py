from flask import Flask, render_template, request, url_for, flash, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import requests
from flask_bcrypt import Bcrypt
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
import re
import logging
from logging.handlers import RotatingFileHandler
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf

app = Flask(__name__)

load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    basedir, "database.db"
)


db = SQLAlchemy(app)
bycrypt = Bcrypt(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(256), nullable=False)

    newsletter = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Fonction


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def generate_confirmation_token(email):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="confirm-email")


def confirm_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="confirm-email", max_age=expiration)
    except:
        return None
    return email


def generate_reset_token(email):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="reset-password")


def confirm_reset_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="reset-password", max_age=expiration)
    except:
        return None
    return email


def send_reset_email(email, reset_url):
    sender_email = os.getenv("MAIL_USER")
    sender_password = os.getenv("MAIL_PASSWORD")

    subject = "Réinitialisation de votre mot de passe — LBG Santé Formation"

    html_message = f"""
    <html>
    <body style="font-family:Poppins,Arial,sans-serif;background:#f6f8ff;padding:40px;">
      <div style="max-width:600px;margin:auto;background:white;
                  border-radius:16px;padding:32px;
                  box-shadow:0 20px 50px rgba(15,23,42,0.15);">

        <h2 style="color:#1E2A5A;font-family:Orbitron,Arial;">
          Réinitialisation du mot de passe
        </h2>

        <p style="color:#0f172a;font-size:15px;line-height:1.6;">
          Vous avez demandé la réinitialisation de votre mot de passe pour votre compte
          <strong>LBG Santé Formation</strong>.<br><br>

          Cliquez sur le bouton ci-dessous pour définir un nouveau mot de passe.
        </p>

        <div style="text-align:center;margin:32px 0;">
          <a href="{reset_url}"
             style="background:#B33A2B;color:white;
                    padding:14px 26px;text-decoration:none;
                    border-radius:10px;font-weight:800;
                    display:inline-block;">
            Réinitialiser mon mot de passe
          </a>
        </div>

        <p style="font-size:13px;color:#475569;">
          ⏳ Ce lien est valable pendant <strong>1 heure</strong>.<br>
          Si vous n’êtes pas à l’origine de cette demande, ignorez simplement cet email.
        </p>

        <hr style="border:none;height:1px;background:#e5e7eb;margin:28px 0;">

        <p style="font-size:12px;color:#64748b;text-align:center;">
          © 2026 LBG Santé Formation<br>
          Prévention • Mouvement • Santé durable
        </p>
      </div>
    </body>
    </html>
    """

    msg = MIMEText(html_message, "html")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.send_message(msg)


# Route pour la page d'accueil
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")  # tu peux créer un fichier minimal


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nom = request.form["last_name"]
        prenom = request.form["first_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Checkbox newsletter
        newsletter = "newsletter" in request.form
        terms_accepted = "terms" in request.form
        if not terms_accepted:
            flash(
                "Vous devez accepter les conditions générales pour créer un compte.",
                "error",
            )
            return redirect(url_for("login"))

        # Vérifications
        if not is_valid_email(email):
            flash("Adresse e-mail invalide.", "error")
            return redirect(url_for("login"))

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(url_for("login"))

        if User.query.filter_by(email=email).first():
            flash("Un compte existe déjà avec cet email.", "error")
            return redirect(url_for("login"))

        # Hash du mot de passe
        hashed_pw = bycrypt.generate_password_hash(password).decode("utf-8")

        # Création utilisateur
        new_user = User(
            last_name=nom,
            first_name=prenom,
            email=email,
            password=hashed_pw,
            newsletter=newsletter,
            confirmed=False,
        )

        db.session.add(new_user)
        db.session.commit()

        # Génération du token de confirmation
        token = generate_confirmation_token(email)
        confirm_url = url_for("confirm_email", token=token, _external=True)

        # Contenu du mail (HTML pro)
        sender_email = os.getenv("MAIL_USER")
        sender_password = os.getenv("MAIL_PASSWORD")

        subject = "Confirmez votre compte — LBG Santé Formation"

        html_message = f"""
        <html>
        <body style="font-family:Poppins,Arial,sans-serif;background:#f6f8ff;padding:40px;">
          <div style="max-width:600px;margin:auto;background:white;
                      border-radius:16px;padding:32px;
                      box-shadow:0 20px 50px rgba(15,23,42,0.15);">

            <h2 style="color:#1E2A5A;font-family:Orbitron,Arial;">
              Bienvenue sur <span style="color:#B33A2B;">LBG Santé Formation</span>
            </h2>

            <p style="color:#0f172a;font-size:15px;line-height:1.6;">
              Merci pour votre inscription 👋<br><br>
              Pour activer votre compte et accéder à votre espace personnel,
              veuillez confirmer votre adresse email en cliquant sur le bouton ci-dessous.
            </p>

            <div style="text-align:center;margin:32px 0;">
              <a href="{confirm_url}"
                 style="background:#B33A2B;color:white;
                        padding:14px 26px;text-decoration:none;
                        border-radius:10px;font-weight:800;
                        display:inline-block;">
                Confirmer mon compte
              </a>
            </div>

            <p style="font-size:13px;color:#475569;">
              Si vous n’êtes pas à l’origine de cette inscription,
              vous pouvez ignorer ce message.
            </p>

            <hr style="border:none;height:1px;background:#e5e7eb;margin:28px 0;">

            <p style="font-size:12px;color:#64748b;text-align:center;">
              © 2026 LBG Santé Formation<br>
              Prévention • Mouvement • Santé durable
            </p>
          </div>
        </body>
        </html>
        """

        msg = MIMEText(html_message, "html")
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.set_debuglevel(1)
                server.login(sender_email, sender_password)
                server.send_message(msg)
        except Exception as e:
            flash(
                "Compte créé, mais l'email de confirmation n'a pas pu être envoyé.",
                "warning",
            )
            return redirect(url_for("login"))

        flash(
            "Compte créé avec succès. Un email de confirmation vous a été envoyé.",
            "success",
        )
        return redirect(url_for("login"))

    return redirect(url_for("login"))


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("Lien Invalide ou expiré.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Utilisateur Introuvable.", "error")
        return redirect(url_for("login"))

    if user.confirmed:
        flash("Ton compte est déja confirmé.", "info")
    else:
        user.confirmed = True
        user.confirmed_at = datetime.utcnow()
        db.session.commit()
        flash("Ton compte a été crée avec succés.", "success")

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        remember = "remember" in request.form

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email ou mot de passe incorrect.", "error")
            return redirect(url_for("login"))

        if not bycrypt.check_password_hash(user.password, password):
            flash("Email ou mot de passe incorrect.", "error")
            return redirect(url_for("login"))

        if not user.confirmed:
            flash(
                "Veuillez confirmer votre adresse email avant de vous connecter.",
                "warning",
            )
            return redirect(url_for("login"))

        login_user(user, remember=remember)
        flash("Connexion réussie 🎉", "success")
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        user = User.query.filter_by(email=email).first()

        # Toujours message générique (sécurité)
        if not user:
            flash(
                "Si un compte est associé à cet email, un message de réinitialisation sera envoyé.",
                "info",
            )
            return redirect(url_for("login"))

        # Génération du token
        token = generate_reset_token(email)
        reset_url = url_for("reset_password", token=token, _external=True)

        try:
            send_reset_email(email, reset_url)
        except Exception as e:
            flash(
                "Une erreur est survenue lors de l’envoi de l’email. Veuillez réessayer plus tard.",
                "error",
            )
            return redirect(url_for("forgot_password"))

        flash(
            "Un email de réinitialisation vous a été envoyé. Vérifiez votre boîte mail.",
            "success",
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash("Lien invalide ou expiré.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(request.url)

        user.password = bycrypt.generate_password_hash(password).decode("utf-8")
        db.session.commit()

        flash("Mot de passe modifié avec succès 🔐", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie 👋", "info")
    return redirect(url_for("home"))


# Contact
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        # Honeypot anti-spam (champ caché côté HTML)
        hp = request.form.get("website", "").strip()
        if hp:
            # On fait comme si tout allait bien (ne pas aider les bots)
            flash("Message envoyé ✅", "success")
            return redirect(url_for("contact"))

        # Validations
        if not name or len(name) < 2:
            flash("Veuillez indiquer votre nom.", "error")
            return redirect(url_for("contact"))

        if not is_valid_email(email):
            flash("Adresse e-mail invalide.", "error")
            return redirect(url_for("contact"))

        if not subject:
            flash("Veuillez sélectionner un sujet.", "error")
            return redirect(url_for("contact"))

        if not message or len(message) < 10:
            flash("Votre message est trop court (min. 10 caractères).", "error")
            return redirect(url_for("contact"))

        if len(message) > 5000:
            flash("Votre message est trop long (max. 5000 caractères).", "error")
            return redirect(url_for("contact"))

        # Prépare email
        sender_email = os.getenv("MAIL_USER")
        sender_password = os.getenv("MAIL_PASSWORD")

        if not sender_email or not sender_password:
            flash("Configuration email manquante côté serveur.", "error")
            return redirect(url_for("contact"))

        # Tu peux remplacer par une adresse dédiée si tu veux
        receiver_email = os.getenv("CONTACT_RECEIVER", sender_email)

        mail_subject = f"[Contact LBG] {subject} — {name}"

        safe_phone = phone if phone else "Non renseigné"

        html_message = f"""
        <html>
        <body style="font-family:Poppins,Arial,sans-serif;background:#f6f8ff;padding:40px;">
          <div style="max-width:680px;margin:auto;background:white;
                      border-radius:16px;padding:32px;
                      box-shadow:0 20px 50px rgba(15,23,42,0.15);">

            <h2 style="color:#1E2A5A;font-family:Orbitron,Arial;margin:0 0 12px;">
              Nouveau message — <span style="color:#B33A2B;">LBG Santé Formation</span>
            </h2>

            <p style="color:#0f172a;font-size:14px;line-height:1.6;margin:0 0 18px;">
              Vous avez reçu un nouveau message depuis la page <strong>Contact</strong>.
            </p>

            <div style="background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
              <p style="margin:0 0 10px;"><strong>Nom :</strong> {name}</p>
              <p style="margin:0 0 10px;"><strong>Email :</strong> {email}</p>
              <p style="margin:0 0 10px;"><strong>Téléphone :</strong> {safe_phone}</p>
              <p style="margin:0;"><strong>Sujet :</strong> {subject}</p>
            </div>

            <h3 style="color:#1E2A5A;margin:22px 0 10px;font-family:Orbitron,Arial;">
              Message
            </h3>

            <div style="white-space:pre-wrap;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;color:#0f172a;line-height:1.6;">
              {message}
            </div>

            <hr style="border:none;height:1px;background:#e5e7eb;margin:28px 0;">

            <p style="font-size:12px;color:#64748b;text-align:center;margin:0;">
              © 2026 LBG Santé Formation — Prévention • Mouvement • Santé durable
            </p>
          </div>
        </body>
        </html>
        """

        msg = MIMEText(html_message, "html", "utf-8")
        msg["Subject"] = mail_subject
        msg["From"] = sender_email
        msg["To"] = receiver_email
        # Permet de répondre directement au client depuis ton mail
        msg["Reply-To"] = email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, sender_password)
                server.send_message(msg)
        except Exception:
            flash(
                "Une erreur est survenue lors de l’envoi. Réessayez plus tard.", "error"
            )
            return redirect(url_for("contact"))

        flash("Message envoyé ✅ Nous vous répondrons rapidement.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html")


if __name__ == "__main__":
    # Mode debug activé pour voir les modifications en temps réel
    app.run(debug=True, port=5000)
