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
database_url = os.getenv("SCALINGO_POSTGRESQL_URL") or os.getenv("DATABASE_URL")

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///" + os.path.join(
    basedir, "database.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


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
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    slug = db.Column(db.String(180), unique=True, nullable=False, index=True)

    title = db.Column(db.String(220), nullable=False)
    excerpt = db.Column(db.Text, nullable=False)  # aperçu court
    content_html = db.Column(db.Text, nullable=False)  # contenu complet (HTML)
    cover_image = db.Column(db.String(600), nullable=True)

    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class NewsletterCampaign(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    name = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    content_text = db.Column(db.Text, nullable=False)

    frequency = db.Column(db.String(20), nullable=False, default="weekly")
    # daily / weekly / monthly

    start_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    end_date = db.Column(db.DateTime, nullable=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    last_sent_at = db.Column(db.DateTime, nullable=True)
    next_send_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class NewsletterSendLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    campaign_id = db.Column(
        db.Integer, db.ForeignKey("newsletter_campaign.id"), nullable=False
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(50), default="sent", nullable=False)
    error_message = db.Column(db.Text, nullable=True)


# Fonction
from functools import wraps
from flask import abort


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


import secrets
import string


def generate_temp_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def send_admin_invite_email(email, temp_password, reset_url):
    sender_email = os.getenv("MAIL_USER")
    sender_password = os.getenv("MAIL_PASSWORD")

    subject = "Invitation Admin — LBG Santé Formation"

    html_message = f"""
    <html>
    <body style="font-family:Poppins,Arial,sans-serif;background:#f6f8ff;padding:40px;">
      <div style="max-width:600px;margin:auto;background:white;border-radius:16px;padding:32px;
                  box-shadow:0 20px 50px rgba(15,23,42,0.15);">
        <h2 style="color:#1E2A5A;font-family:Orbitron,Arial;">
          Invitation Admin — <span style="color:#B33A2B;">LBG Santé Formation</span>
        </h2>

        <p style="color:#0f172a;font-size:15px;line-height:1.6;">
          Vous avez été invité(e) à rejoindre l’espace <strong>Administration</strong>.
          <br><br>
          <strong>Identifiant :</strong> {email}<br>
          <strong>Mot de passe temporaire :</strong> {temp_password}
        </p>

        <p style="color:#0f172a;font-size:15px;line-height:1.6;">
          Pour sécuriser votre compte, veuillez définir immédiatement un nouveau mot de passe :
        </p>

        <div style="text-align:center;margin:26px 0;">
          <a href="{reset_url}"
             style="background:#2D8C86;color:white;padding:14px 26px;text-decoration:none;
                    border-radius:10px;font-weight:800;display:inline-block;">
            Définir mon mot de passe
          </a>
        </div>

        <p style="font-size:13px;color:#475569;">
          ⏳ Ce lien est valable pendant <strong>1 heure</strong>.
        </p>

        <hr style="border:none;height:1px;background:#e5e7eb;margin:28px 0;">
        <p style="font-size:12px;color:#64748b;text-align:center;">
          © 2026 LBG Santé Formation — Prévention • Mouvement • Santé durable
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
        server.set_debuglevel(1)
        server.login(sender_email, sender_password)
        server.send_message(msg)


def seed_articles():
    if Article.query.first():
        return

    a1 = Article(
        slug="bouger-plus-sit-less",
        title="Bouger plus, s’asseoir moins : les bases solides",
        excerpt="Les recommandations internationales insistent : toute activité compte. Voici comment transformer ça en habitudes simples au quotidien.",
        cover_image="https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1600&q=80",
        content_html="""
        <h3>Pourquoi c’est important</h3>
        <p>Les recommandations de santé publique rappellent que bouger régulièrement et réduire la sédentarité améliore la santé globale.</p>
        <h3>Ce que vous pouvez appliquer</h3>
        <ul>
          <li>Des “micro-pauses” actives toutes les 45–60 minutes</li>
          <li>Un objectif simple : plus de pas + 2 séances renfo/semaine</li>
          <li>Une routine courte mobilité (3–6 minutes)</li>
        </ul>
        <h3>Sources</h3>
        <ul>
          <li>WHO – Physical activity (2024)</li>
          <li>WHO 2020 Guidelines (Bull et al.)</li>
        </ul>
        """,
    )

    a2 = Article(
        slug="lever-porter-sans-se-casser",
        title="Lever / porter sans se casser : repères biomécaniques",
        excerpt="Le risque ne dépend pas seulement du poids. Distance, posture, répétition et hauteur changent tout. Voici des repères clairs.",
        cover_image="https://images.unsplash.com/photo-1584467735871-8f8b2d98d4c4?auto=format&fit=crop&w=1600&q=80",
        content_html="""
        <h3>Le point clé</h3>
        <p>La méthode RNLE (NIOSH) montre que la distance, la hauteur, l’asymétrie et la fréquence influencent fortement le risque lombaire.</p>
        <h3>Repères terrain</h3>
        <ul>
          <li>Rapprocher la charge</li>
          <li>Réduire la torsion (pivoter avec les pieds)</li>
          <li>Optimiser la hauteur (éviter très bas / très haut)</li>
          <li>Limiter répétition + ajouter pauses</li>
        </ul>
        <h3>Sources</h3>
        <ul>
          <li>CDC/NIOSH – Revised NIOSH Lifting Equation</li>
          <li>Étude RNLE & risque lombaire (PMC)</li>
        </ul>
        """,
    )

    a3 = Article(
        slug="exercice-lombalgie-chronique",
        title="Exercice et lombalgie chronique : ce que dit la synthèse",
        excerpt="L’exercice est généralement utile dans la lombalgie chronique. Voici comment choisir simple et progressif.",
        cover_image="https://images.unsplash.com/photo-1599058917765-3d3e8f55f4f2?auto=format&fit=crop&w=1600&q=80",
        content_html="""
        <h3>Ce qu’on retient</h3>
        <p>Les synthèses de la littérature indiquent que l’exercice est globalement plus efficace que l’absence d’intervention habituelle pour la douleur dans la lombalgie chronique.</p>
        <h3>Application pratique</h3>
        <ul>
          <li>Commencer bas (2–3 exercices) et progresser</li>
          <li>Prioriser régularité > intensité</li>
          <li>Choisir des exercices tolérés, sans flare-up</li>
        </ul>
        <h3>Source</h3>
        <ul>
          <li>Cochrane – Exercise for treatment of chronic low back pain</li>
        </ul>
        """,
    )

    db.session.add_all([a1, a2, a3])
    db.session.commit()


with app.app_context():
    db.create_all()
    seed_articles()


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


from urllib.parse import urlparse, urljoin


def is_safe_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def calculate_next_send_at(current_date, frequency):
    if frequency == "daily":
        return current_date + timedelta(days=1)
    elif frequency == "weekly":
        return current_date + timedelta(weeks=1)
    elif frequency == "monthly":
        return current_date + timedelta(days=30)
    return None


def send_newsletter_email(to_email, subject, html_content):
    sender_email = os.getenv("MAIL_USER")
    sender_password = os.getenv("MAIL_PASSWORD")

    msg = MIMEText(html_content, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.send_message(msg)


def send_campaign_now(campaign):
    recipients = User.query.filter_by(
        is_admin=False, newsletter=True, confirmed=True
    ).all()

    for user in recipients:
        try:
            unsubscribe_url = url_for(
                "unsubscribe_newsletter", user_id=user.id, _external=True
            )

            message_text = campaign.content_text or ""
            message_text = message_text.replace("{{first_name}}", user.first_name or "")
            message_text = message_text.replace("{{last_name}}", user.last_name or "")
            message_text = message_text.replace("{{email}}", user.email or "")

            # transformer les retours à la ligne en <br>
            message_html = message_text.replace("\n", "<br>")

            # lien de désinscription ajouté automatiquement
            final_html = f"""
            <html>
            <body style="font-family:Poppins,Arial,sans-serif;background:#f6f8ff;padding:40px;">
              <div style="max-width:600px;margin:auto;background:white;border-radius:16px;padding:32px;
                          box-shadow:0 20px 50px rgba(15,23,42,0.15);">

                <h2 style="color:#1E2A5A;font-family:Orbitron,Arial;">
                  LBG Santé Formation
                </h2>

                <div style="color:#0f172a;font-size:15px;line-height:1.7;">
                  {message_html}
                </div>

                <hr style="border:none;height:1px;background:#e5e7eb;margin:28px 0;">

                <p style="font-size:13px;color:#64748b;">
                  Vous recevez cet email car vous avez accepté de recevoir les actualités de LBG Santé Formation.
                </p>

                <p style="margin-top:18px;">
                  <a href="{unsubscribe_url}" style="color:#B33A2B;font-weight:700;">
                    Se désinscrire
                  </a>
                </p>

                <p style="font-size:12px;color:#64748b;text-align:center;margin-top:28px;">
                  © 2026 LBG Santé Formation — Prévention • Mouvement • Santé durable
                </p>
              </div>
            </body>
            </html>
            """

            send_newsletter_email(
                to_email=user.email, subject=campaign.subject, html_content=final_html
            )

            log = NewsletterSendLog(
                campaign_id=campaign.id, user_id=user.id, status="sent"
            )
            db.session.add(log)

        except Exception as e:
            log = NewsletterSendLog(
                campaign_id=campaign.id,
                user_id=user.id,
                status="failed",
                error_message=str(e),
            )
            db.session.add(log)

    now = datetime.utcnow()
    campaign.last_sent_at = now
    campaign.next_send_at = calculate_next_send_at(now, campaign.frequency)

    # On laisse la campagne active tant que la date de fin n'est pas dépassée
    if campaign.end_date and now >= campaign.end_date:
        campaign.is_active = False

    db.session.commit()


def process_due_campaigns():
    now = datetime.utcnow()

    campaigns = NewsletterCampaign.query.filter(
        NewsletterCampaign.is_active == True,
        NewsletterCampaign.next_send_at.isnot(None),
        NewsletterCampaign.next_send_at <= now,
    ).all()

    processed = 0

    for campaign in campaigns:
        if campaign.end_date and now > campaign.end_date:
            campaign.is_active = False
            db.session.commit()
            continue

        send_campaign_now(campaign)
        processed += 1

    return processed


# Route pour la page d'accueil
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/articles")
def articles():
    items = (
        Article.query.filter_by(published=True)
        .order_by(Article.created_at.desc())
        .all()
    )
    return render_template("articles.html", articles=items)


@app.route("/articles/<slug>")
def article_detail(slug):
    art = Article.query.filter_by(slug=slug, published=True).first_or_404()
    return render_template("article_detail.html", article=art)


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

        if getattr(user, "must_change_password", False):
            flash("Veuillez définir un nouveau mot de passe (sécurité).", "warning")
            token = generate_reset_token(user.email)
            return redirect(url_for("reset_password", token=token))

        flash("Connexion réussie 🎉", "success")

        # ✅ priorité 1 : next (si safe)
        next_url = request.args.get("next")
        if next_url and is_safe_url(next_url):
            return redirect(next_url)

        # ✅ priorité 2 : admin -> dashboard admin
        if getattr(user, "is_admin", False):
            return redirect(url_for("admin_dashboard"))

        # ✅ sinon accueil
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
        user.must_change_password = False

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


# Admin
@app.route("/admin")
@admin_required
def admin_dashboard():
    return redirect(url_for("admin_articles"))


@app.route("/admin/articles")
@admin_required
def admin_articles():
    items = Article.query.order_by(Article.created_at.desc()).all()
    return render_template("admin/articles.html", articles=items)


@app.route("/admin/articles/new", methods=["GET", "POST"])
@admin_required
def admin_article_new():
    if request.method == "POST":
        title = request.form["title"].strip()
        slug = request.form["slug"].strip()
        excerpt = request.form["excerpt"].strip()
        cover_image = request.form.get("cover_image", "").strip() or None
        content_html = request.form["content_html"]

        if Article.query.filter_by(slug=slug).first():
            flash("Slug déjà utilisé.", "error")
            return redirect(url_for("admin_article_new"))

        art = Article(
            title=title,
            slug=slug,
            excerpt=excerpt,
            cover_image=cover_image,
            content_html=content_html,
            published=("published" in request.form),
        )
        db.session.add(art)
        db.session.commit()
        flash("Article créé ✅", "success")
        return redirect(url_for("admin_articles"))

    return render_template("admin/article_new.html")


@app.route("/admin/articles/<int:article_id>/delete", methods=["POST"])
@admin_required
def admin_article_delete(article_id):
    art = Article.query.get_or_404(article_id)
    db.session.delete(art)
    db.session.commit()
    flash("Article supprimé 🗑️", "info")
    return redirect(url_for("admin_articles"))


@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()

    users_count = User.query.filter_by(is_admin=False).count()
    newsletter_count = User.query.filter_by(is_admin=False, newsletter=True).count()

    return render_template(
        "admin/users.html",
        users=users,
        users_count=users_count,
        newsletter_count=newsletter_count,
    )


@app.route("/admin/admins", methods=["GET", "POST"])
@admin_required
def admin_admins():

    # 👉 Liste admins uniquement
    admins = User.query.filter_by(is_admin=True).order_by(User.created_at.desc()).all()

    # 👉 Compteurs
    admins_count = User.query.filter_by(is_admin=True).count()
    must_change_count = User.query.filter_by(
        is_admin=True, must_change_password=True
    ).count()

    # ========================
    # INVITATION ADMIN
    # ========================
    if request.method == "POST":

        email = request.form["email"].strip().lower()
        first_name = request.form.get("first_name", "").strip() or "Admin"
        last_name = request.form.get("last_name", "").strip() or "Invité"

        # Validation email
        if not is_valid_email(email):
            flash("Email invalide.", "error")
            return redirect(url_for("admin_admins"))

        # Email déjà existant
        if User.query.filter_by(email=email).first():
            flash("Un compte existe déjà avec cet email.", "warning")
            return redirect(url_for("admin_admins"))

        # Mot de passe temporaire
        temp_password = generate_temp_password(12)
        hashed_pw = bycrypt.generate_password_hash(temp_password).decode("utf-8")

        new_admin = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_pw,
            confirmed=True,
            confirmed_at=datetime.utcnow(),
            is_admin=True,
            must_change_password=True,
        )

        db.session.add(new_admin)
        db.session.commit()

        # Lien reset password
        token = generate_reset_token(email)
        reset_url = url_for("reset_password", token=token, _external=True)

        try:
            send_admin_invite_email(email, temp_password, reset_url)
            flash("Invitation admin envoyée ✅", "success")
        except Exception as e:
            print("Erreur mail admin :", e)
            flash("Admin créé mais email non envoyé.", "warning")

        return redirect(url_for("admin_admins"))

    # ========================
    # AFFICHAGE PAGE
    # ========================
    return render_template(
        "admin/admins.html",
        admins=admins,
        admins_count=admins_count,
        must_change_count=must_change_count,
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_user_delete(user_id):
    u = User.query.get_or_404(user_id)

    # ✅ Empêche de te supprimer toi-même
    if u.id == current_user.id:
        flash("Tu ne peux pas supprimer ton propre compte.", "error")
        return redirect(url_for("admin_users"))

    # ✅ Optionnel : empêcher suppression d’un admin
    if u.is_admin:
        flash("Suppression impossible : c’est un compte admin.", "warning")
        return redirect(url_for("admin_users"))

    db.session.delete(u)
    db.session.commit()
    flash("Utilisateur supprimé 🗑️", "info")
    return redirect(url_for("admin_users"))


from datetime import datetime, timedelta


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    # Compteurs
    users_count = User.query.filter_by(is_admin=False).count()
    admins_count = User.query.filter_by(is_admin=True).count()
    newsletter_count = User.query.filter_by(is_admin=False, newsletter=True).count()
    articles_count = Article.query.filter_by(published=True).count()

    confirmed_users = User.query.filter_by(is_admin=False, confirmed=True).count()
    unconfirmed_users = User.query.filter_by(is_admin=False, confirmed=False).count()

    # Série 30 jours : inscriptions utilisateurs (hors admins)
    today = datetime.utcnow().date()
    start_day = today - timedelta(days=29)

    # Récupère tous les users créés dans les 30 jours (hors admins)
    recent = (
        User.query.filter(User.is_admin == False)
        .filter(User.created_at >= datetime.combine(start_day, datetime.min.time()))
        .all()
    )

    # Bucket par jour
    counts_by_day = {(start_day + timedelta(days=i)).isoformat(): 0 for i in range(30)}

    for u in recent:
        d = u.created_at.date().isoformat()
        if d in counts_by_day:
            counts_by_day[d] += 1

    labels = list(counts_by_day.keys())
    values = list(counts_by_day.values())

    return render_template(
        "admin/analytics.html",
        users_count=users_count,
        admins_count=admins_count,
        newsletter_count=newsletter_count,
        articles_count=articles_count,
        confirmed_users=confirmed_users,
        unconfirmed_users=unconfirmed_users,
        labels=labels,
        values=values,
    )


@app.route("/unsubscribe-newsletter/<int:user_id>")
def unsubscribe_newsletter(user_id):
    user = User.query.get_or_404(user_id)

    if not user.newsletter:
        flash("Vous êtes déjà désinscrit de la newsletter.", "info")
        return redirect(url_for("home"))

    user.newsletter = False
    db.session.commit()

    flash("Vous avez bien été désinscrit de la newsletter.", "success")
    return redirect(url_for("home"))


@app.route("/admin/newsletters")
@admin_required
def admin_newsletters():
    campaigns = NewsletterCampaign.query.order_by(
        NewsletterCampaign.created_at.desc()
    ).all()

    campaigns_count = NewsletterCampaign.query.count()
    active_campaigns_count = NewsletterCampaign.query.filter_by(is_active=True).count()
    subscribers_count = User.query.filter_by(
        is_admin=False, newsletter=True, confirmed=True
    ).count()

    return render_template(
        "admin/newsletters.html",
        campaigns=campaigns,
        campaigns_count=campaigns_count,
        active_campaigns_count=active_campaigns_count,
        subscribers_count=subscribers_count,
    )


@app.route("/admin/newsletters/new", methods=["GET", "POST"])
@admin_required
def admin_newsletter_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        subject = request.form.get("subject", "").strip()
        content_text = request.form.get("content_text", "").strip()
        frequency = request.form.get("frequency", "weekly").strip()

        duration_value = request.form.get("duration_value", "1").strip()
        duration_unit = request.form.get("duration_unit", "weeks").strip()

        if not name or not subject or not content_text:
            flash("Tous les champs sont obligatoires.", "error")
            return redirect(url_for("admin_newsletter_new"))

        try:
            duration_value = int(duration_value)
            if duration_value < 1:
                duration_value = 1
        except ValueError:
            duration_value = 1

        start_date = datetime.utcnow()

        if duration_unit == "days":
            end_date = start_date + timedelta(days=duration_value)
        elif duration_unit == "weeks":
            end_date = start_date + timedelta(weeks=duration_value)
        elif duration_unit == "months":
            end_date = start_date + timedelta(days=30 * duration_value)
        else:
            end_date = None

        campaign = NewsletterCampaign(
            name=name,
            subject=subject,
            content_text=content_text,
            frequency=frequency,
            start_date=start_date,
            end_date=end_date,
            is_active=True,
            next_send_at=start_date,
        )

        db.session.add(campaign)
        db.session.commit()

        flash("Newsletter créée avec succès ✅", "success")
        return redirect(url_for("admin_newsletters"))

    return render_template("admin/newsletter_new.html", active="newsletters")


@app.route("/admin/newsletters/<int:campaign_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_newsletter_edit(campaign_id):
    campaign = NewsletterCampaign.query.get_or_404(campaign_id)

    if request.method == "POST":
        campaign.name = request.form.get("name", "").strip()
        campaign.subject = request.form.get("subject", "").strip()
        campaign.content_text = request.form.get("content_text", "").strip()
        campaign.frequency = request.form.get("frequency", "weekly").strip()
        campaign.is_active = "is_active" in request.form

        db.session.commit()
        flash("Newsletter modifiée avec succès ✏️", "success")
        return redirect(url_for("admin_newsletters"))

    return render_template(
        "admin/newsletter_edit.html",
        campaign=campaign,
        active="newsletters",
    )


@app.route("/admin/newsletters/<int:campaign_id>/send", methods=["POST"])
@admin_required
def admin_newsletter_send_now(campaign_id):
    campaign = NewsletterCampaign.query.get_or_404(campaign_id)

    try:
        send_campaign_now(campaign)
        flash("Newsletter envoyée aux abonnés ✅", "success")
    except Exception as e:
        flash(f"Erreur pendant l'envoi : {str(e)}", "error")

    return redirect(url_for("admin_newsletters"))


@app.route("/admin/newsletters/<int:campaign_id>/delete", methods=["POST"])
@admin_required
def admin_newsletter_delete(campaign_id):
    campaign = NewsletterCampaign.query.get_or_404(campaign_id)

    NewsletterSendLog.query.filter_by(campaign_id=campaign.id).delete()
    db.session.delete(campaign)
    db.session.commit()

    flash("Newsletter supprimée 🗑️", "info")
    return redirect(url_for("admin_newsletters"))


@app.route("/admin/newsletters/<int:campaign_id>/logs")
@admin_required
def admin_newsletter_logs(campaign_id):
    campaign = NewsletterCampaign.query.get_or_404(campaign_id)
    logs = (
        NewsletterSendLog.query.filter_by(campaign_id=campaign.id)
        .order_by(NewsletterSendLog.sent_at.desc())
        .all()
    )

    return render_template(
        "admin/newsletter_logs.html",
        campaign=campaign,
        logs=logs,
    )


@app.route("/cron/process-newsletters", methods=["POST"])
def cron_process_newsletters():
    token = request.headers.get("X-CRON-TOKEN")
    secret = os.getenv("CRON_SECRET_TOKEN")

    if token != secret:
        abort(401)

    processed = process_due_campaigns()
    return {"processed": processed}, 200


if __name__ == "__main__":
    # Mode debug activé pour voir les modifications en temps réel
    app.run(debug=True, port=5000)
