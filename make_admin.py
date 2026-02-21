from app import app, db, bycrypt, User
from datetime import datetime


def make_admin(
    email: str,
    password: str,
    first_name="Admin",
    last_name="LBG",
    force_password_change=True,
):
    email = email.strip().lower()

    with app.app_context():
        user = User.query.filter_by(email=email).first()

        hashed_pw = bycrypt.generate_password_hash(password).decode("utf-8")

        if user:
            # Mise à jour du compte existant
            user.first_name = first_name
            user.last_name = last_name
            user.password = hashed_pw

            user.confirmed = True
            user.confirmed_at = datetime.utcnow()

            user.is_admin = True
            user.must_change_password = bool(force_password_change)

            db.session.commit()
            print(f"✅ Admin mis à jour : {email}")
            return

        # Création nouveau compte admin
        new_admin = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_pw,
            newsletter=False,
            confirmed=True,
            confirmed_at=datetime.utcnow(),
            is_admin=True,
            must_change_password=bool(force_password_change),
        )

        db.session.add(new_admin)
        db.session.commit()
        print(f"✅ Admin créé : {email}")


if __name__ == "__main__":
    # ---- MODIFIE ICI ----
    admin_email = "francestrasbourg06@gmail.com"
    admin_password = "Amine"
    admin_first_name = "Admin"
    admin_last_name = "LBG"

    make_admin(
        admin_email,
        admin_password,
        first_name=admin_first_name,
        last_name=admin_last_name,
        force_password_change=False,  # mets True si tu veux forcer à changer au premier login
    )
