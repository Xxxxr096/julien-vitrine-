from app import db, app

with app.app_context():
    db.create_all()
    print("Les tables sont crée")
