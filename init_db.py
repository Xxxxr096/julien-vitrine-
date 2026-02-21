from app import db, app, seed_articles

with app.app_context():
    db.create_all()
    seed_articles()
    print("Les tables sont crée")
