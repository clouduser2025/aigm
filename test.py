from app import db, app

with app.app_context():
    try:
        db.session.execute("SELECT 1")
        print("✅ Database is connected successfully!")
    except Exception as e:
        print("❌ Database connection failed:", str(e))
