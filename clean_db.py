from app import app, db, User

with app.app_context():
    print("🧹 Cleaning database...")
    users = User.query.all()
    count = 0
    for u in users:
        if u.username and u.username != u.username.strip():
            print(f"   Fixing: '{u.username}' -> '{u.username.strip()}'")
            u.username = u.username.strip()
            count += 1
    
    if count > 0:
        db.session.commit()
        print(f"✅ Fixed {count} usernames!")
    else:
        print("✨ Database is already clean.")
