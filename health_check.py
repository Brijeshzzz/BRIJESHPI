import os
from app import app, db, User, ServiceRequest, ProviderProfile

def check_database_health():
    print("\n" + "="*50)
    print("🏥  BRIJESHPI SYSTEM HEALTH CHECK  🏥")
    print("="*50 + "\n")

    with app.app_context():
        # --- 1. CHECK USERS FOR DIRTY DATA ---
        print("🔍 CHECKING USERS...")
        users = User.query.all()
        dirty_users = []
        for u in users:
            issues = []
            if not u.username:
                issues.append("Missing Username")
            elif u.username != u.username.strip():
                issues.append(f"Hidden Spaces (Stored as '{u.username}')")
            
            if not u.email:
                issues.append("Missing Email")
            elif "@" not in u.email:
                issues.append(f"Invalid Email Format ('{u.email}')")
            
            if issues:
                dirty_users.append(f"User ID {u.id}: {', '.join(issues)}")

        if dirty_users:
            print(f"❌ Found {len(dirty_users)} user(s) with data issues:")
            for issue in dirty_users:
                print(f"   - {issue}")
            print("   👉 FIX: Run the cleanup command below to remove spaces.")
        else:
            print("✅ All User data looks clean.")

        # --- 2. CHECK SERVICE REQUESTS ---
        print("\n🔍 CHECKING SERVICE REQUESTS...")
        requests = ServiceRequest.query.all()
        orphaned_requests = [r for r in requests if not r.client_name]
        if orphaned_requests:
            print(f"⚠️ Found {len(orphaned_requests)} requests with missing names.")
        else:
            print("✅ All Service Requests have valid names.")

        # --- 3. CHECK PROVIDER PROFILES ---
        print("\n🔍 CHECKING PROVIDER PROFILES...")
        profiles = ProviderProfile.query.all()
        orphaned_profiles = []
        for p in profiles:
            parent = User.query.get(p.user_id)
            if not parent:
                orphaned_profiles.append(p.id)
        
        if orphaned_profiles:
            print(f"❌ Found {len(orphaned_profiles)} provider profiles linked to deleted users (IDs: {orphaned_profiles}).")
        else:
            print("✅ Provider links are healthy.")

        # --- 4. CHECK ENVIRONMENT ---
        print("\n🔍 CHECKING ENVIRONMENT...")
        if not os.getenv("GROQ_API_KEY"):
            print("⚠️ WARNING: GROQ_API_KEY is missing. Chatbot will crash.")
        else:
            print("✅ GROQ_API_KEY is found.")
        
        print("\n" + "="*50)
        print("DONE.")
        print("="*50 + "\n")

if __name__ == "__main__":
    check_database_health()
