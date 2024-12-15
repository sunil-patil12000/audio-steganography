from app import app, db, User

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()

        # Create an admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com'
            )
            admin.set_password('admin123')
            db.session.add(admin)

        # Create a test user
        if not User.query.filter_by(username='test').first():
            test_user = User(
                username='test',
                email='test@example.com'
            )
            test_user.set_password('test123')
            db.session.add(test_user)

        # Commit the changes
        db.session.commit()

if __name__ == '__main__':
    init_database()
    print("Database initialized successfully!") 