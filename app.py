from flask import Flask
from sqlalchemy import text
from config import Config
from extensions import db, login_manager
from models import User


def _ensure_schema_updates():
    """Lightweight schema migration for hackathon demo updates."""
    vuln_columns = {
        row[1] for row in db.session.execute(text("PRAGMA table_info(vulnerability)")).fetchall()
    }
    if "mock_before_code" not in vuln_columns:
        db.session.execute(text("ALTER TABLE vulnerability ADD COLUMN mock_before_code TEXT"))
    if "mock_after_code" not in vuln_columns:
        db.session.execute(text("ALTER TABLE vulnerability ADD COLUMN mock_after_code TEXT"))
    if "fixed_at" not in vuln_columns:
        db.session.execute(text("ALTER TABLE vulnerability ADD COLUMN fixed_at DATETIME"))
    db.session.commit()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.demo_target import demo_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(demo_bp, url_prefix='/target')

    with app.app_context():
        # Create database
        db.create_all()
        _ensure_schema_updates()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
