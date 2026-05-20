import os
from dotenv import load_dotenv

# Load environment variables from .env file BEFORE importing config
load_dotenv()

from flask import Flask, render_template
from flask_login import LoginManager
from models import db, User
from config import config
from auth_routes import auth_bp
from main_routes import main_bp
from encryption_routes import encryption_bp
from password_routes import password_bp
from sharing_routes import sharing_bp

def create_app(config_name='development'):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    # Create upload folders
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)
    os.makedirs(app.config['DECRYPTED_FOLDER'], exist_ok=True)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(encryption_bp)
    app.register_blueprint(password_bp)
    app.register_blueprint(sharing_bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template('errors/500.html'), 500

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html'), 403

    # Context processors
    @app.context_processor
    def inject_user():
        from flask_login import current_user
        return {'current_user': current_user}

    # Create database tables and seed data if needed
    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app('development')
    app.run(debug=True, host='127.0.0.1', port=5000)
