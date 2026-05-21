import os
from dotenv import load_dotenv

# Load environment variables from .env file BEFORE importing config
load_dotenv()

from flask import Flask, render_template
from flask_login import LoginManager
from flask_socketio import SocketIO
from models import db, User
from config import config
from auth_routes import auth_bp
from main_routes import main_bp
from encryption_routes import encryption_bp
from password_routes import password_bp
from sharing_routes import sharing_bp
from services.email_service import mail
from utils.rate_limiter import limiter, configure_rate_limiting

def create_app(config_name='development'):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    # Initialize Flask-SocketIO
    socketio = SocketIO(
        app,
        cors_allowed_origins=app.config.get('SOCKETIO_CORS_ALLOWED_ORIGINS', ['*']),
        async_mode=app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet'),
        ping_timeout=120,
        ping_interval=25
    )

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

    # Register Socket.IO event handlers
    register_socketio_handlers(socketio, app)

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

    return app, socketio


def register_socketio_handlers(socketio, app):
    """Register Socket.IO event handlers"""
    from flask import session, request
    from flask_login import current_user, disconnect
    import logging

    logger = logging.getLogger(__name__)

    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        if not current_user.is_authenticated:
            disconnect()
            return False

        logger.info(f"Client connected: {current_user.username}")
        socketio.emit('notification:connected', {
            'message': 'Connected to real-time notifications',
            'user': current_user.username
        })

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        if current_user.is_authenticated:
            logger.info(f"Client disconnected: {current_user.username}")

    @socketio.on('subscribe_share_updates')
    def handle_subscribe_share_updates(data):
        """Subscribe to share-specific updates"""
        if not current_user.is_authenticated:
            return False

        share_id = data.get('share_id')
        if share_id:
            room_name = f"share_{share_id}"
            socketio.join_room(room_name, skip_sid=True)
            logger.info(f"User {current_user.id} subscribed to {room_name}")
            socketio.emit('notification:subscribed', {
                'share_id': share_id,
                'message': f'Subscribed to updates for share {share_id}'
            })

    @socketio.on('unsubscribe_share_updates')
    def handle_unsubscribe_share_updates(data):
        """Unsubscribe from share-specific updates"""
        if not current_user.is_authenticated:
            return False

        share_id = data.get('share_id')
        if share_id:
            room_name = f"share_{share_id}"
            socketio.leave_room(room_name, skip_sid=True)
            logger.info(f"User {current_user.id} unsubscribed from {room_name}")

    @socketio.on('get_notifications')
    def handle_get_notifications():
        """Get user notifications"""
        if not current_user.is_authenticated:
            return False

        from services.notification_service import NotificationService

        notifications = NotificationService.get_user_notifications(current_user.id, limit=10)
        socketio.emit('notification:list', {
            'notifications': notifications,
            'count': len(notifications)
        })

    @socketio.on('mark_notification_read')
    def handle_mark_notification_read(data):
        """Mark notification as read"""
        if not current_user.is_authenticated:
            return False

        notification_id = data.get('notification_id')
        from services.notification_service import NotificationService

        if NotificationService.mark_notification_as_read(notification_id, current_user.id):
            socketio.emit('notification:read', {
                'notification_id': notification_id,
                'success': True
            })


if __name__ == '__main__':
    app, socketio = create_app('development')
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)

