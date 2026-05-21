"""Notification service for real-time updates via WebSocket"""

from flask_socketio import emit, join_room, leave_room
from models import db, ShareNotification, User
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for managing real-time notifications"""

    @staticmethod
    def emit_share_notification(recipient_id, shared_file, sender, action='shared'):
        """
        Emit real-time notification when file is shared

        Args:
            recipient_id: ID of recipient user
            shared_file: SharedFile object
            sender: User object (sender)
            action: Type of action (shared, revoked, accessed, etc.)
        """
        try:
            # Create notification record
            if action == 'shared':
                message = f"{sender.username} shared file '{shared_file.encrypted_file.original_filename}' with you"
            elif action == 'revoked':
                message = f"{sender.username} revoked access to '{shared_file.encrypted_file.original_filename}'"
            elif action == 'expired':
                message = f"Share for '{shared_file.encrypted_file.original_filename}' has expired"
            elif action == 'accessed':
                message = f"Your shared file '{shared_file.encrypted_file.original_filename}' was accessed"
            else:
                message = f"File sharing update: {action}"

            notification = ShareNotification(
                recipient_id=recipient_id,
                shared_file_id=shared_file.id,
                sender_id=sender.id if sender else None,
                notification_type=action,
                message=message
            )

            db.session.add(notification)
            db.session.commit()

            # Emit real-time WebSocket event
            emit('notification:new', {
                'id': notification.id,
                'type': action,
                'message': message,
                'sender': sender.username if sender else 'System',
                'file_name': shared_file.encrypted_file.original_filename,
                'timestamp': notification.created_at.isoformat(),
                'icon': NotificationService._get_icon_for_action(action),
                'color': NotificationService._get_color_for_action(action)
            }, room=recipient_id)

            logger.info(f"Notification emitted to {recipient_id}: {action}")
            return notification

        except Exception as e:
            logger.error(f"Error emitting share notification: {str(e)}")
            return None

    @staticmethod
    def emit_access_notification(owner_id, accessor_name, file_name, access_type='viewed'):
        """
        Emit real-time notification when shared file is accessed

        Args:
            owner_id: ID of file owner
            accessor_name: Name of person accessing
            file_name: Name of file
            access_type: Type of access (viewed, downloaded, etc.)
        """
        try:
            message = f"{accessor_name} {access_type} your shared file '{file_name}'"

            notification = ShareNotification(
                recipient_id=owner_id,
                notification_type='accessed',
                message=message
            )

            db.session.add(notification)
            db.session.commit()

            emit('notification:access', {
                'message': message,
                'accessor': accessor_name,
                'file_name': file_name,
                'action': access_type,
                'timestamp': notification.created_at.isoformat(),
                'icon': 'eye' if access_type == 'viewed' else 'download',
                'color': 'info'
            }, room=owner_id)

            logger.info(f"Access notification emitted to {owner_id}")
            return notification

        except Exception as e:
            logger.error(f"Error emitting access notification: {str(e)}")
            return None

    @staticmethod
    def emit_otp_notification(user_id, file_name, otp_code=None):
        """
        Emit OTP sent notification

        Args:
            user_id: User ID
            file_name: File name
            otp_code: OTP code (if in test mode)
        """
        try:
            message = f"OTP sent for accessing '{file_name}'. Check your email for the verification code."

            emit('notification:otp', {
                'message': message,
                'file_name': file_name,
                'timestamp': datetime.now().isoformat(),
                'icon': 'key',
                'color': 'warning'
            }, room=user_id)

            logger.info(f"OTP notification emitted to {user_id}")

        except Exception as e:
            logger.error(f"Error emitting OTP notification: {str(e)}")

    @staticmethod
    def emit_security_alert(user_id, alert_type, message, severity='medium'):
        """
        Emit security alert notification

        Args:
            user_id: User ID
            alert_type: Type of alert
            message: Alert message
            severity: Severity level (low, medium, high, critical)
        """
        try:
            emit('notification:security', {
                'type': alert_type,
                'message': message,
                'severity': severity,
                'timestamp': datetime.now().isoformat(),
                'icon': 'shield-exclamation' if severity == 'high' else 'shield-alert',
                'color': 'danger' if severity == 'high' else 'warning'
            }, room=user_id)

            logger.info(f"Security alert emitted to {user_id}: {alert_type}")

        except Exception as e:
            logger.error(f"Error emitting security alert: {str(e)}")

    @staticmethod
    def emit_dashboard_update(user_id, stats):
        """
        Emit real-time dashboard update

        Args:
            user_id: User ID
            stats: Dictionary with updated statistics
        """
        try:
            emit('dashboard:update', {
                'stats': stats,
                'timestamp': datetime.now().isoformat()
            }, room=user_id)

            logger.info(f"Dashboard update emitted to {user_id}")

        except Exception as e:
            logger.error(f"Error emitting dashboard update: {str(e)}")

    @staticmethod
    def emit_share_analytics_update(user_id, share_id, analytics):
        """
        Emit share analytics update

        Args:
            user_id: User ID
            share_id: Share ID
            analytics: Analytics data
        """
        try:
            emit('share:analytics-update', {
                'share_id': share_id,
                'analytics': analytics,
                'timestamp': datetime.now().isoformat()
            }, room=user_id)

            logger.info(f"Share analytics update emitted to {user_id} for share {share_id}")

        except Exception as e:
            logger.error(f"Error emitting share analytics update: {str(e)}")

    @staticmethod
    def subscribe_to_share_updates(user_id, share_id):
        """
        Subscribe user to share-specific updates

        Args:
            user_id: User ID
            share_id: Share ID
        """
        try:
            room_name = f"share_{share_id}"
            join_room(room_name)
            logger.info(f"User {user_id} subscribed to {room_name}")

        except Exception as e:
            logger.error(f"Error subscribing to share updates: {str(e)}")

    @staticmethod
    def unsubscribe_from_share_updates(user_id, share_id):
        """
        Unsubscribe user from share-specific updates

        Args:
            user_id: User ID
            share_id: Share ID
        """
        try:
            room_name = f"share_{share_id}"
            leave_room(room_name)
            logger.info(f"User {user_id} unsubscribed from {room_name}")

        except Exception as e:
            logger.error(f"Error unsubscribing from share updates: {str(e)}")

    @staticmethod
    def get_user_notifications(user_id, limit=10, unread_only=False):
        """
        Get notifications for user

        Args:
            user_id: User ID
            limit: Number of notifications to retrieve
            unread_only: Get only unread notifications

        Returns:
            List of notifications
        """
        try:
            query = ShareNotification.query.filter_by(recipient_id=user_id)

            if unread_only:
                query = query.filter_by(is_read=False)

            notifications = query.order_by(ShareNotification.created_at.desc()).limit(limit).all()

            return [
                {
                    'id': n.id,
                    'type': n.notification_type,
                    'message': n.message,
                    'sender': n.sender.username if n.sender else 'System',
                    'is_read': n.is_read,
                    'created_at': n.created_at.isoformat(),
                    'icon': NotificationService._get_icon_for_action(n.notification_type),
                    'color': NotificationService._get_color_for_action(n.notification_type)
                }
                for n in notifications
            ]

        except Exception as e:
            logger.error(f"Error retrieving notifications: {str(e)}")
            return []

    @staticmethod
    def mark_notification_as_read(notification_id, user_id):
        """
        Mark notification as read

        Args:
            notification_id: Notification ID
            user_id: User ID

        Returns:
            Boolean indicating success
        """
        try:
            notification = ShareNotification.query.filter_by(
                id=notification_id,
                recipient_id=user_id
            ).first()

            if notification:
                notification.is_read = True
                notification.read_at = datetime.utcnow()
                db.session.commit()
                return True

            return False

        except Exception as e:
            logger.error(f"Error marking notification as read: {str(e)}")
            return False

    @staticmethod
    def _get_icon_for_action(action):
        """Get icon for notification type"""
        icons = {
            'shared': 'share-2',
            'accessed': 'eye',
            'downloaded': 'download',
            'revoked': 'lock',
            'expired': 'clock',
            'failed_otp': 'alert-circle',
            'verified': 'check-circle'
        }
        return icons.get(action, 'bell')

    @staticmethod
    def _get_color_for_action(action):
        """Get color for notification type"""
        colors = {
            'shared': 'success',
            'accessed': 'info',
            'downloaded': 'primary',
            'revoked': 'warning',
            'expired': 'warning',
            'failed_otp': 'danger',
            'verified': 'success'
        }
        return colors.get(action, 'info')
