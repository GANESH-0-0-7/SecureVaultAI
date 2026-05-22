"""File Sharing Service - Core business logic for secure file sharing"""

from datetime import datetime, timedelta
from models import db, SharedFile, AccessLog, User, EncryptedFile
from sharing_utils import ShareTokenGenerator, QRCodeGenerator, OTPManager
from services.notification_service import NotificationService
from services.email_service import EmailService
import logging
from flask import request

logger = logging.getLogger(__name__)


class SharingService:
    """Service for managing file sharing operations"""

    @staticmethod
    def create_share(file_id, owner_id, share_method, recipient_identifier=None, access_mode='view_only',
                     share_expiry_hours=24, max_access_count=None, otp_required=False, qr_options=None):
        """
        Create a new file share with specified method and options

        Args:
            file_id: Encrypted file ID
            owner_id: Owner/sender user ID
            share_method: Sharing method (otp, qrcode, user_id, link)
            recipient_identifier: Username/email/ID for user_id method
            access_mode: Access mode (view_only, download_only, full_access, locked)
            share_expiry_hours: Hours until share expires
            max_access_count: Max number of accesses (None for unlimited)
            otp_required: Whether to require OTP verification
            qr_options: QR-specific options dict

        Returns:
            Dictionary with share creation result
        """
        try:
            # Validate file exists and belongs to owner
            encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=owner_id).first()
            if not encrypted_file:
                return {
                    'success': False,
                    'message': 'File not found or unauthorized'
                }

            # Create shared file record
            shared_file = SharedFile(
                encrypted_file_id=file_id,
                owner_id=owner_id,
                share_method=share_method,
                sharing_token=ShareTokenGenerator.generate_share_token(),
                access_mode=access_mode,
                otp_required=otp_required,
                share_expiry=datetime.utcnow() + timedelta(hours=share_expiry_hours),
                max_access_count=int(max_access_count) if max_access_count else None,
                is_active=True
            )

            # Handle different sharing methods
            if share_method == 'otp':
                shared_file.otp_code = OTPManager.generate_otp(length=6)
                shared_file.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                shared_file.max_otp_attempts = 5

            elif share_method == 'qrcode':
                qr_token = ShareTokenGenerator.generate_qr_token(file_id, owner_id)
                shared_file.qr_token = qr_token
                qr_data = f"{request.host_url.rstrip('/')}
/sharing/access/qr/{qr_token}"
                shared_file.qr_code_data = QRCodeGenerator.generate_qr_code(qr_data)

            elif share_method == 'user_id':
                # Find recipient by username or ID
                recipient = User.query.filter_by(username=recipient_identifier).first()
                if not recipient:
                    recipient = User.query.filter_by(email=recipient_identifier).first()
                if not recipient:
                    recipient = User.query.filter_by(id=recipient_identifier).first()

                if not recipient:
                    return {
                        'success': False,
                        'message': 'Recipient not found'
                    }

                shared_file.recipient_id = recipient.id
                shared_file.recipient_email = recipient.email

            elif share_method == 'link':
                # Link-based sharing uses the share token
                pass

            # Save the share
            db.session.add(shared_file)
            db.session.commit()

            # Log the share event
            SharingService.log_share_event(
                action='share_created',
                share_id=shared_file.id,
                owner_id=owner_id,
                file_id=file_id,
                details=f'Share created via {share_method}'
            )

            # Send notifications
            if share_method == 'user_id' and shared_file.recipient_id:
                NotificationService.emit_share_notification(
                    recipient_id=shared_file.recipient_id,
                    shared_file=shared_file,
                    sender_name=User.query.get(owner_id).username,
                    action='shared'
                )
                try:
                    EmailService.send_share_notification(
                        recipient_email=shared_file.recipient_email,
                        sender_name=User.query.get(owner_id).username,
                        file_name=encrypted_file.original_filename,
                        access_level=access_mode,
                        share_link=f"{request.host_url.rstrip('/')}/sharing/access/{shared_file.sharing_token}"
                    )
                except Exception as e:
                    logger.error(f"Error sending share email: {str(e)}")

            return {
                'success': True,
                'message': 'File shared successfully',
                'share_id': shared_file.id,
                'sharing_token': shared_file.sharing_token,
                'qr_token': shared_file.qr_token,
                'qr_code': shared_file.qr_code_data,
                'otp_code': shared_file.otp_code if share_method == 'otp' else None,
                'expires_at': shared_file.share_expiry.isoformat()
            }

        except Exception as e:
            logger.error(f"Error creating share: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'message': 'Error creating share',
                'error': str(e)
            }

    @staticmethod
    def revoke_share(share_id, owner_id):
        """
        Revoke a file share

        Args:
            share_id: Share ID
            owner_id: Owner user ID (for authorization)

        Returns:
            Dictionary with result
        """
        try:
            shared_file = SharedFile.query.filter_by(id=share_id, owner_id=owner_id).first()

            if not shared_file:
                return {
                    'success': False,
                    'message': 'Share not found or unauthorized'
                }

            shared_file.is_active = False
            shared_file.updated_at = datetime.utcnow()
            db.session.commit()

            # Log the revocation
            SharingService.log_share_event(
                action='share_revoked',
                share_id=share_id,
                owner_id=owner_id,
                details='Share revoked by owner'
            )

            # Notify recipient if applicable
            if shared_file.recipient_id:
                NotificationService.emit_share_notification(
                    recipient_id=shared_file.recipient_id,
                    shared_file=shared_file,
                    sender_name=User.query.get(owner_id).username,
                    action='revoked'
                )

            logger.info(f"Share {share_id} revoked by owner {owner_id}")
            return {
                'success': True,
                'message': 'Share revoked successfully'
            }

        except Exception as e:
            logger.error(f"Error revoking share: {str(e)}")
            return {
                'success': False,
                'message': 'Error revoking share'
            }

    @staticmethod
    def extend_share_expiry(share_id, owner_id, additional_hours=24):
        """
        Extend share expiration

        Args:
            share_id: Share ID
            owner_id: Owner user ID
            additional_hours: Hours to add to expiration

        Returns:
            Dictionary with result
        """
        try:
            shared_file = SharedFile.query.filter_by(id=share_id, owner_id=owner_id).first()

            if not shared_file:
                return {
                    'success': False,
                    'message': 'Share not found or unauthorized'
                }

            old_expiry = shared_file.share_expiry
            shared_file.share_expiry = shared_file.share_expiry + timedelta(hours=additional_hours)
            db.session.commit()

            logger.info(f"Share {share_id} expiry extended from {old_expiry} to {shared_file.share_expiry}")
            return {
                'success': True,
                'message': 'Share expiration extended',
                'new_expiry': shared_file.share_expiry.isoformat()
            }

        except Exception as e:
            logger.error(f"Error extending share: {str(e)}")
            return {
                'success': False,
                'message': 'Error extending share'
            }

    @staticmethod
    def get_share_analytics(share_id, owner_id):
        """
        Get analytics for a shared file

        Args:
            share_id: Share ID
            owner_id: Owner user ID

        Returns:
            Dictionary with analytics
        """
        try:
            shared_file = SharedFile.query.filter_by(id=share_id, owner_id=owner_id).first()

            if not shared_file:
                return {
                    'success': False,
                    'message': 'Share not found'
                }

            access_logs = AccessLog.query.filter_by(shared_file_id=share_id).all()
            unique_ips = set(log.ip_address for log in access_logs)
            unique_users = set(log.user_id for log in access_logs if log.user_id)
            failed_attempts = len([log for log in access_logs if log.status == 'failed'])

            return {
                'success': True,
                'analytics': {
                    'total_accesses': shared_file.access_count,
                    'unique_ips': len(unique_ips),
                    'unique_users': len(unique_users),
                    'failed_attempts': failed_attempts,
                    'last_accessed': shared_file.last_accessed.isoformat() if shared_file.last_accessed else None,
                    'created_at': shared_file.created_at.isoformat(),
                    'expires_at': shared_file.share_expiry.isoformat() if shared_file.share_expiry else None,
                    'is_active': shared_file.is_active,
                    'access_count_remaining': (shared_file.max_access_count - shared_file.access_count) if shared_file.max_access_count else 'Unlimited'
                }
            }

        except Exception as e:
            logger.error(f"Error getting share analytics: {str(e)}")
            return {
                'success': False,
                'message': 'Error getting analytics'
            }

    @staticmethod
    def validate_access(share_id, user_id=None):
        """
        Validate if access to share is allowed

        Args:
            share_id: Share ID
            user_id: User ID attempting access

        Returns:
            Dictionary with validation result
        """
        try:
            shared_file = SharedFile.query.get(share_id)

            if not shared_file:
                return {
                    'valid': False,
                    'reason': 'share_not_found'
                }

            # Check if share is active
            if not shared_file.is_active:
                return {
                    'valid': False,
                    'reason': 'share_inactive'
                }

            # Check expiration
            if shared_file.share_expiry and datetime.utcnow() > shared_file.share_expiry:
                return {
                    'valid': False,
                    'reason': 'share_expired'
                }

            # Check access count
            if shared_file.max_access_count and shared_file.access_count >= shared_file.max_access_count:
                return {
                    'valid': False,
                    'reason': 'access_limit_exceeded'
                }

            # Check if user is recipient (for user_id method)
            if shared_file.share_method == 'user_id' and user_id and shared_file.recipient_id != user_id:
                return {
                    'valid': False,
                    'reason': 'unauthorized_recipient'
                }

            return {
                'valid': True,
                'share_id': share_id
            }

        except Exception as e:
            logger.error(f"Error validating access: {str(e)}")
            return {
                'valid': False,
                'reason': 'validation_error'
            }

    @staticmethod
    def log_access(shared_file_id, action, user_id=None, status='success', failure_reason=None):
        """
        Log access to a shared file

        Args:
            shared_file_id: Share ID
            action: Action performed (viewed, downloaded, failed_otp, etc.)
            user_id: User ID (optional)
            status: Success or failed
            failure_reason: Reason for failure
        """
        try:
            from services.device_service import DeviceService

            device_info = DeviceService.get_device_info()
            access_log = AccessLog(
                shared_file_id=shared_file_id,
                user_id=user_id,
                ip_address=request.remote_addr if request else '0.0.0.0',
                user_agent=request.headers.get('User-Agent', 'Unknown') if request else 'Unknown',
                device_info=device_info.get('ip_address'),
                device_type=device_info.get('device_type'),
                browser=device_info.get('browser'),
                operating_system=device_info.get('operating_system'),
                action=action,
                status=status,
                failure_reason=failure_reason,
                request_method=request.method if request else 'GET'
            )
            db.session.add(access_log)
            db.session.commit()

        except Exception as e:
            logger.error(f"Error logging access: {str(e)}")

    @staticmethod
    def log_share_event(action, share_id, owner_id, file_id=None, details=None):
        """
        Log share-related events

        Args:
            action: Action type (share_created, share_revoked, etc.)
            share_id: Share ID
            owner_id: Owner user ID
            file_id: File ID (optional)
            details: Additional details
        """
        try:
            from models import SecurityLog

            log = SecurityLog(
                user_id=owner_id,
                action=action,
                description=f"Share {share_id}: {details or action}",
                ip_address=request.remote_addr if request else '0.0.0.0',
                user_agent=request.headers.get('User-Agent') if request else 'Unknown',
                status='success'
            )
            db.session.add(log)
            db.session.commit()

        except Exception as e:
            logger.error(f"Error logging share event: {str(e)}")
