"""OTP (One-Time Password) Service for secure verification"""

from datetime import datetime, timedelta
from models import db, OTPVerification
from sharing_utils import OTPManager
from services.email_service import EmailService
from services.notification_service import NotificationService
import logging

logger = logging.getLogger(__name__)


class OTPService:
    """Service for managing OTP verification and delivery"""

    @staticmethod
    def create_otp_verification(user_id, shared_file_id=None, ip_address=None, device_info=None, expires_in_minutes=5):
        """
        Create new OTP verification record

        Args:
            user_id: User ID requesting OTP
            shared_file_id: Optional shared file ID (for file access OTP)
            ip_address: IP address of requester
            device_info: Device information string
            expires_in_minutes: OTP expiration time in minutes

        Returns:
            OTPVerification instance
        """
        try:
            otp_code = OTPManager.generate_otp(length=6)
            expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)

            otp_verification = OTPVerification(
                user_id=user_id,
                shared_file_id=shared_file_id,
                otp_code=otp_code,
                expires_at=expires_at,
                ip_address=ip_address or '0.0.0.0',
                device_info=device_info,
                verified=False,
                failed_attempts=0
            )

            db.session.add(otp_verification)
            db.session.commit()

            logger.info(f"OTP created for user {user_id} (expires in {expires_in_minutes} minutes)")
            return otp_verification

        except Exception as e:
            logger.error(f"Error creating OTP verification: {str(e)}")
            raise

    @staticmethod
    def verify_otp_code(otp_id, provided_otp):
        """
        Verify OTP code with attempt tracking

        Args:
            otp_id: OTPVerification ID
            provided_otp: OTP code provided by user

        Returns:
            Dictionary with status and message
        """
        try:
            otp_record = OTPVerification.query.get(otp_id)

            if not otp_record:
                return {
                    'success': False,
                    'message': 'OTP not found',
                    'reason': 'invalid_otp_id'
                }

            # Check if already verified
            if otp_record.verified:
                return {
                    'success': False,
                    'message': 'OTP already used',
                    'reason': 'otp_already_verified'
                }

            # Check expiration
            if datetime.utcnow() > otp_record.expires_at:
                return {
                    'success': False,
                    'message': 'OTP has expired',
                    'reason': 'otp_expired'
                }

            # Check max attempts (default 5)
            if otp_record.failed_attempts >= 5:
                return {
                    'success': False,
                    'message': 'Too many failed attempts. OTP locked.',
                    'reason': 'max_attempts_exceeded'
                }

            # Verify code
            if otp_record.otp_code == provided_otp:
                otp_record.verified = True
                otp_record.verified_at = datetime.utcnow()
                db.session.commit()

                logger.info(f"OTP verified for user {otp_record.user_id}")
                return {
                    'success': True,
                    'message': 'OTP verified successfully',
                    'otp_id': otp_id
                }
            else:
                otp_record.failed_attempts += 1
                db.session.commit()

                remaining = max(0, 5 - otp_record.failed_attempts)
                logger.warning(f"OTP verification failed for user {otp_record.user_id} (attempt {otp_record.failed_attempts})")

                return {
                    'success': False,
                    'message': f'Invalid OTP. {remaining} attempts remaining.',
                    'reason': 'invalid_otp_code',
                    'attempts_remaining': remaining
                }

        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'message': 'Error verifying OTP',
                'reason': 'verification_error'
            }

    @staticmethod
    def resend_otp(otp_id, user_email=None, file_name=None):
        """
        Resend OTP via email

        Args:
            otp_id: OTPVerification ID
            user_email: User's email address
            file_name: Optional file name being shared

        Returns:
            Dictionary with status and message
        """
        try:
            otp_record = OTPVerification.query.get(otp_id)

            if not otp_record:
                return {
                    'success': False,
                    'message': 'OTP not found'
                }

            # Generate new OTP
            otp_record.otp_code = OTPManager.generate_otp(length=6)
            otp_record.expires_at = datetime.utcnow() + timedelta(minutes=5)
            otp_record.failed_attempts = 0
            otp_record.verified = False
            db.session.commit()

            # Send email if address provided
            if user_email:
                try:
                    EmailService.send_otp_email(
                        recipient_email=user_email,
                        otp_code=otp_record.otp_code,
                        file_name=file_name or 'Secure File',
                        expiry_minutes=5
                    )
                    logger.info(f"OTP resent to {user_email}")
                except Exception as e:
                    logger.error(f"Error sending OTP email: {str(e)}")
                    # Still return success for OTP creation, just note email failure
                    return {
                        'success': True,
                        'message': 'OTP regenerated but email send failed',
                        'email_error': True
                    }

            return {
                'success': True,
                'message': 'OTP resent successfully'
            }

        except Exception as e:
            logger.error(f"Error resending OTP: {str(e)}")
            return {
                'success': False,
                'message': 'Error resending OTP'
            }

    @staticmethod
    def cleanup_expired_otps():
        """
        Clean up expired OTP records (maintenance task)

        Returns:
            Number of records deleted
        """
        try:
            expired_count = OTPVerification.query.filter(
                OTPVerification.expires_at < datetime.utcnow(),
                OTPVerification.verified == False
            ).delete()

            db.session.commit()
            logger.info(f"Cleaned up {expired_count} expired OTP records")
            return expired_count

        except Exception as e:
            logger.error(f"Error cleaning up expired OTPs: {str(e)}")
            return 0

    @staticmethod
    def get_otp_status(otp_id):
        """
        Get OTP status for UI display

        Args:
            otp_id: OTPVerification ID

        Returns:
            Dictionary with OTP status information
        """
        try:
            otp_record = OTPVerification.query.get(otp_id)

            if not otp_record:
                return {
                    'exists': False,
                    'verified': False
                }

            remaining_seconds = max(0, int((otp_record.expires_at - datetime.utcnow()).total_seconds()))
            remaining_minutes = remaining_seconds // 60
            remaining_secs = remaining_seconds % 60

            return {
                'exists': True,
                'verified': otp_record.verified,
                'expired': datetime.utcnow() > otp_record.expires_at,
                'remaining_seconds': remaining_seconds,
                'remaining_time': f"{remaining_minutes}:{remaining_secs:02d}",
                'attempts_remaining': max(0, 5 - otp_record.failed_attempts),
                'failed_attempts': otp_record.failed_attempts,
                'created_at': otp_record.created_at.isoformat() if otp_record.created_at else None
            }

        except Exception as e:
            logger.error(f"Error getting OTP status: {str(e)}")
            return {
                'exists': False,
                'error': str(e)
            }

    @staticmethod
    def send_otp_email(user_email, file_name=None, username=None):
        """
        Send OTP email to user

        Args:
            user_email: Email address
            file_name: Name of file being shared
            username: Username of recipient

        Returns:
            Boolean indicating success
        """
        try:
            otp_code = OTPManager.generate_otp(length=6)

            EmailService.send_otp_email(
                recipient_email=user_email,
                otp_code=otp_code,
                file_name=file_name or 'Secure File',
                expiry_minutes=5
            )

            logger.info(f"OTP email sent to {user_email}")
            return True

        except Exception as e:
            logger.error(f"Error sending OTP email: {str(e)}")
            return False

    @staticmethod
    def validate_otp_for_share(share_token, provided_otp):
        """
        Validate OTP for a specific share

        Args:
            share_token: Share token
            provided_otp: OTP provided by user

        Returns:
            Boolean indicating if OTP is valid
        """
        from models import SharedFile

        try:
            shared_file = SharedFile.query.filter_by(sharing_token=share_token).first()

            if not shared_file or shared_file.share_method != 'otp':
                return False

            # Check if OTP has expired
            if not shared_file.otp_expiry or datetime.utcnow() > shared_file.otp_expiry:
                return False

            # Verify OTP code
            from sharing_utils import OTPManager
            if not OTPManager.verify_otp(provided_otp, shared_file.otp_code, expires_at=shared_file.otp_expiry):
                # Increment failed attempts
                shared_file.otp_attempts += 1
                db.session.commit()
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating OTP for share: {str(e)}")
            return False
