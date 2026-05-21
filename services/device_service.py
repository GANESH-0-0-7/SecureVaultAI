"""Device service for tracking, fingerprinting, and classifying devices"""

from flask import request
from user_agents import parse
import hashlib
import logging

logger = logging.getLogger(__name__)


class DeviceService:
    """Service for device tracking and fingerprinting"""

    @staticmethod
    def get_device_info():
        """
        Extract device information from request

        Returns:
            Dictionary with device information
        """
        try:
            user_agent_string = request.headers.get('User-Agent', 'Unknown')
            user_agent = parse(user_agent_string)
            ip_address = DeviceService._get_client_ip()

            device_info = {
                'ip_address': ip_address,
                'user_agent': user_agent_string,
                'device_type': DeviceService._classify_device(user_agent),
                'browser': DeviceService._get_browser_name(user_agent),
                'operating_system': DeviceService._get_os_name(user_agent),
                'device_name': DeviceService._get_device_name(user_agent),
                'is_mobile': user_agent.is_mobile,
                'is_tablet': user_agent.is_tablet,
                'is_pc': user_agent.is_pc
            }

            return device_info

        except Exception as e:
            logger.error(f"Error getting device info: {str(e)}")
            return {
                'ip_address': request.remote_addr,
                'user_agent': 'Unknown',
                'device_type': 'unknown',
                'browser': 'Unknown',
                'operating_system': 'Unknown',
                'device_name': 'Unknown Device'
            }

    @staticmethod
    def generate_fingerprint(ip_address, user_agent):
        """
        Generate a device fingerprint hash

        Args:
            ip_address: IP address of device
            user_agent: User agent string

        Returns:
            SHA256 hash fingerprint
        """
        try:
            fingerprint_data = f"{ip_address}:{user_agent}"
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            return fingerprint

        except Exception as e:
            logger.error(f"Error generating fingerprint: {str(e)}")
            return None

    @staticmethod
    def _classify_device(user_agent):
        """
        Classify device as desktop, mobile, tablet, or unknown

        Args:
            user_agent: Parsed user agent object

        Returns:
            Device type string
        """
        if user_agent.is_mobile:
            return 'mobile'
        elif user_agent.is_tablet:
            return 'tablet'
        elif user_agent.is_pc:
            return 'desktop'
        else:
            return 'unknown'

    @staticmethod
    def _get_browser_name(user_agent):
        """
        Extract browser name from user agent

        Args:
            user_agent: Parsed user agent object

        Returns:
            Browser name and version
        """
        try:
            browser = user_agent.browser
            if browser.family and browser.version_string:
                return f"{browser.family} {browser.version_string}"
            elif browser.family:
                return browser.family
            else:
                return 'Unknown Browser'

        except Exception:
            return 'Unknown Browser'

    @staticmethod
    def _get_os_name(user_agent):
        """
        Extract operating system name from user agent

        Args:
            user_agent: Parsed user agent object

        Returns:
            OS name and version
        """
        try:
            os = user_agent.os
            if os.family and os.version_string:
                return f"{os.family} {os.version_string}"
            elif os.family:
                return os.family
            else:
                return 'Unknown OS'

        except Exception:
            return 'Unknown OS'

    @staticmethod
    def _get_device_name(user_agent):
        """
        Get human-readable device name

        Args:
            user_agent: Parsed user agent object

        Returns:
            Device name (e.g., "Chrome on Windows 10")
        """
        try:
            browser = DeviceService._get_browser_name(user_agent)
            os_name = DeviceService._get_os_name(user_agent)
            return f"{browser} on {os_name}"

        except Exception:
            return 'Unknown Device'

    @staticmethod
    def _get_client_ip():
        """
        Get client IP address, accounting for proxies

        Returns:
            IP address string
        """
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr

    @staticmethod
    def is_new_device(user_id, fingerprint, db):
        """
        Check if device is new (not previously used by user)

        Args:
            user_id: User ID
            fingerprint: Device fingerprint
            db: Database instance

        Returns:
            Boolean indicating if device is new
        """
        try:
            from models import DeviceSession

            existing_device = DeviceSession.query.filter_by(
                user_id=user_id,
                device_fingerprint=fingerprint
            ).first()

            return existing_device is None

        except Exception as e:
            logger.error(f"Error checking if device is new: {str(e)}")
            return True

    @staticmethod
    def record_device_session(user_id, device_info, db, is_trusted=False):
        """
        Record a device session for user

        Args:
            user_id: User ID
            device_info: Dictionary with device information
            db: Database instance
            is_trusted: Whether device is trusted

        Returns:
            DeviceSession object
        """
        try:
            from models import DeviceSession

            fingerprint = DeviceService.generate_fingerprint(
                device_info['ip_address'],
                device_info['user_agent']
            )

            # Check if device already exists
            existing_device = DeviceSession.query.filter_by(
                user_id=user_id,
                device_fingerprint=fingerprint
            ).first()

            if existing_device:
                # Update last_used timestamp
                existing_device.last_used = datetime.utcnow()
                db.session.commit()
                return existing_device

            # Create new device session
            device_session = DeviceSession(
                user_id=user_id,
                device_fingerprint=fingerprint,
                device_name=device_info.get('device_name', 'Unknown Device'),
                device_type=device_info.get('device_type', 'unknown'),
                browser=device_info.get('browser'),
                operating_system=device_info.get('operating_system'),
                ip_address=device_info['ip_address'],
                user_agent=device_info['user_agent'],
                is_trusted=is_trusted
            )

            db.session.add(device_session)
            db.session.commit()

            logger.info(f"Device session recorded for user {user_id}: {device_info.get('device_name')}")
            return device_session

        except Exception as e:
            logger.error(f"Error recording device session: {str(e)}")
            return None

    @staticmethod
    def get_user_devices(user_id, db):
        """
        Get all devices for a user

        Args:
            user_id: User ID
            db: Database instance

        Returns:
            List of device sessions
        """
        try:
            from models import DeviceSession

            devices = DeviceSession.query.filter_by(user_id=user_id).order_by(
                DeviceSession.last_used.desc()
            ).all()

            return [
                {
                    'id': device.id,
                    'name': device.device_name,
                    'type': device.device_type,
                    'browser': device.browser,
                    'os': device.operating_system,
                    'ip': device.ip_address,
                    'is_trusted': device.is_trusted,
                    'last_used': device.last_used.isoformat() if device.last_used else None,
                    'created_at': device.created_at.isoformat() if device.created_at else None
                }
                for device in devices
            ]

        except Exception as e:
            logger.error(f"Error retrieving user devices: {str(e)}")
            return []

    @staticmethod
    def trust_device(device_id, user_id, db):
        """
        Mark device as trusted

        Args:
            device_id: Device ID
            user_id: User ID
            db: Database instance

        Returns:
            Boolean indicating success
        """
        try:
            from models import DeviceSession

            device = DeviceSession.query.filter_by(
                id=device_id,
                user_id=user_id
            ).first()

            if device:
                device.is_trusted = True
                db.session.commit()
                logger.info(f"Device {device_id} marked as trusted")
                return True

            return False

        except Exception as e:
            logger.error(f"Error trusting device: {str(e)}")
            return False

    @staticmethod
    def revoke_device(device_id, user_id, db):
        """
        Revoke/remove device

        Args:
            device_id: Device ID
            user_id: User ID
            db: Database instance

        Returns:
            Boolean indicating success
        """
        try:
            from models import DeviceSession

            device = DeviceSession.query.filter_by(
                id=device_id,
                user_id=user_id
            ).first()

            if device:
                db.session.delete(device)
                db.session.commit()
                logger.info(f"Device {device_id} revoked")
                return True

            return False

        except Exception as e:
            logger.error(f"Error revoking device: {str(e)}")
            return False


# Import datetime here to avoid circular imports
from datetime import datetime
