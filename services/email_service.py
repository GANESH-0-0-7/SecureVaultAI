"""Email service for sending notifications and OTP codes"""

from flask_mail import Mail, Message
from flask import render_template_string
from datetime import datetime
import logging

mail = Mail()
logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails"""

    @staticmethod
    def send_otp_email(recipient_email, otp_code, username, file_name, expiry_minutes=5):
        """
        Send OTP verification email to recipient

        Args:
            recipient_email: Recipient email address
            otp_code: 6-digit OTP code
            username: Username of recipient
            file_name: Name of the file being shared
            expiry_minutes: OTP expiry time in minutes
        """
        try:
            subject = f"Secure Access Code for {file_name} - SecureVaultAI"

            html_template = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; }}
                        .header {{ text-align: center; border-bottom: 3px solid #667eea; padding-bottom: 20px; }}
                        .header h1 {{ color: #667eea; margin: 0; }}
                        .otp-box {{ background-color: #f0f4ff; border: 2px solid #667eea; padding: 20px; margin: 20px 0; text-align: center; border-radius: 8px; }}
                        .otp-code {{ font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; }}
                        .expiry {{ color: #ff6b6b; font-weight: bold; margin-top: 10px; }}
                        .info-box {{ background-color: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #667eea; }}
                        .footer {{ text-align: center; color: #888; font-size: 12px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }}
                        .warning {{ background-color: #fff3cd; padding: 10px; border-radius: 4px; margin: 15px 0; color: #856404; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 SecureVaultAI - Secure Access</h1>
                        </div>

                        <p>Hello <strong>{username}</strong>,</p>

                        <p>Someone has shared the encrypted file <strong>{file_name}</strong> with you. To access this secure file, use the verification code below:</p>

                        <div class="otp-box">
                            <p>Your Secure Access Code:</p>
                            <div class="otp-code">{otp_code}</div>
                            <div class="expiry">Valid for {expiry_minutes} minutes</div>
                        </div>

                        <div class="info-box">
                            <strong>How to use this code:</strong>
                            <ul>
                                <li>Go to the secure file access page</li>
                                <li>Enter the 6-digit code above</li>
                                <li>Access your secure file</li>
                            </ul>
                        </div>

                        <div class="warning">
                            <strong>Security Notice:</strong> Never share this code with anyone. This code is valid for {expiry_minutes} minutes. If you didn't request this, ignore this email.
                        </div>

                        <div class="info-box">
                            <strong>File Details:</strong>
                            <ul>
                                <li>File Name: {file_name}</li>
                                <li>Shared via: SecureVaultAI</li>
                                <li>Access Level: Secure (Password Protected)</li>
                            </ul>
                        </div>

                        <p>Questions? Check our security documentation or contact support.</p>

                        <div class="footer">
                            <p>&copy; 2026 SecureVaultAI. All rights reserved.</p>
                            <p>This is an automated security email. Please do not reply directly.</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                html=html_template
            )

            mail.send(msg)
            logger.info(f"OTP email sent to {recipient_email} for file {file_name}")
            return True

        except Exception as e:
            logger.error(f"Error sending OTP email: {str(e)}")
            return False

    @staticmethod
    def send_share_notification(recipient_email, sender_name, file_name, access_level, share_link=None):
        """
        Send file share notification email

        Args:
            recipient_email: Recipient email address
            sender_name: Name of the person sharing the file
            file_name: Name of the shared file
            access_level: Access level (View Only, Download, Full Access, etc.)
            share_link: Optional direct link to access share
        """
        try:
            subject = f"{sender_name} has shared '{file_name}' with you"

            link_section = ""
            if share_link:
                link_section = f"""
                <div class="info-box">
                    <a href="{share_link}" style="display: inline-block; background-color: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 10px 0;">
                        Access Shared File →
                    </a>
                </div>
                """

            html_template = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; }}
                        .header {{ text-align: center; border-bottom: 3px solid #667eea; padding-bottom: 20px; }}
                        .header h1 {{ color: #667eea; margin: 0; }}
                        .info-box {{ background-color: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #667eea; border-radius: 4px; }}
                        .footer {{ text-align: center; color: #888; font-size: 12px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }}
                        .badge {{ display: inline-block; background-color: #e8f0ff; color: #667eea; padding: 5px 10px; border-radius: 4px; margin: 5px 0; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>📤 File Shared with You</h1>
                        </div>

                        <p><strong>{sender_name}</strong> has shared a secure file with you on <strong>SecureVaultAI</strong>.</p>

                        <div class="info-box">
                            <strong>File Details:</strong>
                            <ul>
                                <li><strong>File Name:</strong> {file_name}</li>
                                <li><strong>Shared By:</strong> {sender_name}</li>
                                <li><strong>Access Level:</strong> <span class="badge">{access_level}</span></li>
                                <li><strong>Shared Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
                            </ul>
                        </div>

                        <p>This file is encrypted and secured. You may need to verify your identity using a one-time password (OTP) to access it.</p>

                        {link_section}

                        <div class="info-box" style="background-color: #f0fdf4; border-left-color: #10b981;">
                            <strong>🔒 Security Features:</strong>
                            <ul>
                                <li>End-to-End Encryption (AES-256)</li>
                                <li>OTP Verification Required</li>
                                <li>Access Logging & Audit Trail</li>
                                <li>Expiration Controls</li>
                            </ul>
                        </div>

                        <p>If you have any questions or didn't expect this share, please contact the sender directly.</p>

                        <div class="footer">
                            <p>&copy; 2026 SecureVaultAI. All rights reserved.</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                html=html_template
            )

            mail.send(msg)
            logger.info(f"Share notification sent to {recipient_email} from {sender_name}")
            return True

        except Exception as e:
            logger.error(f"Error sending share notification: {str(e)}")
            return False

    @staticmethod
    def send_access_notification(recipient_email, accessor_name, file_name, access_type, timestamp=None):
        """
        Send file access notification email

        Args:
            recipient_email: Recipient email address
            accessor_name: Name of person accessing the file
            file_name: Name of the accessed file
            access_type: Type of access (viewed, downloaded, etc.)
            timestamp: When the file was accessed
        """
        try:
            if timestamp is None:
                timestamp = datetime.now().strftime('%B %d, %Y at %I:%M %p')

            subject = f"[Alert] {file_name} was {access_type} by {accessor_name}"

            html_template = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; }}
                        .header {{ text-align: center; border-bottom: 3px solid #f59e0b; padding-bottom: 20px; }}
                        .header h1 {{ color: #f59e0b; margin: 0; }}
                        .info-box {{ background-color: #fffbeb; padding: 15px; margin: 15px 0; border-left: 4px solid #f59e0b; border-radius: 4px; }}
                        .footer {{ text-align: center; color: #888; font-size: 12px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>⚠️ File Access Alert</h1>
                        </div>

                        <p>Your shared file <strong>{file_name}</strong> was <strong>{access_type}</strong> on SecureVaultAI.</p>

                        <div class="info-box">
                            <strong>Access Details:</strong>
                            <ul>
                                <li><strong>File Name:</strong> {file_name}</li>
                                <li><strong>Accessed By:</strong> {accessor_name}</li>
                                <li><strong>Action:</strong> {access_type}</li>
                                <li><strong>Time:</strong> {timestamp}</li>
                            </ul>
                        </div>

                        <p>This is an automatic notification from SecureVaultAI to keep you informed about your shared files.</p>

                        <p>If you didn't authorize this access, you can revoke the share immediately from your SecureVaultAI dashboard.</p>

                        <div class="footer">
                            <p>&copy; 2026 SecureVaultAI. All rights reserved.</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                html=html_template
            )

            mail.send(msg)
            logger.info(f"Access notification sent to {recipient_email} for {file_name}")
            return True

        except Exception as e:
            logger.error(f"Error sending access notification: {str(e)}")
            return False

    @staticmethod
    def send_security_alert(recipient_email, alert_type, message, details=None):
        """
        Send security alert email

        Args:
            recipient_email: Recipient email address
            alert_type: Type of alert (failed_otp, unauthorized_access, etc.)
            message: Alert message
            details: Additional details about the alert
        """
        try:
            subject = f"🚨 Security Alert - SecureVaultAI"

            details_section = ""
            if details:
                details_section = f"""
                <div class="details-box">
                    <strong>Details:</strong>
                    <p>{details}</p>
                </div>
                """

            html_template = f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; }}
                        .header {{ text-align: center; border-bottom: 3px solid #dc2626; padding-bottom: 20px; }}
                        .header h1 {{ color: #dc2626; margin: 0; }}
                        .alert-box {{ background-color: #fee2e2; padding: 15px; margin: 15px 0; border-left: 4px solid #dc2626; border-radius: 4px; }}
                        .details-box {{ background-color: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #666; border-radius: 4px; }}
                        .action-box {{ background-color: #f0fdf4; padding: 15px; margin: 15px 0; border-left: 4px solid #10b981; border-radius: 4px; }}
                        .footer {{ text-align: center; color: #888; font-size: 12px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🚨 Security Alert</h1>
                        </div>

                        <div class="alert-box">
                            <strong>Alert Type:</strong> {alert_type.replace('_', ' ').title()}
                            <p>{message}</p>
                        </div>

                        {details_section}

                        <div class="action-box">
                            <strong>Recommended Actions:</strong>
                            <ul>
                                <li>Review your recent account activity</li>
                                <li>Check your shared files for unauthorized access</li>
                                <li>Update your password if needed</li>
                                <li>Enable two-factor authentication for additional security</li>
                            </ul>
                        </div>

                        <p>If you believe this is an error or you have questions, please contact our security team immediately.</p>

                        <div class="footer">
                            <p>&copy; 2026 SecureVaultAI. All rights reserved.</p>
                            <p>This is a security alert from SecureVaultAI.</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                html=html_template
            )

            mail.send(msg)
            logger.info(f"Security alert sent to {recipient_email}: {alert_type}")
            return True

        except Exception as e:
            logger.error(f"Error sending security alert: {str(e)}")
            return False
