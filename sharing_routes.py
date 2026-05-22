"""Routes for secure file sharing system"""

from flask import Blueprint, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, SharedFile, AccessLog, EncryptedFile, User
from sharing_utils import (
    QRCodeGenerator, OTPManager, ShareTokenGenerator, 
    AccessValidator, DeviceFingerprint, ShareLinkGenerator
)
from datetime import datetime, timedelta
from functools import wraps
import os

sharing_bp = Blueprint('sharing', __name__, url_prefix='/sharing')


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def log_access(shared_file_id, action, status='success', failure_reason=None, user_id=None):
    """Log access to a shared file"""
    try:
        device_info = DeviceFingerprint.get_device_info()
        access_log = AccessLog(
            shared_file_id=shared_file_id,
            user_id=user_id or (current_user.id if current_user.is_authenticated else None),
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            device_info=device_info.get('ip_address'),
            action=action,
            status=status,
            failure_reason=failure_reason,
            request_method=request.method
        )
        db.session.add(access_log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging access: {str(e)}")


# ==================== FILE SHARING ENDPOINTS ====================

@sharing_bp.route('/share/<file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    """Share an encrypted file"""
    encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    
    if not encrypted_file:
        flash('File not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        try:
            share_method = request.form.get('share_method')  # qrcode, otp, user_id, link
            recipient_identifier = request.form.get('recipient_identifier')
            access_mode = request.form.get('access_mode', 'view_only')
            share_expiry_hours = int(request.form.get('share_expiry_hours', 24))
            max_access_count = request.form.get('max_access_count')
            
            # Create shared file record
            shared_file = SharedFile(
                encrypted_file_id=file_id,
                owner_id=current_user.id,
                share_method=share_method,
                sharing_token=ShareTokenGenerator.generate_share_token(),
                access_mode=access_mode,
                share_expiry=datetime.utcnow() + timedelta(hours=share_expiry_hours),
                max_access_count=int(max_access_count) if max_access_count else None
            )
            
            # Handle different sharing methods
            if share_method == 'otp':
                otp_code = OTPManager.generate_otp(length=6)
                shared_file.otp_code = otp_code
                shared_file.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            
            elif share_method == 'qrcode':
                qr_token = ShareTokenGenerator.generate_qr_token(file_id, current_user.id)
                shared_file.qr_token = qr_token
                qr_data = f"{request.host_url}sharing/access/qr/{qr_token}"
                shared_file.qr_code_data = QRCodeGenerator.generate_qr_code(qr_data)
            
            elif share_method == 'user_id':
                recipient = User.query.filter_by(username=recipient_identifier).first()
                if not recipient:
                    return jsonify({'error': 'User not found'}), 404
                shared_file.recipient_id = recipient.id
            
            elif share_method == 'link':
                temp_link = ShareLinkGenerator.generate_temporary_link(shared_file.id)
                shared_file.sharing_token = temp_link['token']
                shared_file.share_expiry = temp_link['expiry']
            
            db.session.add(shared_file)
            db.session.commit()
            
            log_access(shared_file.id, 'shared', user_id=current_user.id)
            
            return jsonify({
                'success': True,
                'shared_file_id': shared_file.id,
                'otp': shared_file.otp_code if share_method == 'otp' else None,
                'qr_code': shared_file.qr_code_data if share_method == 'qrcode' else None,
                'link': f"/sharing/access/{shared_file.sharing_token}" if share_method == 'link' else None
            })
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return render_template('sharing/share_file.html', file=encrypted_file)


@sharing_bp.route('/dashboard')
@login_required
def sharing_dashboard():
    """View sharing dashboard with analytics"""
    shared_files = SharedFile.query.filter_by(owner_id=current_user.id).all()
    received_shares = SharedFile.query.filter_by(recipient_id=current_user.id).all()
    
    # Calculate analytics
    total_shares = len(shared_files)
    active_shares = len([s for s in shared_files if s.is_active and AccessValidator.validate_share_expiry(s.share_expiry)])
    total_accesses = sum([s.access_count for s in shared_files])
    
    return render_template('sharing/dashboard.html',
                         shared_files=shared_files,
                         received_shares=received_shares,
                         analytics={
                             'total_shares': total_shares,
                             'active_shares': active_shares,
                             'total_accesses': total_accesses
                         })


@sharing_bp.route('/access/<token>', methods=['GET', 'POST'])
def access_shared_file(token):
    """Access a shared file with token"""
    shared_file = SharedFile.query.filter_by(sharing_token=token).first()
    
    if not shared_file:
        log_access(None, 'access_failed', status='failed', failure_reason='Invalid token')
        flash('Invalid share link', 'error')
        return redirect(url_for('auth.login'))
    
    # Validate share conditions
    if not shared_file.is_active:
        log_access(shared_file.id, 'access_denied', status='failed', failure_reason='Share inactive')
        flash('This share has been revoked', 'error')
        return redirect(url_for('auth.login'))
    
    if not AccessValidator.validate_share_expiry(shared_file.share_expiry):
        log_access(shared_file.id, 'access_expired', status='failed', failure_reason='Share expired')
        flash('This share link has expired', 'error')
        return redirect(url_for('auth.login'))
    
    if not AccessValidator.validate_access_count(shared_file.access_count, shared_file.max_access_count):
        log_access(shared_file.id, 'access_limit_exceeded', status='failed', failure_reason='Access limit reached')
        flash('Access limit reached for this share', 'error')
        return redirect(url_for('auth.login'))
    
    # Check if OTP verification is needed
    if shared_file.share_method == 'otp' and not request.session.get(f'otp_verified_{shared_file.id}'):
        return redirect(url_for('sharing.verify_otp', share_id=shared_file.id))
    
    log_access(shared_file.id, 'accessed')
    shared_file.access_count += 1
    shared_file.last_accessed = datetime.utcnow()
    db.session.commit()
    
    return render_template('sharing/view_shared_file.html', shared_file=shared_file)


@sharing_bp.route('/verify-otp/<share_id>', methods=['GET', 'POST'])
def verify_otp(share_id):
    """Verify OTP for accessing shared file"""
    shared_file = SharedFile.query.filter_by(id=share_id).first()
    
    if not shared_file or shared_file.share_method != 'otp':
        flash('Invalid request', 'error')
        return redirect(url_for('auth.login'))
    
    if not AccessValidator.validate_otp_expiry(shared_file.otp_expiry):
        log_access(shared_file.id, 'otp_expired', status='failed', failure_reason='OTP expired')
        flash('OTP has expired', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        otp_input = request.form.get('otp_code')
        
        if shared_file.otp_attempts >= shared_file.max_otp_attempts:
            log_access(shared_file.id, 'otp_attempts_exceeded', status='failed')
            flash('Too many OTP attempts', 'error')
            return redirect(url_for('auth.login'))
        
        if OTPManager.verify_otp(otp_input, shared_file.otp_code, expires_at=shared_file.otp_expiry):
            log_access(shared_file.id, 'otp_verified')
            request.session[f'otp_verified_{shared_file.id}'] = True
            return redirect(url_for('sharing.access_shared_file', token=shared_file.sharing_token))
        else:
            shared_file.otp_attempts += 1
            db.session.commit()
            log_access(shared_file.id, 'otp_failed', status='failed', failure_reason='Invalid OTP')
            flash(f'Invalid OTP. Attempts remaining: {shared_file.max_otp_attempts - shared_file.otp_attempts}', 'error')
    
    return render_template('sharing/verify_otp.html', shared_file=shared_file)


@sharing_bp.route('/download/<share_id>')
def download_shared_file(share_id):
    """Download a shared file"""
    shared_file = SharedFile.query.filter_by(id=share_id).first()
    
    if not shared_file:
        return jsonify({'error': 'Share not found'}), 404
    
    if shared_file.access_mode not in ['download_only', 'full_access']:
        log_access(shared_file.id, 'download_denied', status='failed', failure_reason='Insufficient permissions')
        return jsonify({'error': 'Download not permitted for this share'}), 403
    
    try:
        file_path = os.path.join(
            'static/encrypted',
            shared_file.encrypted_file.encrypted_filename
        )
        
        log_access(shared_file.id, 'downloaded')
        shared_file.access_count += 1
        db.session.commit()
        
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        log_access(shared_file.id, 'download_failed', status='failed', failure_reason=str(e))
        return jsonify({'error': 'Error downloading file'}), 500


@sharing_bp.route('/revoke/<share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    """Revoke a share"""
    shared_file = SharedFile.query.filter_by(id=share_id, owner_id=current_user.id).first()
    
    if not shared_file:
        return jsonify({'error': 'Share not found'}), 404
    
    shared_file.is_active = False
    db.session.commit()
    log_access(shared_file.id, 'revoked', user_id=current_user.id)
    
    return jsonify({'success': True, 'message': 'Share revoked'})


@sharing_bp.route('/analytics/<share_id>')
@login_required
def share_analytics(share_id):
    """Get analytics for a shared file"""
    shared_file = SharedFile.query.filter_by(id=share_id, owner_id=current_user.id).first()
    
    if not shared_file:
        return jsonify({'error': 'Share not found'}), 404
    
    access_logs = AccessLog.query.filter_by(shared_file_id=share_id).all()
    
    analytics = {
        'total_accesses': shared_file.access_count,
        'unique_ips': len(set([log.ip_address for log in access_logs])),
        'failed_attempts': len([log for log in access_logs if log.status == 'failed']),
        'last_accessed': shared_file.last_accessed,
        'created_at': shared_file.created_at,
        'expires_at': shared_file.share_expiry
    }
    
    return jsonify(analytics)


@sharing_bp.route('/qr-modal/<file_id>')
@login_required
def qr_modal(file_id):
    """Display QR code sharing modal"""
    encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    
    if not encrypted_file:
        return jsonify({'error': 'File not found'}), 404
    
    return render_template('sharing/qr_modal.html', file=encrypted_file)


# ==================== API ENDPOINTS ====================

@sharing_bp.route('/api/generate-qr', methods=['POST'])
@login_required
def generate_qr_api():
    """API endpoint to generate QR code"""
    try:
        file_id = request.json.get('file_id')
        
        encrypted_file = EncryptedFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not encrypted_file:
            return jsonify({'error': 'File not found'}), 404
        
        qr_data = f"{request.host_url}sharing/access/qr/{file_id}"
        qr_code = QRCodeGenerator.generate_qr_code(qr_data)
        
        return jsonify({'success': True, 'qr_code': qr_code})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/api/resend-otp/<share_id>', methods=['POST'])
def resend_otp_api(share_id):
    """API endpoint to resend OTP"""
    try:
        shared_file = SharedFile.query.filter_by(id=share_id).first()
        
        if not shared_file or shared_file.share_method != 'otp':
            return jsonify({'error': 'Invalid request'}), 400
        
        # Generate new OTP
        otp_code = OTPManager.generate_otp(length=6)
        shared_file.otp_code = otp_code
        shared_file.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        shared_file.otp_attempts = 0
        db.session.commit()
        
        # In production, send OTP via email
        log_access(shared_file.id, 'otp_resent')
        
        return jsonify({'success': True, 'message': 'OTP resent'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
