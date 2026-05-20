from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import login_required, current_user
from models import db, EncryptedFile, SecurityLog
from utils import EncryptionManager, FileValidator, get_client_ip
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json

encryption_bp = Blueprint('encryption', __name__, url_prefix='/encryption')

@encryption_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    """Encrypt file page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('encryption.encrypt'))

        file = request.files['file']
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        password_hint = request.form.get('password_hint', '')

        if not file or file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('encryption.encrypt'))

        if not password or not confirm_password:
            flash('Password is required', 'danger')
            return redirect(url_for('encryption.encrypt'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('encryption.encrypt'))

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('encryption.encrypt'))

        if not FileValidator.allowed_file(file.filename):
            flash(f'File type not allowed. Allowed: {", ".join(FileValidator.ALLOWED_EXTENSIONS)}', 'danger')
            return redirect(url_for('encryption.encrypt'))

        try:
            # Read file content
            file_content = file.read()

            if not FileValidator.check_file_size(len(file_content)):
                flash(f'File size exceeds maximum limit (100MB)', 'danger')
                return redirect(url_for('encryption.encrypt'))

            # Encrypt file
            encrypted_content, salt = EncryptionManager.encrypt_file(file_content, password)

            # Generate unique filename
            original_filename = secure_filename(file.filename)
            file_ext = FileValidator.get_file_extension(original_filename)
            encrypted_filename = f"{current_user.id}_{datetime.utcnow().timestamp()}_{os.urandom(4).hex()}.enc"

            # Save encrypted file
            from config import Config
            os.makedirs(Config.ENCRYPTED_FOLDER, exist_ok=True)
            encrypted_path = os.path.join(Config.ENCRYPTED_FOLDER, encrypted_filename)

            # Store salt in metadata
            metadata = {'salt': salt}
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_content)

            # Save metadata
            metadata_path = encrypted_path + '.meta'
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f)

            # Create database record
            encrypted_file = EncryptedFile(
                user_id=current_user.id,
                original_filename=original_filename,
                encrypted_filename=encrypted_filename,
                file_extension=file_ext,
                encryption_type='AES-256-Fernet',
                file_size=len(file_content),
                status='encrypted',
                decryption_password_hint=password_hint if password_hint else None
            )
            db.session.add(encrypted_file)

            # Log security event
            log = SecurityLog(
                user_id=current_user.id,
                action='file_encrypted',
                description=f'File encrypted: {original_filename}',
                ip_address=get_client_ip(request),
                user_agent=request.headers.get('User-Agent', ''),
                status='success'
            )
            db.session.add(log)
            db.session.commit()

            flash(f'File encrypted successfully! (Size: {len(file_content) / 1024:.2f} KB)', 'success')
            return redirect(url_for('main.dashboard'))

        except Exception as e:
            flash(f'Encryption error: {str(e)}', 'danger')
            return redirect(url_for('encryption.encrypt'))

    return render_template('encryption/encrypt.html')


@encryption_bp.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    """Decrypt file page"""
    if request.method == 'POST':
        file_id = request.form.get('file_id', '')
        password = request.form.get('password', '')

        if not file_id or not password:
            flash('File ID and password required', 'danger')
            return redirect(url_for('encryption.decrypt'))

        encrypted_file = EncryptedFile.query.filter_by(
            id=file_id,
            user_id=current_user.id
        ).first()

        if not encrypted_file:
            flash('File not found', 'danger')
            return redirect(url_for('encryption.decrypt'))

        try:
            from config import Config

            encrypted_path = os.path.join(Config.ENCRYPTED_FOLDER, encrypted_file.encrypted_filename)
            metadata_path = encrypted_path + '.meta'

            if not os.path.exists(encrypted_path):
                flash('Encrypted file not found on server', 'danger')
                return redirect(url_for('encryption.decrypt'))

            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Read and decrypt file
            with open(encrypted_path, 'rb') as f:
                encrypted_content = f.read()

            decrypted_content = EncryptionManager.decrypt_file(
                encrypted_content,
                password,
                metadata['salt']
            )

            # Save decrypted file
            os.makedirs(Config.DECRYPTED_FOLDER, exist_ok=True)
            decrypted_filename = f"{current_user.id}_{datetime.utcnow().timestamp()}_{encrypted_file.original_filename}"
            decrypted_path = os.path.join(Config.DECRYPTED_FOLDER, decrypted_filename)

            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_content)

            # Update database
            encrypted_file.is_decrypted = True
            encrypted_file.last_accessed = datetime.utcnow()
            db.session.commit()

            # Log security event
            log = SecurityLog(
                user_id=current_user.id,
                action='file_decrypted',
                description=f'File decrypted: {encrypted_file.original_filename}',
                ip_address=get_client_ip(request),
                user_agent=request.headers.get('User-Agent', ''),
                status='success'
            )
            db.session.add(log)
            db.session.commit()

            flash('File decrypted successfully! Ready for download.', 'success')
            return redirect(url_for('encryption.view_decrypted', file_id=file_id))

        except Exception as e:
            flash(f'Decryption error: {str(e)}', 'danger')
            return redirect(url_for('encryption.decrypt'))

    # Get user's encrypted files for selection
    user_files = EncryptedFile.query.filter_by(user_id=current_user.id).all()
    return render_template('encryption/decrypt.html', user_files=user_files)


@encryption_bp.route('/view-decrypted/<file_id>')
@login_required
def view_decrypted(file_id):
    """View decrypted file details"""
    encrypted_file = EncryptedFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first()

    if not encrypted_file:
        flash('File not found', 'danger')
        return redirect(url_for('main.dashboard'))

    return render_template('encryption/view_decrypted.html', file=encrypted_file)


@encryption_bp.route('/download/<file_id>')
@login_required
def download(file_id):
    """Download decrypted file"""
    encrypted_file = EncryptedFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first()

    if not encrypted_file or not encrypted_file.is_decrypted:
        flash('File not available for download', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        from config import Config
        decrypted_filename = f"{current_user.id}_{encrypted_file.id}_{encrypted_file.original_filename}"
        decrypted_path = os.path.join(Config.DECRYPTED_FOLDER, decrypted_filename)

        # Try to find the file (filename might have timestamp)
        if not os.path.exists(decrypted_path):
            # Search in decrypted folder
            for filename in os.listdir(Config.DECRYPTED_FOLDER):
                if encrypted_file.id in filename:
                    decrypted_path = os.path.join(Config.DECRYPTED_FOLDER, filename)
                    break

        if os.path.exists(decrypted_path):
            return send_file(
                decrypted_path,
                as_attachment=True,
                download_name=encrypted_file.original_filename
            )
        else:
            flash('Decrypted file not found', 'danger')
            return redirect(url_for('main.dashboard'))

    except Exception as e:
        flash(f'Download error: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))


@encryption_bp.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete encrypted file"""
    encrypted_file = EncryptedFile.query.filter_by(
        id=file_id,
        user_id=current_user.id
    ).first()

    if not encrypted_file:
        return jsonify({'success': False, 'message': 'File not found'}), 404

    try:
        from config import Config

        # Delete physical files
        encrypted_path = os.path.join(Config.ENCRYPTED_FOLDER, encrypted_file.encrypted_filename)
        metadata_path = encrypted_path + '.meta'

        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        if os.path.exists(metadata_path):
            os.remove(metadata_path)

        # Delete database record
        db.session.delete(encrypted_file)

        # Log security event
        log = SecurityLog(
            user_id=current_user.id,
            action='file_deleted',
            description=f'File deleted: {encrypted_file.original_filename}',
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            status='success'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'success': True, 'message': 'File deleted successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
