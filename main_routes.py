from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models import db, EncryptedFile, PasswordAnalysis, SecurityLog, User
from sqlalchemy import func
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Landing page"""
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    from flask import redirect, url_for
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    user_id = current_user.id

    # Statistics
    total_files = EncryptedFile.query.filter_by(user_id=user_id).count()
    decrypted_files = EncryptedFile.query.filter_by(user_id=user_id, is_decrypted=True).count()
    total_analyses = PasswordAnalysis.query.filter_by(user_id=user_id).count()

    # Files storage
    all_files = EncryptedFile.query.filter_by(user_id=user_id).all()
    total_storage = sum(f.file_size for f in all_files)

    # Recent files
    recent_files = EncryptedFile.query.filter_by(user_id=user_id).order_by(
        EncryptedFile.upload_date.desc()
    ).limit(5).all()

    # Recent analyses
    recent_analyses = PasswordAnalysis.query.filter_by(user_id=user_id).order_by(
        PasswordAnalysis.created_at.desc()
    ).limit(5).all()

    # Security alerts (last 7 days with failed attempts or suspicious activity)
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    security_logs = SecurityLog.query.filter_by(user_id=user_id).filter(
        SecurityLog.timestamp >= one_week_ago
    ).order_by(SecurityLog.timestamp.desc()).limit(5).all()

    # Password strength distribution
    analyses_30days = PasswordAnalysis.query.filter_by(user_id=user_id).filter(
        PasswordAnalysis.created_at >= datetime.utcnow() - timedelta(days=30)
    ).all()

    strength_dist = {
        'weak': len([a for a in analyses_30days if a.strength_level == 'Weak']),
        'medium': len([a for a in analyses_30days if a.strength_level == 'Medium']),
        'strong': len([a for a in analyses_30days if a.strength_level == 'Strong']),
    }

    # Daily file uploads (last 30 days)
    daily_stats = db.session.query(
        func.date(EncryptedFile.upload_date),
        func.count(EncryptedFile.id)
    ).filter_by(user_id=user_id).filter(
        EncryptedFile.upload_date >= datetime.utcnow() - timedelta(days=30)
    ).group_by(func.date(EncryptedFile.upload_date)).all()

    daily_uploads = {str(date): count for date, count in daily_stats}

    context = {
        'total_files': total_files,
        'decrypted_files': decrypted_files,
        'total_analyses': total_analyses,
        'total_storage': round(total_storage / (1024 * 1024), 2),  # Convert to MB
        'recent_files': recent_files,
        'recent_analyses': recent_analyses,
        'security_logs': security_logs,
        'strength_dist': strength_dist,
        'daily_uploads': daily_uploads,
    }

    return render_template('dashboard/dashboard.html', **context)


@main_bp.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    """API endpoint for dashboard statistics"""
    user_id = current_user.id

    total_files = EncryptedFile.query.filter_by(user_id=user_id).count()
    decrypted_files = EncryptedFile.query.filter_by(user_id=user_id, is_decrypted=True).count()

    all_files = EncryptedFile.query.filter_by(user_id=user_id).all()
    total_storage = sum(f.file_size for f in all_files)

    return jsonify({
        'total_files': total_files,
        'decrypted_files': decrypted_files,
        'encrypted_files': total_files - decrypted_files,
        'total_storage_mb': round(total_storage / (1024 * 1024), 2),
        'timestamp': datetime.utcnow().isoformat()
    })


@main_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    user_stats = {
        'total_files': EncryptedFile.query.filter_by(user_id=current_user.id).count(),
        'total_analyses': PasswordAnalysis.query.filter_by(user_id=current_user.id).count(),
        'account_created': current_user.created_at,
        'last_login': current_user.last_login,
    }

    return render_template('dashboard/profile.html', user_stats=user_stats)


@main_bp.route('/settings')
@login_required
def settings():
    """Settings page"""
    return render_template('dashboard/settings.html')


@main_bp.route('/file-history')
@login_required
def file_history():
    """File history and management"""
    page = request.args.get('page', 1, type=int)
    per_page = 10

    files = EncryptedFile.query.filter_by(user_id=current_user.id).order_by(
        EncryptedFile.upload_date.desc()
    ).paginate(page=page, per_page=per_page)

    return render_template('dashboard/file_history.html', files=files)


@main_bp.route('/analysis-history')
@login_required
def analysis_history():
    """Password analysis history"""
    page = request.args.get('page', 1, type=int)
    per_page = 10

    analyses = PasswordAnalysis.query.filter_by(user_id=current_user.id).order_by(
        PasswordAnalysis.created_at.desc()
    ).paginate(page=page, per_page=per_page)

    return render_template('dashboard/analysis_history.html', analyses=analyses)


@main_bp.route('/help')
def help():
    """Help and documentation page"""
    return render_template('help.html')


@main_bp.route('/error')
def error():
    """Error page"""
    return render_template('errors/error.html'), 500
