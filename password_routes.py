from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models import db, PasswordAnalysis, SecurityLog
from utils import PasswordAnalyzer, get_client_ip
from datetime import datetime

password_bp = Blueprint('password', __name__, url_prefix='/password')

@password_bp.route('/analyzer')
@login_required
def analyzer():
    """Password strength analyzer page"""
    return render_template('password/analyzer.html')


@password_bp.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    """API endpoint for password analysis"""
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password required'}), 400

    try:
        # Analyze password
        analysis = PasswordAnalyzer.analyze_password(password)

        # Generate secure password suggestion
        secure_suggestion = PasswordAnalyzer.generate_secure_password()
        memorable_suggestion = PasswordAnalyzer.generate_memorable_password()

        # Save analysis to database
        password_analysis = PasswordAnalysis(
            user_id=current_user.id,
            analyzed_password=password[:50],  # Store truncated for security
            strength_level=analysis['strength_level'],
            entropy_score=analysis['entropy'],
            crack_time_estimation=analysis['crack_time'],
            has_uppercase=analysis['has_uppercase'],
            has_lowercase=analysis['has_lowercase'],
            has_numbers=analysis['has_numbers'],
            has_special_chars=analysis['has_special_chars'],
            password_length=analysis['password_length'],
            is_common=analysis['is_common'],
            recommendations='\n'.join(analysis['recommendations']),
            suggested_password=secure_suggestion
        )
        db.session.add(password_analysis)

        # Log security event
        log = SecurityLog(
            user_id=current_user.id,
            action='password_analyzed',
            description=f'Password strength analyzed',
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            status='success'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            'success': True,
            'analysis': {
                'strength_level': analysis['strength_level'],
                'entropy_score': round(analysis['entropy'], 2),
                'crack_time': analysis['crack_time'],
                'score': analysis['score'],
                'has_uppercase': analysis['has_uppercase'],
                'has_lowercase': analysis['has_lowercase'],
                'has_numbers': analysis['has_numbers'],
                'has_special_chars': analysis['has_special_chars'],
                'password_length': analysis['password_length'],
                'is_common': analysis['is_common'],
                'recommendations': analysis['recommendations'],
                'secure_suggestion': secure_suggestion,
                'memorable_suggestion': memorable_suggestion,
            },
            'analysis_id': password_analysis.id
        })

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@password_bp.route('/api/generate-password')
@login_required
def api_generate_password():
    """Generate secure password"""
    password_type = request.args.get('type', 'secure')  # secure or memorable
    length = request.args.get('length', 16, type=int)

    try:
        if password_type == 'memorable':
            password = PasswordAnalyzer.generate_memorable_password(length)
        else:
            password = PasswordAnalyzer.generate_secure_password(length)

        # Log security event
        log = SecurityLog(
            user_id=current_user.id,
            action='password_generated',
            description=f'Password generated ({password_type})',
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            status='success'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'success': True, 'password': password})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@password_bp.route('/suggestions')
@login_required
def suggestions():
    """Password suggestions page"""
    return render_template('password/suggestions.html')


@password_bp.route('/history')
@login_required
def history():
    """Password analysis history"""
    page = request.args.get('page', 1, type=int)
    per_page = 10

    analyses = PasswordAnalysis.query.filter_by(user_id=current_user.id).order_by(
        PasswordAnalysis.created_at.desc()
    ).paginate(page=page, per_page=per_page)

    return render_template('password/history.html', analyses=analyses)
