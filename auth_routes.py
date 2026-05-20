from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, SecurityLog
from utils import InputValidator, get_client_ip
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        valid_username, username_msg = InputValidator.validate_username(username)
        if not valid_username:
            flash(username_msg, 'danger')
            return redirect(url_for('auth.register'))

        valid_email, email_msg = InputValidator.validate_email(email)
        if not valid_email:
            flash(email_msg, 'danger')
            return redirect(url_for('auth.register'))

        valid_password, password_msg = InputValidator.validate_password(password)
        if not valid_password:
            flash(password_msg, 'danger')
            return redirect(url_for('auth.register'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.register'))

        # Check existing user
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('auth.register'))

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Log security event
        log = SecurityLog(
            user_id=user.id,
            action='account_created',
            description=f'New account created',
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', ''),
            status='success'
        )
        db.session.add(log)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=bool(remember_me))
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Log security event
            log = SecurityLog(
                user_id=user.id,
                action='login',
                description=f'User logged in',
                ip_address=get_client_ip(request),
                user_agent=request.headers.get('User-Agent', ''),
                status='success'
            )
            db.session.add(log)
            db.session.commit()

            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    username = current_user.username

    # Log security event
    log = SecurityLog(
        user_id=current_user.id,
        action='logout',
        description=f'User logged out',
        ip_address=get_client_ip(request),
        user_agent=request.headers.get('User-Agent', ''),
        status='success'
    )
    db.session.add(log)
    db.session.commit()

    logout_user()
    flash(f'Goodbye, {username}! You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
