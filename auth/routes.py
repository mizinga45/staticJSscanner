from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, logout_user, login_required
from models import db, User, ScanResult, ManagerLink
from auth.forms import RegistrationForm, LoginForm
from flask_bcrypt import Bcrypt

auth_bp = Blueprint('auth', __name__, template_folder='../templates')
bcrypt = Bcrypt()


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            full_name=form.full_name.data,
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            password_hash=hashed
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.email == form.email.data) | (User.username == form.email.data)
        ).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            # Redirect based on role
            if user.is_manager:
                return redirect(url_for('main.manager_panel'))
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)


@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('landing'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Generate invite code for developer
    if request.method == 'POST' and not current_user.is_manager:
        current_user.generate_invite_code()
        db.session.commit()
        flash(f'New invite code generated: {current_user.invite_code}', 'success')

    scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).all()
    total_vulns = sum(s.total_vulns for s in scans)
    return render_template('profile.html', user=current_user, scans=scans, total_vulns=total_vulns)
