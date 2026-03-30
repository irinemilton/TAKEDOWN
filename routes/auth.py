from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from models import User, Project, Log
from extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user)
        return redirect(url_for('dashboard.index'))
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role') # 'client' or 'admin'
        plan = request.form.get('plan') # 'free' or 'premium'

        # Default fallback
        if not role:
            role = 'client'
        if not plan:
            plan = 'free'

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email address already registered.')
            return redirect(url_for('auth.register'))
        
        user = User(username=username, email=email, role=role, plan=plan)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard.index'))
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
