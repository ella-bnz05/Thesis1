from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from services.email import send_verification_email
import random
import string
from app import mysql
import MySQLdb.cursors
from flask_login import current_user

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods =['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        enable_2fa = request.form.get('enable_2fa')

        # Basic validations
        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))

        if len(username) < 4:
            flash('Username must be at least 4 characters.', 'error')
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        try:
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                flash('Username or email already exists.', 'error')
                return redirect(url_for('signup'))

            hashed_password = generate_password_hash(password)
            verification_code = ''.join(random.choices(string.digits, k=6)) if enable_2fa else None
            is_verified = 0 if enable_2fa else 1

            # Insert user into database
            cursor.execute(
                "INSERT INTO users (username, email, password, is_verified, verification_code, role) VALUES (%s, %s, %s, %s, %s, 'user')",
                (username, email, hashed_password, is_verified, verification_code)
            )
            mysql.connection.commit()
    
            if enable_2fa:
                send_verification_email(email, verification_code)
                session['pending_verification'] = username
                flash('Verification code sent to your email. Please verify.', 'info')
                return redirect(url_for('verify_email')) 

            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            mysql.connection.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')
pass

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next')  # Save any ?next= parameter from the login redirect

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Both fields are required', 'danger')
            return redirect(url_for('login', next=next_url))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cursor.execute("""
                SELECT id, username, password, LOWER(TRIM(role)) as role 
                FROM users 
                WHERE username = %s
            """, (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                user_obj = User(
                    id=user['id'],
                    username=user['username'],
                    role=user['role']
                )
                
                print(f"LOGIN SUCCESS: {user_obj.username} as {user_obj.role}")
                
                login_user(user_obj)
                flash('Login successful', 'success')

                # Redirect to next if available, otherwise to role verifier
                return redirect(next_url or url_for('verify_role'))

            flash('Invalid credentials', 'danger')

        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error occurred', 'danger')
        finally:
            cursor.close()

    return render_template('login.html', next=next_url)
pass

@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'pending_verification' not in session:
        flash('No verification pending', 'error')
        return redirect(url_for('signup'))

    username = session['pending_verification']
    
    if request.method == 'POST':
        code_entered = request.form.get('code')
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT verification_code FROM users WHERE username = %s", 
            (username,)
        )
        user = cursor.fetchone()
        
        if user and user['verification_code'] == code_entered:
            cursor.execute(
                "UPDATE users SET is_verified = 1, verification_code = NULL "
                "WHERE username = %s",
                (username,)
            )
            mysql.connection.commit()
            session.pop('pending_verification')
            flash('Email verified! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid code. Please try again.', 'error')

    return render_template('verify_email.html')
pass

@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username  # Now works with the import
    logout_user()
    flash(f'{username} has been successfully logged out', 'success')
    return redirect(url_for('index'))
pass