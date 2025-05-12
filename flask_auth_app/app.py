from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for, abort, send_file, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
from PIL import Image
import spacy
import os
import PyPDF2
from datetime import datetime, timedelta
import shutil
from email_utils import send_verification_email 
from email_utils import generate_code, send_verification_email
import smtplib
from email.mime.text import MIMEText
import random
import string
import smtplib
from email.mime.text import MIMEText
import os
from markupsafe import Markup

from ocr_ner_utils import (
    extract_text_from_pdf,
    extract_text_from_image,
    extract_info
)

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'
# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'flask_auth'

# Gmail SMTP Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True  # For security (TLS encryption)
app.config['MAIL_USERNAME'] = 'compscithesis@gmail.com'  
app.config['MAIL_PASSWORD'] = 'yrrl idjh teci uamk'  

# Configure upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

mysql = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load NLP model
nlp = spacy.load("en_core_web_lg")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = str(role).lower().strip()
        
    def get_id(self):
        return str(self.id)
        
    def is_admin(self):
        return self.role == 'admin'
    
@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        print(f"Loading user: {user['username']} with role: {user['role']}")
        return User(user['id'], user['username'], user['role'])
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Store search query in session
        session['search_query'] = request.form.get('search')
        flash('Please login to view search results', 'info')
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '') or session.get('search_query', '')
    
    if not query:
        return redirect(url_for('browse_theses'))

    # Store query in session so it's available after login if needed
    session['search_query'] = query

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Search metadata
    cursor.execute("""
        SELECT pt.* 
        FROM published_theses pt
        WHERE pt.title LIKE %s OR pt.authors LIKE %s OR pt.keywords LIKE %s
        ORDER BY pt.published_at DESC
    """, (f'%{query}%', f'%{query}%', f'%{query}%'))
    metadata_results = cursor.fetchall()

    # Search in full text
    cursor.execute("""
        SELECT pt.*, tp.page_number,
               MATCH(tp.page_text) AGAINST(%s IN NATURAL LANGUAGE MODE) as relevance
        FROM thesis_pages tp
        JOIN published_theses pt ON tp.thesis_id = pt.id
        WHERE MATCH(tp.page_text) AGAINST(%s IN NATURAL LANGUAGE MODE)
        ORDER BY relevance DESC
    """, (query, query))
    page_results = cursor.fetchall()

    return render_template('search_results.html',
                           query=query,
                           metadata_results=metadata_results,
                           page_results=page_results)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

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
            verification_code = ''.join(random.choices(string.digits, k=6))
            code_expires = datetime.now() + timedelta(minutes=10)  # Code expires in 10 minutes

            # Insert user into database (always unverified initially)
            cursor.execute(
                "INSERT INTO users (username, email, password, is_verified, verification_code, code_expires, role) VALUES (%s, %s, %s, %s, %s, %s, 'user')",
                (username, email, hashed_password, 0, verification_code, code_expires)
            )
            mysql.connection.commit()
    
            send_verification_email(email, verification_code)
            session['pending_verification'] = username
            flash('Verification code sent to your email. Please verify.', 'info')
            return redirect(url_for('verify_email')) 

        except Exception as e:
            mysql.connection.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Both fields are required', 'danger')
            return redirect(url_for('login', next=next_url))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cursor.execute("""
                SELECT id, username, password, LOWER(TRIM(role)) as role, is_verified
                FROM users 
                WHERE username = %s
            """, (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                if not user['is_verified']:
                    flash('Please verify your email before logging in.', 'danger')
                    session['pending_verification'] = username
                    return redirect(url_for('verify_email'))
                
                user_obj = User(
                    id=user['id'],
                    username=user['username'],
                    role=user['role']
                )
                
                login_user(user_obj)
                flash('Login successful', 'success')
                return redirect(next_url or url_for('verify_role'))

            flash('Invalid credentials', 'danger')

        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error occurred', 'danger')
        finally:
            cursor.close()

    return render_template('login.html', next=next_url)

@app.route('/verify-role')
@login_required
def verify_role():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT LOWER(TRIM(role)) as role 
        FROM users 
        WHERE id = %s
    """, (current_user.id,))
    actual_role = cursor.fetchone()['role']
    cursor.close()
    
    current_user.role = actual_role
    
    if actual_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        abort(403)
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Corrected stats calculation
    cursor.execute("""
        SELECT
            (
                (SELECT COUNT(*) FROM thesis_submissions WHERE status IN ('pending', 'rejected'))
                +
                (SELECT COUNT(*) FROM published_theses)
            ) AS total_submissions,
            (SELECT COUNT(*) FROM thesis_submissions WHERE status = 'pending') AS pending,
            (SELECT COUNT(*) FROM thesis_submissions WHERE status = 'rejected') AS rejected,
            (SELECT COUNT(*) FROM published_theses) AS total_published
    """)
    stats = cursor.fetchone()
    
    # Recent submissions (no change)
    cursor.execute("""
        SELECT 
            ts.id, 
            ts.title, 
            ts.status, 
            ts.created_at,
            pt.id as published_thesis_id
        FROM thesis_submissions ts
        LEFT JOIN published_theses pt ON ts.id = pt.submission_id
        ORDER BY ts.created_at DESC 
        LIMIT 5
    """)
    recent_submissions = cursor.fetchall()
    
    return render_template('admin_dashboard.html', 
                         stats=stats,
                         recent_submissions=recent_submissions)
@app.route('/user-dashboard')
@login_required
def user_dashboard():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get stats
    cursor.execute("""
        SELECT COUNT(*) as total_published FROM published_theses
    """)
    stats = cursor.fetchone()
    
    # Get recent theses
    cursor.execute("""
        SELECT * FROM published_theses
        ORDER BY published_at DESC
        LIMIT 3
    """)
    recent_theses = cursor.fetchall()
    
    return render_template('user_dashboard.html', 
                         stats=stats,
                         recent_theses=recent_theses)

@app.route('/browse-theses')
@login_required
def browse_theses():
    # Redirect admin users to admin version
    if current_user.is_admin():
        return redirect(url_for('admin_browse_theses'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = """
        SELECT pt.* 
        FROM published_theses pt
        WHERE 1=1
    """
    
    if search_query:
        query += """
            AND (pt.title LIKE %s OR pt.authors LIKE %s OR pt.keywords LIKE %s)
        """
        params = (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
    else:
        params = ()
    
    query += " ORDER BY pt.published_at DESC LIMIT %s OFFSET %s"
    params += (per_page, (page-1)*per_page)
    
    cursor.execute(query, params)
    theses = cursor.fetchall()
    
    # Get total count
    count_query = "SELECT COUNT(*) as total FROM published_theses WHERE 1=1"
    if search_query:
        count_query += " AND (title LIKE %s OR authors LIKE %s OR keywords LIKE %s)"
        count_params = (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
    else:
        count_params = ()
    
    cursor.execute(count_query, count_params)
    total = cursor.fetchone()['total']
    
    return render_template('user_browse_theses.html', 
                         theses=theses, 
                         search_query=search_query,
                         page=page,
                         per_page=per_page,
                         total=total,
                         total_pages=(total + per_page - 1) // per_page)

@app.route('/admin/browse-theses')
@login_required
def admin_browse_theses():
    if not current_user.is_admin():
        abort(403)
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = """
        SELECT pt.*, u.username as publisher_username
        FROM published_theses pt
        JOIN users u ON pt.published_by = u.id
        WHERE 1=1
    """
    
    if search_query:
        query += """
            AND (pt.title LIKE %s OR pt.authors LIKE %s OR pt.keywords LIKE %s)
        """
        params = (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
    else:
        params = ()
    
    query += " ORDER BY pt.published_at DESC LIMIT %s OFFSET %s"
    params += (per_page, (page-1)*per_page)
    
    cursor.execute(query, params)
    theses = cursor.fetchall()
    
    # Get total count
    count_query = "SELECT COUNT(*) as total FROM published_theses WHERE 1=1"
    if search_query:
        count_query += " AND (title LIKE %s OR authors LIKE %s OR keywords LIKE %s)"
        count_params = (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')
    else:
        count_params = ()
    
    cursor.execute(count_query, count_params)
    total = cursor.fetchone()['total']
    
    return render_template('admin_browse_theses.html', 
                         theses=theses, 
                         search_query=search_query,
                         page=page,
                         per_page=per_page,
                         total=total,
                         total_pages=(total + per_page - 1) // per_page)

@app.route('/process-image-search', methods=['POST'])
@login_required
def process_image_search():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    if file and allowed_file(file.filename):
        try:
            # Save temporary image
            filename = secure_filename(f"search_{current_user.id}_{datetime.now().timestamp()}.jpg")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_search', filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            
            # Extract text using OCR
            text = extract_text_from_image(filepath)
            
            # Process text to get important keywords (excluding common words)
            doc = nlp(text.lower())
            common_words = {'the', 'and', 'of', 'to', 'in', 'a', 'is', 'that', 'for', 'it', 'as', 'was', 'with', 'be', 'by', 'on', 'not', 'he', 'i', 'this', 'are', 'or', 'his', 'from', 'at', 'which', 'but', 'have', 'an', 'had', 'they', 'you', 'were', 'their', 'one', 'all', 'we', 'can', 'her', 'has', 'there', 'been', 'if', 'more', 'when', 'will', 'would', 'who', 'so', 'no'}
            
            keywords = []
            for token in doc:
                if (token.pos_ in ['NOUN', 'PROPN', 'ADJ'] and 
                    token.text not in common_words and 
                    len(token.text) > 3 and 
                    not token.is_stop):
                    keywords.append(token.text)
            
            # Remove duplicates and limit to 5 most relevant
            keywords = list(set(keywords))[:5]
            
            # Clean up
            os.remove(filepath)
            
            return jsonify({
                'success': True,
                'keywords': ' '.join(keywords)
            })
            
        except Exception as e:
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'Invalid file type'})
@app.route('/thesis/<int:thesis_id>')
@login_required
def view_thesis(thesis_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Record view history
    cursor.execute("""
        INSERT INTO user_view_history (user_id, thesis_id)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE viewed_at = CURRENT_TIMESTAMP
    """, (current_user.id, thesis_id))
    mysql.connection.commit()
    
    # Get thesis details
    cursor.execute("""
        SELECT pt.*, u.username as publisher_username
        FROM published_theses pt
        JOIN users u ON pt.published_by = u.id
        WHERE pt.id = %s
    """, (thesis_id,))
    thesis = cursor.fetchone()
    
    if not thesis:
        abort(404)
    
    # Check if bookmarked
    cursor.execute("""
        SELECT id FROM user_bookmarks
        WHERE user_id = %s AND thesis_id = %s
    """, (current_user.id, thesis_id))
    is_bookmarked = cursor.fetchone() is not None
    
    # Get introduction pages only (first 5 pages)
    cursor.execute("""
        SELECT page_text FROM thesis_pages
        WHERE thesis_id = %s AND page_number <= 5
        ORDER BY page_number
    """, (thesis_id,))
    intro_pages = [page['page_text'] for page in cursor.fetchall()]
    
    # If search query exists, find matching pages but exclude introduction
    search_query = request.args.get('q', '')
    matching_pages = []
    
    if search_query:
        # Get all pages that match the search query (excluding common words)
        cursor.execute("""
            SELECT page_number, page_text 
            FROM thesis_pages
            WHERE thesis_id = %s 
            AND MATCH(page_text) AGAINST(%s IN BOOLEAN MODE)
            AND page_number > 5  # Skip introduction
            ORDER BY page_number
        """, (thesis_id, f'+{search_query}*'))
        
        matching_pages = cursor.fetchall()
    
    # Choose template based on user role
    if current_user.is_admin():
        return render_template('thesis_detail.html', 
                             thesis=thesis,
                             intro_pages=intro_pages,
                             matching_pages=matching_pages,
                             search_query=search_query,
                             is_bookmarked=is_bookmarked)
    else:
        return render_template('user_thesis_detail.html', 
                             thesis=thesis,
                             intro_pages=intro_pages,
                             matching_pages=matching_pages,
                             search_query=search_query,
                             is_bookmarked=is_bookmarked)
    
@app.route('/thesis-file/<int:thesis_id>')
@login_required
def serve_thesis_file(thesis_id):
    # Get the file path from the database based on thesis_id
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT file_path FROM published_theses WHERE id = %s", (thesis_id,))
    result = cursor.fetchone()
    cursor.close()

    if not result:
        abort(404)

    file_path = result['file_path']

    response = make_response(send_file(file_path))
    
    # Prevent download via Content-Disposition
    response.headers["Content-Disposition"] = "inline; filename=view.pdf"
    
    # Additional headers to discourage saving/downloading
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return response
@app.route('/admin/upload', methods=['POST'])
@login_required

def admin_upload():
    if not current_user.is_admin():
        abort(403)
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if not file or not allowed_file(file.filename):
        flash('Invalid file type', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Save the original file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'submissions', filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        file.save(filepath)
        
        # Extract text
        if filename.lower().endswith('.pdf'):
            text = extract_text_from_pdf(filepath)
        else:
            text = extract_text_from_image(filepath)
        
        # Extract metadata
        thesis_info = extract_info(text)
        
        # Store in database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            INSERT INTO thesis_submissions 
            (admin_id, file_path, original_filename, title, authors, school, year_made, keywords, extracted_text)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            current_user.id,
            filepath,
            filename,
            thesis_info['Title'],
            thesis_info['Author'],
            thesis_info['School'],
            thesis_info['Year Made'],
            thesis_info['Keywords'],
            text
        ))
        submission_id = cursor.lastrowid
        mysql.connection.commit()
        
        # Immediately redirect to review page
        log_admin_action(
            'thesis_upload',
            f"Uploaded new thesis file: {filename}",
            target_id=submission_id,
            target_type='thesis_submission'
        )
        flash('Thesis uploaded successfully. Please review the extracted information.', 'success')
        return redirect(url_for('review_submission', submission_id=submission_id))
        
    except Exception as e:
        mysql.connection.rollback()
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
        flash(f'Error processing file: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    
def extract_page_count(filepath):
    if filepath.lower().endswith('.pdf'):
        with open(filepath, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            return len(reader.pages)
    return 1  # For images, consider each as one page

# First, modify the admin_submissions route to handle status filtering
@app.route('/admin/submissions')
@login_required
def admin_submissions():
    if not current_user.is_admin():
        abort(403)

    # Change this line to default to 'pending'
    status_filter = request.args.get('status', 'pending')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    query = """
        SELECT ts.*, u.username as admin_username 
        FROM thesis_submissions ts
        JOIN users u ON ts.admin_id = u.id
    """
    
    if status_filter in ['pending', 'approved', 'rejected']:
        query += " WHERE ts.status = %s"
        params = (status_filter,)
    else:
        params = ()

    query += " ORDER BY ts.created_at DESC"
    
    cursor.execute(query, params)
    submissions = cursor.fetchall()

    # Get stats
    cursor.execute("""
        SELECT
            (
                (SELECT COUNT(*) FROM thesis_submissions WHERE status IN ('pending', 'rejected'))
                +
                (SELECT COUNT(*) FROM published_theses)
            ) AS total_submissions,
            (SELECT COUNT(*) FROM thesis_submissions WHERE status = 'pending') AS pending,
            (SELECT COUNT(*) FROM thesis_submissions WHERE status = 'rejected') AS rejected,
            (SELECT COUNT(*) FROM published_theses) AS total_published
    """)
    stats = cursor.fetchone()


    return render_template('admin_submissions.html',
                         submissions=submissions,
                         stats=stats,
                         current_filter=status_filter)


@app.route('/admin/trash', methods=['GET', 'POST'])
@login_required
def manage_trash():
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        action = request.form.get('action')
        thesis_id = request.form.get('thesis_id')

        try:
            if action == 'restore':
                cursor.execute("""
                    UPDATE thesis_submissions 
                    SET status = 'pending', deleted_at = NULL
                    WHERE id = %s
                """, (thesis_id,))
                log_admin_action(
                    'thesis_restore',
                    f"Restored thesis from trash: {thesis_id}",
                    target_id=thesis_id,
                    target_type='thesis_submission'
                )

                flash('Thesis restored successfully', 'success')
            elif action == 'delete':
                cursor.execute("""
                    DELETE FROM thesis_submissions 
                    WHERE id = %s AND status = 'rejected'
                """, (thesis_id,))
                log_admin_action(
                    'thesis_permanent_delete',
                    f"Permanently deleted thesis: {thesis_id}",
                    target_id=thesis_id,
                    target_type='thesis_submission'
                )
                flash('Thesis permanently deleted', 'success')

            mysql.connection.commit()
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error processing request: {str(e)}', 'danger')

    # Auto-delete old rejected items
    cursor.execute("""
        SELECT * FROM thesis_submissions 
        WHERE status = 'rejected' 
        AND deleted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
    """)
    old_rejected = cursor.fetchall()
    if old_rejected:
        try:
            cursor.executemany("""
                DELETE FROM thesis_submissions 
                WHERE id = %s
            """, [(item['id'],) for item in old_rejected])
            mysql.connection.commit()
        except Exception as e:
            mysql.connection.rollback()
            print(f"Error auto-deleting old rejected items: {e}")

    # Get all rejected items
    cursor.execute("""
        SELECT ts.*, u.username as admin_username 
        FROM thesis_submissions ts
        JOIN users u ON ts.admin_id = u.id
        WHERE ts.status = 'rejected'
        ORDER BY ts.deleted_at DESC
    """)
    rejected_items = cursor.fetchall()

    # Pass current time to the template
    return render_template('manage_trash.html', rejected_items=rejected_items, now=datetime.now())

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    search_query = request.args.get('search', '').strip()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        try:
            if action == 'delete':
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                log_admin_action(
                    'user_delete', 
                    f"Deleted user with ID {user_id}",
                    target_id=user_id,
                    target_type='user'
                )
                flash('User deleted successfully.', 'success')
            elif action == 'change_role':
                new_role = request.form.get('new_role')
                cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
                log_admin_action(
                    'user_role_change',
                    f"Changed role of user {user_id} to {new_role}",
                    target_id=user_id,
                    target_type='user'
                )
                flash('User role updated.', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error: {str(e)}', 'danger')

    # Modified query to include search
    query = "SELECT id, username, email, role FROM users WHERE id != %s"
    params = [current_user.id]
    
    if search_query:
        query += " AND username LIKE %s"
        params.append(f'%{search_query}%')

    cursor.execute(query, tuple(params))
    users = cursor.fetchall()

    return render_template('manage_users.html', 
                         users=users,
                         search_query=search_query)


@app.route('/admin/submission/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def review_submission(submission_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT ts.*, u.username as admin_username 
        FROM thesis_submissions ts
        JOIN users u ON ts.admin_id = u.id
        WHERE ts.id = %s
    """, (submission_id,))
    submission = cursor.fetchone()

    if not submission:
        abort(404)

    file_exists = submission['file_path'] and os.path.exists(submission['file_path'])
    file_missing = not file_exists and submission.get('file_persisted', False)

    if request.method == 'POST':
        action = request.form.get('action')

        revised_file = request.files.get('revised_file')
        current_file = submission['file_path']

        if revised_file and revised_file.filename != '':
            if allowed_file(revised_file.filename):
                filename = secure_filename(f"{submission_id}_{os.path.splitext(revised_file.filename)[0]}.pdf")
                current_file = os.path.join(app.config['UPLOAD_FOLDER'], 'submissions', filename)
                os.makedirs(os.path.dirname(current_file), exist_ok=True)
                revised_file.save(current_file)
                cursor.execute("""
                    UPDATE thesis_submissions 
                    SET file_path = %s, file_persisted = TRUE, file_reuploaded = TRUE
                    WHERE id = %s
                """, (current_file, submission_id))
            else:
                flash('Invalid file type - must be PDF for final submission', 'danger')
                return redirect(url_for('review_submission', submission_id=submission_id))

        elif not file_exists and not submission.get('file_persisted', False):
            flash('No file uploaded yet.', 'danger')
            return redirect(url_for('review_submission', submission_id=submission_id))

        # Process metadata
        edited_title = request.form.get('title')
        edited_authors = request.form.get('authors')
        edited_school = request.form.get('school')
        edited_year = request.form.get('year_made')
        edited_keywords = request.form.get('keywords')
        notes = request.form.get('notes')

        try:
            page_texts = []
            num_pages = 0
            if current_file and os.path.exists(current_file) and current_file.lower().endswith('.pdf'):
                with open(current_file, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    num_pages = len(reader.pages)
                    for i, page in enumerate(reader.pages):
                        text = page.extract_text()
                        page_texts.append({'page_number': i+1, 'text': text})

            # Save version
            cursor.execute("""
                INSERT INTO thesis_versions
                (thesis_id, edited_title, edited_authors, edited_school, 
                 edited_year_made, edited_keywords, notes, edited_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                edited_title,
                edited_authors,
                edited_school,
                edited_year,
                edited_keywords,
                notes,
                current_user.id
            ))

            if action == 'reject':
                cursor.execute("""
                    UPDATE thesis_submissions
                    SET status = 'rejected', deleted_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
                mysql.connection.commit()
                log_admin_action('thesis_reject', f"Rejected thesis submission {submission_id}", submission_id, 'thesis_submission')
                flash('Thesis moved to trash', 'success')
                return redirect(url_for('admin_submissions'))

            elif action == 'approve':
                # Update thesis_submissions first
                cursor.execute("""
                    UPDATE thesis_submissions
                    SET title = %s, authors = %s, school = %s, year_made = %s, 
                        keywords = %s, status = 'approved', num_pages = %s
                    WHERE id = %s
                """, (
                    edited_title,
                    edited_authors,
                    edited_school,
                    edited_year,
                    edited_keywords,
                    num_pages,
                    submission_id
                ))

                # Now publish
                publish_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'published')
                os.makedirs(publish_dir, exist_ok=True)
                pdf_filename = f"{submission_id}_{secure_filename(edited_title)}.pdf"
                publish_path = os.path.join(publish_dir, pdf_filename)
                shutil.copy2(current_file, publish_path)

                cursor.execute("""
                    INSERT INTO published_theses
                    (submission_id, file_path, title, authors, school, 
                     year_made, keywords, published_by, num_pages)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    submission_id,
                    publish_path,
                    edited_title,
                    edited_authors,
                    edited_school,
                    edited_year,
                    edited_keywords,
                    current_user.id,
                    num_pages
                ))
                published_id = cursor.lastrowid

                # Insert pages
                for page in page_texts:
                    cursor.execute("""
                        INSERT INTO thesis_pages
                        (thesis_id, page_number, page_text)
                        VALUES (%s, %s, %s)
                    """, (published_id, page['page_number'], page['text']))

                mysql.connection.commit()
                log_admin_action('thesis_approve', f"Approved and published thesis {submission_id} as {published_id}", published_id, 'published_thesis')
                flash('Thesis published!', 'success')
                return redirect(url_for('admin_submissions'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error processing submission: {str(e)}', 'danger')
            return redirect(url_for('review_submission', submission_id=submission_id))

    # GET request
    preview_url = None
    if submission['file_path'] and os.path.exists(submission['file_path']):
        if submission['file_path'].lower().endswith(('.png', '.jpg', '.jpeg')):
            preview_url = url_for('static', filename='uploads/submissions/' + os.path.basename(submission['file_path']))

    return render_template('review_submission.html', 
                           submission=submission,
                           preview_url=preview_url,
                           existing_file=os.path.basename(submission['file_path']) if submission['file_path'] else None,
                           file_missing=file_missing)

@app.route('/admin/publish/<int:submission_id>', methods=['POST'])
@login_required
def publish_thesis(submission_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Get the approved submission
        cursor.execute("""
            SELECT * FROM thesis_submissions 
            WHERE id = %s AND status = 'approved'
        """, (submission_id,))
        submission = cursor.fetchone()

        if not submission:
            flash('Submission not found or not approved', 'danger')
            return redirect(url_for('admin_submissions'))

        # Determine original file path
        original_path = submission['file_path']
        if not original_path or not os.path.exists(original_path):
            flash('Original file not found', 'danger')
            return redirect(url_for('admin_submissions'))

        # Move file to published folder
        filename = os.path.basename(original_path)
        publish_path = os.path.join(app.config['UPLOAD_FOLDER'], 'published', filename)
        os.makedirs(os.path.dirname(publish_path), exist_ok=True)

        shutil.copy2(original_path, publish_path)

        # Add to published theses
        cursor.execute("""
            INSERT INTO published_theses
            (submission_id, file_path, title, authors, school, year_made, keywords, published_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            submission_id,
            publish_path,
            submission['title'],
            submission['authors'],
            submission['school'],
            submission['year_made'],
            submission['keywords'],
            current_user.id
        ))

        mysql.connection.commit()
        published_id = cursor.lastrowid
        log_admin_action('manual_publish', f"Manually published thesis {submission_id} as {published_id}", published_id, 'published_thesis')

        flash('Thesis published successfully!', 'success')
        return render_template("publish_confirmation.html")

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error publishing thesis: {str(e)}', 'danger')
        return redirect(url_for('admin_submissions'))
@app.route('/admin/edit-thesis/<int:thesis_id>', methods=['GET', 'POST'])
@login_required
def edit_published_thesis(thesis_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Check if thesis exists
    cursor.execute("SELECT * FROM published_theses WHERE id = %s", (thesis_id,))
    thesis = cursor.fetchone()

    if not thesis:
        abort(404)

    if request.method == 'POST':
        title = request.form.get('title')
        authors = request.form.get('authors')
        school = request.form.get('school')
        year_made = request.form.get('year_made')
        keywords = request.form.get('keywords')

        try:
            mysql.connection.begin()

            # Update published thesis
            cursor.execute("""
                UPDATE published_theses
                SET title = %s, authors = %s, school = %s, 
                    year_made = %s, keywords = %s
                WHERE id = %s
            """, (title, authors, school, year_made, keywords, thesis_id))

            # Insert into version history
            cursor.execute("""
                INSERT INTO thesis_versions
                (thesis_id, edited_title, edited_authors, 
                 edited_school, edited_year_made, edited_keywords, 
                 notes, edited_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                thesis_id,
                title,
                authors,
                school,
                year_made,
                keywords,
                "Metadata updated via edit",
                current_user.id
            ))

            # (Optional) Update submission too if linked
            if thesis.get('submission_id'):
                cursor.execute("""
                    UPDATE thesis_submissions
                    SET title = %s, authors = %s, school = %s,
                        year_made = %s, keywords = %s
                    WHERE id = %s
                """, (title, authors, school, year_made, keywords, thesis['submission_id']))

            mysql.connection.commit()
            log_admin_action('thesis_metadata_edit', f"Edited published thesis {thesis_id}", thesis_id, 'published_thesis')

            flash('Thesis updated successfully!', 'success')
            return redirect(url_for('view_thesis', thesis_id=thesis_id))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating thesis: {str(e)}', 'danger')

    return render_template('edit_thesis.html', thesis=thesis)

@app.route('/admin/delete-thesis/<int:thesis_id>', methods=['POST'])
@login_required
def delete_published_thesis(thesis_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        mysql.connection.begin()

        # Delete related pages and versions
        cursor.execute("DELETE FROM thesis_pages WHERE thesis_id = %s", (thesis_id,))
        cursor.execute("DELETE FROM thesis_versions WHERE thesis_id = %s", (thesis_id,))

        # Get file path before deleting
        cursor.execute("SELECT file_path FROM published_theses WHERE id = %s", (thesis_id,))
        thesis = cursor.fetchone()

        if not thesis:
            flash('Thesis not found', 'danger')
            return redirect(url_for('browse_theses'))

        file_path = thesis['file_path']

        # Delete published thesis
        cursor.execute("DELETE FROM published_theses WHERE id = %s", (thesis_id,))

        mysql.connection.commit()

        # Delete file after commit (to be safe)
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Warning: could not delete file: {e}")

        log_admin_action('thesis_delete', f"Deleted published thesis {thesis_id}", thesis_id, 'published_thesis')
        flash('Thesis deleted successfully', 'success')

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting thesis: {str(e)}', 'danger')

    return redirect(url_for('browse_theses'))
def log_admin_action(action_type, description, target_id=None, target_type=None):
    """Log an admin action to the history table."""
    if not current_user.is_authenticated or not current_user.is_admin():
        return  # Only log actions by authenticated admins
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO admin_action_history 
            (admin_id, action_type, description, target_id, target_type)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            current_user.id,
            action_type,
            description,
            target_id,
            target_type
        ))
        mysql.connection.commit()
    except Exception as e:
        print(f"Failed to log admin action: {e}")
        mysql.connection.rollback()
    finally:
        cursor.close()
@app.route('/admin/history')
@login_required
def admin_action_history():
    if not current_user.is_admin():
        abort(403)

    action_type = request.args.get('action_type', '')
    admin_id = request.args.get('admin_id', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    query = """
        SELECT ah.*, u.username as admin_username
        FROM admin_action_history ah
        JOIN users u ON ah.admin_id = u.id
    """
    params = []

    filters = []
    if action_type:
        filters.append("ah.action_type = %s")
        params.append(action_type)
    if admin_id:
        filters.append("ah.admin_id = %s")
        params.append(admin_id)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY ah.performed_at DESC LIMIT %s OFFSET %s"
    params.extend([per_page, (page-1)*per_page])

    cursor.execute(query, params)
    actions = cursor.fetchall()

    count_query = "SELECT COUNT(*) as total FROM admin_action_history ah"
    if filters:
        count_query += " WHERE " + " AND ".join(filters)
    cursor.execute(count_query, params[:-2] if filters else ())
    total = cursor.fetchone()['total']

    total_pages = (total + per_page - 1) // per_page  # ✅ Important fix!

    cursor.execute("SELECT DISTINCT action_type FROM admin_action_history ORDER BY action_type")
    action_types = [row['action_type'] for row in cursor.fetchall()]

    cursor.execute("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
    admins = cursor.fetchall()

    return render_template('admin_action_history.html',
        actions=actions,
        action_types=action_types,
        admins=admins,
        current_filters={
            'action_type': action_type,
            'admin_id': admin_id
        },
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages  # ✅ Pass it here!
    )
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'pending_verification' not in session:
        flash('No verification pending', 'error')
        return redirect(url_for('signup'))

    username = session['pending_verification']
    
    if request.method == 'POST':
        if 'resend' in request.form:
            # Resend code logic
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                "SELECT email FROM users WHERE username = %s", 
                (username,)
            )
            user = cursor.fetchone()
            
            if user:
                new_code = ''.join(random.choices(string.digits, k=6))
                new_expires = datetime.now() + timedelta(minutes=10)
                
                cursor.execute(
                    "UPDATE users SET verification_code = %s, code_expires = %s WHERE username = %s",
                    (new_code, new_expires, username)
                )
                mysql.connection.commit()
                
                send_verification_email(user['email'], new_code)
                flash('New verification code sent!', 'success')
            return redirect(url_for('verify_email'))
        
        # Normal verification attempt
        code_entered = request.form.get('code')
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT verification_code, code_expires FROM users WHERE username = %s", 
            (username,)
        )
        user = cursor.fetchone()
        
        if not user or not user['verification_code']:
            flash('No verification code found. Please request a new one.', 'error')
            return redirect(url_for('verify_email'))
        
        if datetime.now() > user['code_expires']:
            flash('Verification code has expired. Please request a new one.', 'error')
            return redirect(url_for('verify_email'))
        
        if user['verification_code'] == code_entered:
            cursor.execute(
                "UPDATE users SET is_verified = 1, verification_code = NULL, code_expires = NULL "
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

@app.template_filter('highlight')
def highlight_filter(s, search_query):
    if not search_query:
        return s
    
    queries = search_query.split()
    highlighted = s
    for query in queries:
        if len(query) > 3:  # Only highlight words longer than 3 characters
            highlighted = highlighted.replace(query, f'<span class="bg-warning">{query}</span>')
            highlighted = highlighted.replace(query.title(), f'<span class="bg-warning">{query.title()}</span>')
    
    return Markup(highlighted)

@app.route('/profile-settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        try:
            # Verify current password if making any changes
            if new_username != current_user.username or new_password:
                cursor.execute("SELECT password FROM users WHERE id = %s", (current_user.id,))
                user = cursor.fetchone()
                
                if not user or not check_password_hash(user['password'], current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('profile_settings'))

            # Validate username
            if new_username != current_user.username:
                if len(new_username) < 4:
                    flash('Username must be at least 4 characters', 'danger')
                    return redirect(url_for('profile_settings'))
                
                # Check if username is already taken
                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", 
                             (new_username, current_user.id))
                if cursor.fetchone():
                    flash('Username already taken', 'danger')
                    return redirect(url_for('profile_settings'))

            # Validate password if changing
            if new_password:
                if len(new_password) < 6:
                    flash('Password must be at least 6 characters', 'danger')
                    return redirect(url_for('profile_settings'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('profile_settings'))

                hashed_password = generate_password_hash(new_password)
            
            # Update database
            update_query = "UPDATE users SET username = %s"
            params = [new_username]
            
            if new_password:
                update_query += ", password = %s"
                params.append(hashed_password)
            
            update_query += " WHERE id = %s"
            params.append(current_user.id)
            
            cursor.execute(update_query, tuple(params))
            mysql.connection.commit()
            
            # Update Flask-Login's current_user if username changed
            if new_username != current_user.username:
                current_user.username = new_username
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile_settings'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
            return redirect(url_for('profile_settings'))
        finally:
            cursor.close()

    return render_template('profile_settings.html')

# Bookmark routes
@app.route('/bookmark/<int:thesis_id>', methods=['POST'])
@login_required
def bookmark_thesis(thesis_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    try:
        # Check if thesis exists
        cursor.execute("SELECT id FROM published_theses WHERE id = %s", (thesis_id,))
        if not cursor.fetchone():
            abort(404)
            
        # Check if already bookmarked
        cursor.execute("""
            SELECT id FROM user_bookmarks 
            WHERE user_id = %s AND thesis_id = %s
        """, (current_user.id, thesis_id))
        
        if cursor.fetchone():
            # Remove bookmark
            cursor.execute("""
                DELETE FROM user_bookmarks 
                WHERE user_id = %s AND thesis_id = %s
            """, (current_user.id, thesis_id))
            action = 'removed'
        else:
            # Add bookmark
            cursor.execute("""
                INSERT INTO user_bookmarks (user_id, thesis_id)
                VALUES (%s, %s)
            """, (current_user.id, thesis_id))
            action = 'added'
            
        mysql.connection.commit()
        return jsonify({'success': True, 'action': action})
        
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()

@app.route('/bookmarks')
@login_required
def view_bookmarks():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get bookmarked theses with pagination
    cursor.execute("""
        SELECT pt.* 
        FROM published_theses pt
        JOIN user_bookmarks ub ON pt.id = ub.thesis_id
        WHERE ub.user_id = %s
        ORDER BY ub.created_at DESC
        LIMIT %s OFFSET %s
    """, (current_user.id, per_page, (page-1)*per_page))
    bookmarks = cursor.fetchall()
    
    # Get total count
    cursor.execute("""
        SELECT COUNT(*) as total 
        FROM user_bookmarks 
        WHERE user_id = %s
    """, (current_user.id,))
    total = cursor.fetchone()['total']
    
    return render_template('user_bookmarks.html',
                         bookmarks=bookmarks,
                         page=page,
                         per_page=per_page,
                         total=total,
                         total_pages=(total + per_page - 1) // per_page)

# Viewing history routes
@app.route('/history')
@login_required
def view_history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get view history with pagination
    cursor.execute("""
        SELECT pt.*, uv.viewed_at, uv.id as history_id
        FROM published_theses pt
        JOIN user_view_history uv ON pt.id = uv.thesis_id
        WHERE uv.user_id = %s
        ORDER BY uv.viewed_at DESC
        LIMIT %s OFFSET %s
    """, (current_user.id, per_page, (page-1)*per_page))
    history = cursor.fetchall()
    
    # Get total count
    cursor.execute("""
        SELECT COUNT(*) as total 
        FROM user_view_history 
        WHERE user_id = %s
    """, (current_user.id,))
    total = cursor.fetchone()['total']
    
    return render_template('user_history.html',
                         history=history,
                         page=page,
                         per_page=per_page,
                         total=total,
                         total_pages=(total + per_page - 1) // per_page)
@app.route('/delete-history-item/<int:item_id>', methods=['POST'])
@login_required
def delete_history_item(item_id):
    cursor = mysql.connection.cursor()
    
    try:
        # Verify the history item belongs to the current user before deleting
        cursor.execute("""
            DELETE FROM user_view_history 
            WHERE id = (
                SELECT id FROM (
                    SELECT uv.id 
                    FROM user_view_history uv
                    JOIN published_theses pt ON uv.thesis_id = pt.id
                    WHERE uv.user_id = %s AND pt.id = %s
                    LIMIT 1
                ) AS temp
            )
        """, (current_user.id, item_id))
        
        affected_rows = cursor.rowcount
        mysql.connection.commit()
        
        if affected_rows == 0:
            return jsonify({'success': False, 'error': 'Item not found or not authorized'})
            
        return jsonify({'success': True})
        
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        
@app.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    cursor = mysql.connection.cursor()
    
    try:
        cursor.execute("""
            DELETE FROM user_view_history 
            WHERE user_id = %s
        """, (current_user.id,))
        mysql.connection.commit()
        flash('Viewing history cleared successfully', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash('Error clearing history', 'danger')
    finally:
        cursor.close()
        
    return redirect(url_for('view_history'))

@app.route('/logout')
@login_required
def logout():
    username = current_user.username  # Get username before logout
    logout_user()
    flash(f'{username} has been successfully logged out', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)