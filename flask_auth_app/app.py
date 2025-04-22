from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for, abort, send_file, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image
import re
import spacy
import os
import PyPDF2
from io import BytesIO
from datetime import datetime
import shutil

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'flask_auth'

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

def extract_text_from_pdf(filepath):
    text = ""
    with open(filepath, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_image(filepath):
    image = Image.open(filepath)
    return pytesseract.image_to_string(image)

def clean_ocr_text(text):
    replacements = {
        "‘": "'", "’": "'", "“": '"', "”": '"',  
        "—": "-", "–": "-",  
        "ﬂ": "fl", "ﬁ": "fi",  
        " mus ": " Imus ",  
        "fullment": "fulfillment",  
        "Cavite State Universitv": "Cavite State University",  
    }
    for wrong, right in replacements.items():
        text = text.replace(wrong, right)
    return text

def extract_title(lines):
    title_candidates = []
    for line in lines[:15]:  
        if line.isupper() and len(re.findall(r'\b[A-Z]{2,}\b', line)) > 3:
            title_candidates.append(line)
        elif title_candidates:  
            break  
    return " ".join(title_candidates).strip('.,') if title_candidates else "Not Found"

def extract_authors(lines):
    author_lines = []
    capture_authors = False  

    for line in lines:
        if "Bachelor of Science" in line:
            capture_authors = True  
            continue

        if capture_authors:
            if re.search(r"\b(?:JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER)\b", line):
                break
            
            if line.isupper() and len(line.split()) > 1 and len(line) < 50:
                if not re.search(r'\b(GAME|PROJECT|INTERACTIVE|COMBAT|STUDY|METHOD|INFORMATION|DEPARTMENT|UNIVERSITY|FACULTY|CAMPUS|CITY)\b', line):
                    author_lines.append(line)

    return ", ".join(author_lines) if author_lines else "Not Found"

def extract_keywords(title):
    doc = nlp(title)
    keywords = set()

    for chunk in doc.noun_chunks:
        if 2 <= len(chunk.text.split()) <= 5:
            keywords.add(chunk.text)
    
    for token in doc:
        if token.pos_ in {"NOUN", "PROPN"} and not token.is_stop:
            keywords.add(token.text)
    
    common_words = {"method", "study", "studies", "information", "extraction", "science", "thesis", "project"}
    filtered_keywords = [kw for kw in keywords if kw.lower() not in common_words]
    
    return ", ".join(sorted(filtered_keywords)) if filtered_keywords else "Not Found"

def extract_info(text):
    text = clean_ocr_text(text)
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    
    info = {
        "Title": extract_title(lines),
        "Author": extract_authors(lines),
        "School": "Not Found",
        "Year Made": "Not Found",
        "Keywords": "Not Found"
    }
    
    if info["Title"] != "Not Found":
        info["Keywords"] = extract_keywords(info["Title"])
    
    school_keywords = ["Cavite State University", "Department of Computer Studies", "Imus Campus"]
    detected_schools = [school for school in school_keywords if school in text]
    info["School"] = ", ".join(detected_schools) if detected_schools else "Not Found"
    
    year_match = re.search(r"\b(19|20)\d{2}\b", text)
    if year_match:
        info["Year Made"] = year_match.group(0)
    
    return info

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
        password = request.form.get('password', '').strip()

        if not username:
            flash('Username is required', 'error')
            return redirect(url_for('signup'))
        
        if not password:
            flash('Password is required', 'error')
            return redirect(url_for('signup'))
            
        if len(username) < 4:
            flash('Username must be at least 4 characters', 'error')
            return redirect(url_for('signup'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('signup'))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already taken. Please choose another.', 'error')
                return redirect(url_for('signup'))

            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, 'user')",
                (username, hashed_password)
            )
            mysql.connection.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
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
    
    # Get stats
    cursor.execute("""
        SELECT 
            COUNT(*) as total_theses,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as published,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
        FROM thesis_submissions
    """)
    stats = cursor.fetchone()
    
    # Get recent submissions with published thesis info
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
    return render_template('user_dashboard.html')
@app.route('/theses')
@login_required
def browse_theses():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get search query if exists
    search_query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Items per page
    
    if search_query:
        cursor.execute("""
            SELECT * FROM published_theses
            WHERE title LIKE %s OR authors LIKE %s OR keywords LIKE %s
            ORDER BY published_at DESC
            LIMIT %s OFFSET %s
        """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', per_page, (page-1)*per_page))
    else:
        cursor.execute("""
            SELECT * FROM published_theses
            ORDER BY published_at DESC
            LIMIT %s OFFSET %s
        """, (per_page, (page-1)*per_page))
    
    theses = cursor.fetchall()
    
    # Get total count for pagination
    if search_query:
        cursor.execute("""
            SELECT COUNT(*) as total FROM published_theses
            WHERE title LIKE %s OR authors LIKE %s OR keywords LIKE %s
        """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute("SELECT COUNT(*) as total FROM published_theses")
    
    total = cursor.fetchone()['total']
    
    return render_template('browse_theses.html', 
                         theses=theses, 
                         search_query=search_query,
                         page=page,
                         per_page=per_page,
                         total=total)

@app.route('/thesis/<int:thesis_id>')
@login_required
def view_thesis(thesis_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT pt.*, u.username as publisher_username
        FROM published_theses pt
        JOIN users u ON pt.published_by = u.id
        WHERE pt.id = %s
    """, (thesis_id,))
    thesis = cursor.fetchone()
    
    if not thesis:
        abort(404)
    if not os.path.exists(thesis['file_path']):
        flash('Thesis document not available for viewing', 'danger')
        return redirect(url_for('browse_theses'))
    
    return render_template('thesis_detail.html', thesis=thesis)

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
            COUNT(*) as total_theses,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as published,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
        FROM thesis_submissions
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
                flash('Thesis restored successfully', 'success')
            elif action == 'delete':
                cursor.execute("""
                    DELETE FROM thesis_submissions 
                    WHERE id = %s AND status = 'rejected'
                """, (thesis_id,))
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
                flash('User deleted successfully.', 'success')
            elif action == 'change_role':
                new_role = request.form.get('new_role')
                cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
                flash('User role updated.', 'success')
            mysql.connection.commit()
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

    # Check file status
    file_exists = submission['file_path'] and os.path.exists(submission['file_path'])
    file_missing = not file_exists and submission.get('file_persisted', False)

    if request.method == 'POST':
        action = request.form.get('action')
        
        # Handle rejection
        if action == 'reject':
            try:
                cursor.execute("""
                    UPDATE thesis_submissions 
                    SET status = 'rejected', deleted_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
                mysql.connection.commit()
                flash('Thesis moved to trash', 'success')
                return redirect(url_for('admin_submissions'))
            except Exception as e:
                mysql.connection.rollback()
                flash(f'Error rejecting thesis: {str(e)}', 'danger')
                return redirect(url_for('admin_submissions'))

        # Handle file upload - require PDF for approval
        revised_file = request.files.get('revised_file')
        current_file = submission['file_path']

        if action == 'approve' and (not revised_file or not revised_file.filename.lower().endswith('.pdf')):
            flash('You must upload a PDF file before approving', 'danger')
            return redirect(url_for('review_submission', submission_id=submission_id))

        if revised_file and revised_file.filename != '':
            if allowed_file(revised_file.filename):
                # Ensure we save as PDF
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
        elif not submission.get('file_persisted', False) and file_exists:
            cursor.execute("""
                UPDATE thesis_submissions 
                SET file_persisted = TRUE 
                WHERE id = %s
            """, (submission_id,))

        # Process metadata
        edited_title = request.form.get('title')
        edited_authors = request.form.get('authors')
        edited_school = request.form.get('school')
        edited_year = request.form.get('year_made')
        edited_keywords = request.form.get('keywords')
        notes = request.form.get('notes')

        try:
            # Process text extraction
            num_pages = 0
            page_texts = []
            if current_file and os.path.exists(current_file):
                if current_file.lower().endswith('.pdf'):
                    with open(current_file, 'rb') as f:
                        reader = PyPDF2.PdfReader(f)
                        num_pages = len(reader.pages)
                        for i, page in enumerate(reader.pages):
                            text = page.extract_text()
                            if text:
                                page_texts.append({'page_number': i+1, 'text': text})

            # Save version history
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

            # Update submission
            cursor.execute("""
                UPDATE thesis_submissions
                SET title = %s, authors = %s, school = %s, year_made = %s, keywords = %s,
                    status = %s, num_pages = %s
                WHERE id = %s
            """, (
                edited_title,
                edited_authors,
                edited_school,
                edited_year,
                edited_keywords,
                'approved' if action == 'approve' else 'pending',
                num_pages,
                submission_id
            ))

            # Publish if approved
            if action == 'approve':
                if not current_file or not os.path.exists(current_file):
                    raise Exception("Thesis file not found for publishing")

                # Ensure we're publishing a PDF
                if not current_file.lower().endswith('.pdf'):
                    raise Exception("Only PDF files can be published")

                # Create published directory structure
                publish_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'published')
                os.makedirs(publish_dir, exist_ok=True)

                # Generate PDF filename
                pdf_filename = f"{submission_id}_{secure_filename(edited_title)}.pdf"
                publish_path = os.path.join(publish_dir, pdf_filename)

                # Copy the file
                shutil.copy2(current_file, publish_path)

                # Insert into published_theses
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

                # Store page texts
                for page in page_texts:
                    cursor.execute("""
                        INSERT INTO thesis_pages 
                        (thesis_id, page_number, page_text)
                        VALUES (%s, %s, %s)
                    """, (published_id, page['page_number'], page['text']))

            mysql.connection.commit()
            flash('Thesis published!' if action == 'approve' else 'Changes saved', 'success')
            return redirect(url_for('admin_submissions'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error processing submission: {str(e)}', 'danger')
            return redirect(url_for('review_submission', submission_id=submission_id))

    # GET request - show preview if image
    preview_url = None
    if submission['file_path'] and os.path.exists(submission['file_path']):
        if submission['file_path'].lower().endswith(('.png', '.jpg', '.jpeg')):
            preview_url = url_for('static', filename='uploads/submissions/' + os.path.basename(submission['file_path']))

    return render_template('review_submission.html', 
                         submission=submission,
                         preview_url=preview_url,
                         existing_file=os.path.basename(submission['file_path']) if submission['file_path'] else None,
                         file_missing=file_missing,
                         page_texts=cursor.fetchall() if 'page_texts' in locals() else [])

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
            return redirect(url_for('admin_submissions'))  # Make sure to redirect here

        # Move file to published directory
        original_path = submission['revised_file_path'] or submission['file_path']
        if not original_path:  # Check if path exists
            flash('No file path found for this submission', 'danger')
            return redirect(url_for('admin_submissions'))

        filename = os.path.basename(original_path)
        publish_path = os.path.join(app.config['UPLOAD_FOLDER'], 'published', filename)
        os.makedirs(os.path.dirname(publish_path), exist_ok=True)

        if os.path.exists(original_path):
            os.rename(original_path, publish_path)
        else:
            flash('Original file not found', 'danger')
            return redirect(url_for('admin_submissions'))

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
    
    # GET the existing thesis first to verify it exists
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
            # Start transaction
            mysql.connection.begin()
            
            # 1. First update published_theses
            cursor.execute("""
                UPDATE published_theses
                SET title = %s, authors = %s, school = %s, 
                    year_made = %s, keywords = %s
                WHERE id = %s
            """, (title, authors, school, year_made, keywords, thesis_id))
            
            # 2. Then insert into version history
            cursor.execute("""
                INSERT INTO thesis_versions
                (thesis_id, edited_title, edited_authors, 
                 edited_school, edited_year_made, edited_keywords, 
                 notes, edited_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                thesis_id,  # Using the same ID that exists in published_theses
                title, 
                authors,
                school,
                year_made,
                keywords,
                "Metadata updated via edit", 
                current_user.id
            ))
            
            # 3. Also update the original submission (optional but recommended)
            if thesis.get('submission_id'):
                cursor.execute("""
                    UPDATE thesis_submissions
                    SET title = %s, authors = %s, school = %s,
                        year_made = %s, keywords = %s
                    WHERE id = %s
                """, (title, authors, school, year_made, keywords, thesis['submission_id']))
            
            mysql.connection.commit()
            flash('Thesis updated successfully!', 'success')
            return redirect(url_for('view_thesis', thesis_id=thesis_id))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating thesis: {str(e)}', 'danger')
            # For debugging - print the exact query that failed
            print(f"Failed query: {cursor._last_executed}")
    
    return render_template('edit_thesis.html', thesis=thesis)
@app.route('/admin/delete-thesis/<int:thesis_id>', methods=['POST'])
@login_required
def delete_published_thesis(thesis_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    try:
        # Start transaction
        mysql.connection.begin()
        
        # First delete related records
        cursor.execute("DELETE FROM thesis_pages WHERE thesis_id = %s", (thesis_id,))
        cursor.execute("DELETE FROM thesis_versions WHERE thesis_id = %s", (thesis_id,))
        
        # Get file path before deletion
        cursor.execute("SELECT file_path FROM published_theses WHERE id = %s", (thesis_id,))
        thesis = cursor.fetchone()
        
        if not thesis:
            flash('Thesis not found', 'danger')
            return redirect(url_for('browse_theses'))

        # Delete from database
        cursor.execute("DELETE FROM published_theses WHERE id = %s", (thesis_id,))
        
        # Delete the file
        if thesis['file_path'] and os.path.exists(thesis['file_path']):
            try:
                os.remove(thesis['file_path'])
            except Exception as e:
                print(f"Error deleting file: {e}")
                # Continue with DB deletion even if file delete fails

        mysql.connection.commit()
        flash('Thesis deleted successfully', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting thesis: {str(e)}', 'danger')
    
    return redirect(url_for('browse_theses'))
@app.route('/logout')
@login_required
def logout():
    username = current_user.username  # Get username before logout
    logout_user()
    flash(f'{username} has been successfully logged out', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)