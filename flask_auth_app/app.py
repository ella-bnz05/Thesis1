from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for, abort
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
def search():
    if not current_user.is_authenticated:  # Requires Flask-Login
        return redirect(url_for('login'))
    
    query = session.get('search_query', '')
    # Add your search logic here (query database, etc.)
    # results = Thesis.query.filter(Thesis.title.contains(query)).all()
    return render_template('search_results.html', query=query)  # You'll need to create this template

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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Both fields are required', 'danger')
            return redirect(url_for('login'))

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
                return redirect(url_for('verify_role'))
            
            flash('Invalid credentials', 'danger')
            
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error occurred', 'danger')
        finally:
            cursor.close()

    return render_template('login.html')

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
    
    # Get recent submissions
    cursor.execute("""
        SELECT id, title, status, created_at 
        FROM thesis_submissions 
        ORDER BY created_at DESC 
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
    
    if search_query:
        cursor.execute("""
            SELECT * FROM published_theses
            WHERE title LIKE %s OR authors LIKE %s OR keywords LIKE %s
            ORDER BY published_at DESC
        """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute("""
            SELECT * FROM published_theses
            ORDER BY published_at DESC
        """)
    
    theses = cursor.fetchall()
    return render_template('browse_theses.html', theses=theses, search_query=search_query)

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
    
    return render_template('thesis_detail.html', thesis=thesis)

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
@app.route('/admin/submissions')
@login_required
def admin_submissions():
    if not current_user.is_admin():
        abort(403)
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT ts.*, u.username as admin_username 
        FROM thesis_submissions ts
        JOIN users u ON ts.admin_id = u.id
        WHERE ts.status = 'pending'
        ORDER BY ts.created_at DESC
    """)
    submissions = cursor.fetchall()
    
    return render_template('admin_submissions.html', submissions=submissions)

@app.route('/admin/submission/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def review_submission(submission_id):
    if not current_user.is_admin():
        abort(403)
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        # Handle form submission (approval/rejection with edits)
        action = request.form.get('action')
        edited_title = request.form.get('title')
        edited_authors = request.form.get('authors')
        edited_school = request.form.get('school')
        edited_year = request.form.get('year_made')
        edited_keywords = request.form.get('keywords')
        notes = request.form.get('notes')
        
        try:
            # Save the edited version
            cursor.execute("""
                INSERT INTO thesis_versions
                (thesis_id, edited_title, edited_authors, edited_school, edited_year_made, edited_keywords, notes, edited_by)
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
            
            # Update submission status
            new_status = 'approved' if action == 'approve' else 'rejected'
            cursor.execute("""
                UPDATE thesis_submissions
                SET title = %s, authors = %s, school = %s, year_made = %s, keywords = %s, status = %s
                WHERE id = %s
            """, (
                edited_title,
                edited_authors,
                edited_school,
                edited_year,
                edited_keywords,
                new_status,
                submission_id
            ))
            
            mysql.connection.commit()
            flash('Submission updated successfully', 'success')
            
            if action == 'approve':
                return redirect(url_for('publish_thesis', submission_id=submission_id))
            return redirect(url_for('admin_submissions'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating submission: {str(e)}', 'danger')
    
    # Get submission details
    cursor.execute("""
        SELECT ts.*, u.username as admin_username 
        FROM thesis_submissions ts
        JOIN users u ON ts.admin_id = u.id
        WHERE ts.id = %s
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission:
        abort(404)
    
    return render_template('review_submission.html', submission=submission)

@app.route('/admin/publish/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def publish_thesis(submission_id):
    if not current_user.is_admin():
        abort(403)
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
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
            
            # Move file to published directory
            original_path = submission['file_path']
            filename = os.path.basename(original_path)
            publish_path = os.path.join(app.config['UPLOAD_FOLDER'], 'published', filename)
            os.makedirs(os.path.dirname(publish_path), exist_ok=True)
            
            if os.path.exists(original_path):
                os.rename(original_path, publish_path)
            
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
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error publishing thesis: {str(e)}', 'danger')
    
    # GET request - show confirmation page
    cursor.execute("""
        SELECT ts.* FROM thesis_submissions ts
        WHERE ts.id = %s AND ts.status = 'approved'
    """, (submission_id,))
    submission = cursor.fetchone()
    
    if not submission:
        abort(404)
    
    return render_template('publish_confirmation.html', submission=submission)
@app.route('/logout')
@login_required
def logout():
    username = current_user.username  # Get username before logout
    logout_user()
    flash(f'{username} has been successfully logged out', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)