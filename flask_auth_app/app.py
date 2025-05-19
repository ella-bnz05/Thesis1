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
from nltk.stem import PorterStemmer
import re
import threading
from difflib import SequenceMatcher
from collections import defaultdict

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
app.config['MYSQL_DB'] = 'flask_auth (3)'

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

def compute_similarity(a, b):
    """Compute similarity ratio as percentage."""
    return round(SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100, 2)
@app.route('/search')
@login_required
def search():
    from difflib import SequenceMatcher

    query = request.args.get('q', '') or session.get('search_query', '')
    if not query:
        return redirect(url_for('browse_theses'))

    session['search_query'] = query
    expanded_query = expand_search_terms(query)

    # Clean the query for BOOLEAN MODE search
    clean_query = query.strip()
    clean_query_formatted = f'+{clean_query}' if len(clean_query.split()) == 1 else f'"{clean_query}"'

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Search metadata
    cursor.execute("""
        SELECT pt.*,
               CASE 
                   WHEN MATCH(pt.keywords) AGAINST(%s IN BOOLEAN MODE) THEN 3
                   WHEN MATCH(pt.title) AGAINST(%s IN BOOLEAN MODE) THEN 2
                   WHEN MATCH(pt.authors) AGAINST(%s IN BOOLEAN MODE) THEN 1
                   WHEN pt.year_made = %s THEN 1
                   ELSE 0
               END as relevance_boost
        FROM published_theses pt
        WHERE MATCH(pt.title, pt.authors, pt.keywords) AGAINST(%s IN BOOLEAN MODE)
           OR pt.year_made = %s
        ORDER BY relevance_boost DESC, pt.published_at DESC
    """, (
        clean_query_formatted,
        clean_query_formatted,
        clean_query_formatted,
        query,
        clean_query_formatted,
        query
    ))
    metadata_results = cursor.fetchall()

    # Full-text content search (only intro/abstract pages prioritized)
    cursor.execute("""
        SELECT 
            pt.id as thesis_id,
            pt.title as thesis_title,
            pt.authors,
            pt.year_made,
            tp.page_number,
            tp.page_text,
            SUBSTRING_INDEX(
                SUBSTRING_INDEX(
                    SUBSTRING(tp.page_text, 
                        GREATEST(1, LOCATE(%s, LOWER(tp.page_text)) - 100), 
                        300
                    ), 
                ' ', -10), 
            ' ', 10) as text_snippet,
            (LENGTH(tp.page_text) - LENGTH(REPLACE(LOWER(tp.page_text), LOWER(%s), ''))) / LENGTH(%s) as term_frequency,
            MATCH(tp.page_text) AGAINST(%s IN BOOLEAN MODE) as relevance_score
        FROM thesis_pages tp
        JOIN published_theses pt ON tp.thesis_id = pt.id
        WHERE tp.page_number BETWEEN 1 AND 5
        AND MATCH(tp.page_text) AGAINST(%s IN BOOLEAN MODE)
        ORDER BY (relevance_score * term_frequency * 1.5) DESC
        LIMIT 50
    """, (
        query.lower(), 
        query.lower(), 
        query.lower(),
        clean_query_formatted,
        clean_query_formatted
    ))

    full_text_results = cursor.fetchall()

    # Function to calculate match %
    def calculate_match_percentage(query, text):
        doc1 = nlp(query.lower())
        doc2 = nlp(text.lower())

        # Jaccard similarity
        query_terms = set(token.text for token in doc1 if not token.is_stop and token.is_alpha)
        text_terms = set(token.text for token in doc2 if not token.is_stop and token.is_alpha)
        jaccard = len(query_terms & text_terms) / len(query_terms | text_terms) if (query_terms | text_terms) else 0

        # Token similarity (cosine-like, uses spaCy vectors)
        vector_similarity = doc1.similarity(doc2) if doc1.vector_norm and doc2.vector_norm else 0

        # Sequence match (character-level)
        from difflib import SequenceMatcher
        sequence = SequenceMatcher(None, query.lower(), text.lower()).ratio()

        # Combine all three with weights
        return round((jaccard * 0.3 + vector_similarity * 0.4 + sequence * 0.3) * 100, 2)


    # Group full text results by thesis
    grouped_results = {}
    for result in full_text_results:
        thesis_id = result['thesis_id']
        if thesis_id not in grouped_results:
            grouped_results[thesis_id] = {
                'thesis_title': result['thesis_title'],
                'authors': result['authors'],
                'year_made': result['year_made'],
                'matches': [],
                'match_scores': []
            }

        match_score = calculate_match_percentage(query, result['page_text'])
        grouped_results[thesis_id]['matches'].append({
            'page_number': result['page_number'],
            'text_snippet': result['text_snippet'],
            'relevance_score': result['relevance_score'],
            'match_percentage': match_score
        })
        grouped_results[thesis_id]['match_scores'].append(match_score)

    # Average match score per thesis
    for thesis in grouped_results.values():
        scores = thesis['match_scores']
        weighted_sum = sum(
            score * 1.5 if match['page_number'] <= 5 else score
            for score, match in zip(scores, thesis['matches'])
        )
        weight_count = sum(1.5 if match['page_number'] <= 5 else 1 for match in thesis['matches'])
        thesis['average_match'] = round(weighted_sum / weight_count, 2) if weight_count else 0
        del thesis['match_scores']

    # Match percentage for metadata
    for result in metadata_results:
        combined_text = ' '.join([
            result.get('title', ''),
            result.get('authors', ''),
            result.get('keywords', ''),
            result.get('school', '')
        ])
        result['match_percentage'] = calculate_match_percentage(query, combined_text)

    return render_template('search_results.html',
                           query=query,
                           metadata_results=metadata_results,
                           grouped_results=grouped_results)

# if want to add more cs abbreviated term add here.
def expand_search_terms(query):
    """Expand common abbreviations to their full forms for better search results."""
    term_mapping = {
        'ai': 'artificial intelligence',
        'iot': 'internet of things',
        'ml': 'machine learning',
        'nlp': 'natural language processing',
        'cv': 'computer vision',
        'vr': 'virtual reality',
        'ar': 'augmented reality',
        'db': 'database',
        'os': 'operating system'
    }
    
    # Split query into terms
    terms = query.lower().split()
    expanded_terms = []
    
    for term in terms:
        if term in term_mapping:
            # Only add the expanded version if the original term is an abbreviation
            # and the expanded version isn't already in the query
            expanded = term_mapping[term]
            if expanded not in query.lower():
                expanded_terms.append(expanded)
            else:
                # If the full term is already in query, just keep it
                expanded_terms.append(term)
        else:
            expanded_terms.append(term)
    
    return ' '.join(expanded_terms)

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
    
    # Get total published theses
    cursor.execute("SELECT COUNT(*) as total_published FROM published_theses")
    stats = cursor.fetchone()
    
    # Get user's recent views count
    cursor.execute("""
        SELECT COUNT(DISTINCT thesis_id) as recent_views 
        FROM user_view_history 
        WHERE user_id = %s
    """, (current_user.id,))
    views_stats = cursor.fetchone()
    
    # Get user's saved theses count
    cursor.execute("""
        SELECT COUNT(*) as saved_theses 
        FROM user_bookmarks 
        WHERE user_id = %s
    """, (current_user.id,))
    bookmarks_stats = cursor.fetchone()
    
    # Get recent theses
    cursor.execute("""
        SELECT * FROM published_theses
        ORDER BY published_at DESC
        LIMIT 3
    """)
    recent_theses = cursor.fetchall()
    
    return render_template('user_dashboard.html', 
                         stats={
                             'total_published': stats['total_published'],
                             'recent_views': views_stats['recent_views'],
                             'saved_theses': bookmarks_stats['saved_theses']
                         },
                         recent_theses=recent_theses)
from difflib import SequenceMatcher

@app.route('/browse-theses')
@login_required
def browse_theses():
    if current_user.is_admin():
        return redirect(url_for('admin_browse_theses'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    search_query = request.args.get('q', '')
    year_filter = request.args.get('year', '')
    keyword_filter = request.args.get('keyword', '')
    sort_by = request.args.get('sort', 'recent')  # recent, oldest, title
    page = request.args.get('page', 1, type=int)
    per_page = 10

    original_query = search_query  # Preserve original for display
    
    # Expand search terms if needed
    if search_query:
        search_query = expand_search_terms(search_query)
    
    # Common CS keywords for filter (now includes abbreviations)
    common_cs_keywords = [
        'artificial intelligence', 'ai', 'machine learning', 'ml', 'data science',
        'cybersecurity', 'networking', 'database', 'db', 'algorithm',
        'software engineering', 'web development', 'mobile development',
        'cloud computing', 'blockchain', 'iot', 'internet of things', 
        'computer vision', 'cv', 'natural language processing', 'nlp',
        'big data', 'data mining', 'virtual reality', 'vr', 
        'augmented reality', 'ar', 'operating system', 'os'
    ]

    query = """
        SELECT pt.* 
        FROM published_theses pt
        WHERE 1=1
    """
    params = []

    if search_query:
        query += """
            AND (LOWER(pt.title) LIKE %s OR LOWER(pt.authors) LIKE %s 
                 OR LOWER(pt.keywords) LIKE %s OR pt.year_made = %s)
        """
        like_pattern = f"%{search_query.lower()}%"
        params.extend([like_pattern, like_pattern, like_pattern, search_query])

    if year_filter:
        query += " AND pt.year_made = %s"
        params.append(year_filter)

    if keyword_filter:
        expanded_keyword = expand_search_terms(keyword_filter).split()[-1]
        query += " AND LOWER(pt.keywords) LIKE %s"
        params.append(f'%{expanded_keyword.lower()}%')

    # Sorting
    if sort_by == 'recent':
        query += " ORDER BY pt.published_at DESC"
    elif sort_by == 'oldest':
        query += " ORDER BY pt.published_at ASC"
    elif sort_by == 'title':
        query += " ORDER BY pt.title ASC"

    # Add pagination
    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])

    cursor.execute(query, params)
    theses = cursor.fetchall()

    # 🔍 Add match percentage
    def get_similarity(a, b):
        return round(SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100, 2)

    if original_query:
        for thesis in theses:
            combined_text = ' '.join([
                thesis.get('title', ''),
                thesis.get('authors', ''),
                thesis.get('keywords', ''),
                thesis.get('school', '')
            ])
            thesis['match_percentage'] = get_similarity(original_query, combined_text)

    # 📊 Get total count
    count_query = "SELECT COUNT(*) as total FROM published_theses WHERE 1=1"
    count_params = []

    if search_query:
        count_query += " AND (LOWER(title) LIKE %s OR LOWER(authors) LIKE %s OR LOWER(keywords) LIKE %s OR year_made = %s)"
        like_pattern = f"%{search_query.lower()}%"
        count_params.extend([like_pattern, like_pattern, like_pattern, search_query])

    if year_filter:
        count_query += " AND year_made = %s"
        count_params.append(year_filter)

    if keyword_filter:
        expanded_keyword = expand_search_terms(keyword_filter).split()[-1]
        count_query += " AND LOWER(keywords) LIKE %s"
        count_params.append(f'%{expanded_keyword.lower()}%')

    cursor.execute(count_query, count_params)
    total = cursor.fetchone()['total']

    # 📅 Get available years
    cursor.execute("SELECT DISTINCT year_made FROM published_theses ORDER BY year_made DESC")
    available_years = [str(row['year_made']) for row in cursor.fetchall()]

    return render_template('user_browse_theses.html',
                           theses=theses,
                           search_query=original_query,
                           year_filter=year_filter,
                           keyword_filter=keyword_filter,
                           sort_by=sort_by,
                           common_cs_keywords=common_cs_keywords,
                           available_years=available_years,
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
            # Ensure temp directory exists
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_search')
            os.makedirs(temp_dir, exist_ok=True)
            
            # Save temporary image with a unique filename
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"search_{current_user.id}_{timestamp}.jpg"
            filepath = os.path.join(temp_dir, filename)
            file.save(filepath)
            
            # Verify the image was saved
            if not os.path.exists(filepath):
                return jsonify({'success': False, 'error': 'Failed to save image'})
            
            # Extract text using OCR
            text = extract_text_from_image(filepath)
            
            if not text or len(text.strip()) == 0:
                return jsonify({'success': False, 'error': 'No text found in image'})
            
            # Improved title extraction focusing on academic titles
            def extract_thesis_title(text):
                # Comprehensive list of CS terms to prioritize
                cs_keywords = [
                    'artificial intelligence', 'machine learning', 'deep learning', 'neural network',
                    'computer vision', 'natural language processing', 'data mining', 'big data',
                    'cybersecurity', 'network security', 'encryption', 'blockchain',
                    'cloud computing', 'distributed systems', 'parallel computing',
                    'software engineering', 'agile development', 'devops',
                    'database', 'sql', 'nosql', 'data warehouse',
                    'algorithm', 'data structure', 'computational complexity',
                    'internet of things', 'iot', 'embedded systems',
                    'computer graphics', 'virtual reality', 'augmented reality',
                    'human computer interaction', 'hci', 'user interface',
                    'operating system', 'compiler', 'computer architecture'
                ]
                
                # Common academic phrases to ignore
                ignore_phrases = [
                    'thesis', 'dissertation', 'research', 'study', 'paper', 'project',
                    'submitted', 'university', 'college', 'department', 'faculty', 'school',
                    'bachelor', 'master', 'phd', 'doctorate', 'towards', 'analysis',
                    'of', 'in', 'and', 'the', 'a', 'an', 'for', 'on', 'about', 'using',
                    'with', 'cavite state university', 'city', 'city of imus cavite'
                ]
                
                # Split into lines and find the most likely title line
                lines = [line.strip() for line in text.split('\n') if line.strip()]
                
                # Score each line based on likelihood of being a title
                scored_lines = []
                for line in lines:
                    # Skip lines that are too short or too long
                    if len(line) < 10 or len(line) > 120:
                        continue
                        
                    # Initialize scores
                    position_score = 1.0 / (lines.index(line) + 1)  # Earlier lines score higher
                    length_score = min(1.0, 1.0 - abs(0.5 - (len(line)/100)))  # Medium length preferred
                    
                    # Count title-case words
                    words = line.split()
                    title_case_words = sum(1 for word in words if word.istitle())
                    case_score = title_case_words / len(words) if words else 0
                    
                    # Penalize ignored phrases
                    lower_line = line.lower()
                    ignore_score = sum(-0.5 for phrase in ignore_phrases if phrase in lower_line)
                    
                    # Bonus for CS keywords
                    cs_score = sum(2.0 for term in cs_keywords if term in lower_line)
                    
                    total_score = position_score + length_score + case_score + ignore_score + cs_score
                    scored_lines.append((total_score, line))
                
                if not scored_lines:
                    return None
                
                # Get the highest scoring line
                scored_lines.sort(reverse=True, key=lambda x: x[0])
                best_line = scored_lines[0][1]
                
                # Now extract the most important CS terms from the best line
                doc = nlp(best_line)
                
                # Look for noun phrases that contain CS terms
                topics = []
                for chunk in doc.noun_chunks:
                    chunk_text = chunk.text.lower()
                    
                    # Skip short phrases and those with ignored words
                    if (len(chunk.text.split()) <= 3 or
                        any(t in chunk_text for t in ignore_phrases)):
                        continue
                    
                    # Score based on:
                    # 1. Length (longer is better)
                    # 2. Position in title (earlier is better)
                    # 3. Contains CS terms (higher score)
                    # 4. Contains proper nouns (higher score)
                    score = len(chunk.text.split())  # word count
                    score += (len(best_line) - best_line.find(chunk.text)) / len(best_line)  # position
                    
                    # Bonus for CS terms
                    if any(term in chunk_text for term in cs_keywords):
                        score += 3
                        
                    # Bonus for proper nouns
                    if any(t.pos_ == 'PROPN' for t in chunk):
                        score += 2
                        
                    topics.append((score, chunk.text))
                
                if not topics:
                    return best_line  # fallback to entire line
                
                # Get the highest scoring topic
                topics.sort(reverse=True, key=lambda x: x[0])
                return topics[0][1]

            
            # Extract the main topic
            main_topic = extract_thesis_title(text)
            
            # Clean up
            try:
                os.remove(filepath)
            except:
                pass
            
            if not main_topic or len(main_topic.strip()) == 0:
                return jsonify({
                    'success': False,
                    'error': 'No relevant topic found in extracted text'
                })
            
            return jsonify({
                'success': True,
                'topic': main_topic.strip()
            })
            
        except Exception as e:
            if 'filepath' in locals() and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass
            return jsonify({
                'success': False,
                'error': f'Error processing image: {str(e)}'
            })
    
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/thesis/<int:thesis_id>')
@login_required
def view_thesis(thesis_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Record view history (existing code remains the same)
    today = datetime.now().date()
    cursor.execute("""
        SELECT id FROM user_view_history 
        WHERE user_id = %s AND thesis_id = %s AND DATE(viewed_at) = %s
    """, (current_user.id, thesis_id, today))
    
    if cursor.fetchone():
        cursor.execute("""
            UPDATE user_view_history 
            SET viewed_at = CURRENT_TIMESTAMP
            WHERE user_id = %s AND thesis_id = %s AND DATE(viewed_at) = %s
        """, (current_user.id, thesis_id, today))
    else:
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

    # Get title page (first page only)
    cursor.execute("""
        SELECT page_text FROM thesis_pages
        WHERE thesis_id = %s AND page_number = 1
    """, (thesis_id,))
    title_page = cursor.fetchone()
    
    # Get introduction pages only (pages 2-5)
    cursor.execute("""
        SELECT page_text FROM thesis_pages
        WHERE thesis_id = %s AND page_number BETWEEN 2 AND 5
        ORDER BY page_number
    """, (thesis_id,))
    intro_pages = [page['page_text'] for page in cursor.fetchall()]

    # Search functionality
    search_query = request.args.get('q', '')
    matching_snippets = []
    
    if search_query:
        cursor.execute("""
            SELECT 
                page_number,
                SUBSTRING_INDEX(
                    SUBSTRING_INDEX(
                        SUBSTRING(page_text, 
                            GREATEST(1, LOCATE(%s, page_text) - 100), 
                            300
                        ), 
                        ' ', 
                        -10
                    ),
                    ' ', 
                    10
                ) as text_snippet
            FROM thesis_pages
            WHERE thesis_id = %s 
            AND MATCH(page_text) AGAINST(%s IN BOOLEAN MODE)
            AND page_number > 5  -- Skip introduction pages
            ORDER BY page_number
            LIMIT 10
        """, (search_query, thesis_id, f'+{search_query}*'))
        matching_snippets = cursor.fetchall()

    # Choose template based on user role
    if current_user.is_admin():
        return render_template('thesis_detail.html', 
                               thesis=thesis,
                               title_page=title_page['page_text'] if title_page else None,
                               intro_pages=intro_pages,
                               matching_pages=matching_snippets,
                               search_query=search_query,
                               is_bookmarked=is_bookmarked)
    else:
        return render_template('user_thesis_detail.html', 
                               thesis=thesis,
                               title_page=title_page['page_text'] if title_page else None,
                               intro_pages=intro_pages,
                               matching_snippets=matching_snippets,
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

    camera_file = request.files.get('camera_file')
    upload_file = request.files.get('upload_file')
    file = camera_file or upload_file

    if not file or file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not allowed_file(file.filename):
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

    preview_url = None
    if file_exists:
        # Create a route to serve the submission file
        preview_url = url_for('serve_submission_file', submission_id=submission_id)

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

@app.route('/submission-file/<int:submission_id>')
@login_required
def serve_submission_file(submission_id):
    if not current_user.is_admin():
        abort(403)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT file_path FROM thesis_submissions WHERE id = %s", (submission_id,))
    result = cursor.fetchone()
    cursor.close()

    if not result or not result['file_path'] or not os.path.exists(result['file_path']):
        abort(404)

    # Determine if it's an image or PDF
    if result['file_path'].lower().endswith(('.png', '.jpg', '.jpeg')):
        return send_file(result['file_path'], mimetype='image/jpeg')
    elif result['file_path'].lower().endswith('.pdf'):
        response = make_response(send_file(result['file_path']))
        response.headers["Content-Disposition"] = "inline; filename=view.pdf"
        return response
    else:
        abort(404)
        
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

@app.route('/bookmark/<int:thesis_id>', methods=['DELETE'])
@login_required
def delete_bookmark(thesis_id):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            DELETE FROM user_bookmarks 
            WHERE user_id = %s AND thesis_id = %s
        """, (current_user.id, thesis_id))
        mysql.connection.commit()
        return jsonify({'success': True})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()

# Viewing history routes
@app.route('/history')
@login_required
def view_history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Get unique view history with the most recent view for each thesis
    cursor.execute("""
        SELECT pt.*, MAX(uv.viewed_at) as viewed_at, 
               COUNT(uv.id) as view_count,
               MIN(uv.id) as history_id
        FROM published_theses pt
        JOIN user_view_history uv ON pt.id = uv.thesis_id
        WHERE uv.user_id = %s
        GROUP BY pt.id
        ORDER BY MAX(uv.viewed_at) DESC
        LIMIT %s OFFSET %s
    """, (current_user.id, per_page, (page-1)*per_page))
    history = cursor.fetchall()
    
    # Get total count of unique viewed theses
    cursor.execute("""
        SELECT COUNT(DISTINCT thesis_id) as total 
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
        # First get the thesis_id from the history item
        cursor.execute("""
            SELECT thesis_id FROM user_view_history 
            WHERE id = %s AND user_id = %s
        """, (item_id, current_user.id))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'error': 'Item not found or not authorized'})
            
        thesis_id = result[0]
        
        # Delete all history entries for this thesis
        cursor.execute("""
            DELETE FROM user_view_history 
            WHERE user_id = %s AND thesis_id = %s
        """, (current_user.id, thesis_id))
        
        mysql.connection.commit()
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

@app.route('/limited-thesis/<int:thesis_id>')
@login_required
def serve_limited_thesis(thesis_id):
    """Serve only pages 1-2 of the thesis PDF with scrolling enabled"""
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT file_path FROM published_theses WHERE id = %s", (thesis_id,))
    result = cursor.fetchone()
    cursor.close()

    if not result:
        abort(404)

    file_path = result['file_path']
    
    # Create a temporary directory if it doesn't exist
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_limited')
    os.makedirs(temp_dir, exist_ok=True)
    
    # Generate unique filename
    temp_path = os.path.join(temp_dir, f"limited_{thesis_id}.pdf")
    
    try:
        # Extract only first 2 pages
        with open(file_path, 'rb') as infile:
            reader = PyPDF2.PdfReader(infile)
            writer = PyPDF2.PdfWriter()
            
            # Add only pages 1 and 2 (index 0 and 1)
            for i in range(min(2, len(reader.pages))):
                writer.add_page(reader.pages[i])
            
            with open(temp_path, 'wb') as outfile:
                writer.write(outfile)
        
        # Create response with headers that allow scrolling
        response = make_response(send_file(temp_path))
        response.headers["Content-Disposition"] = "inline; filename=preview.pdf"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
        
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        abort(500, description="Error generating limited preview")

@app.route('/logout')
@login_required
def logout():
    username = current_user.username  # Get username before logout
    logout_user()
    flash(f'{username} has been successfully logged out', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)