from flask import Flask, render_template, request, redirect, url_for, flash, abort, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
from functools import wraps

# Authentication
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import session
import os
import secrets


# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'campuscare-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024   # 5 MB (optional)

# Initialize database
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# ========== DATABASE MODELS ==========
class User(db.Model, UserMixin):
    """User model (for future authentication)"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')  # student, admin, staff, maintenance
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    reported_issues = db.relationship('Issue',
                                      foreign_keys='Issue.reported_by',
                                      backref='reporter',
                                      lazy=True)

    assigned_issues = db.relationship('Issue',
                                      foreign_keys='Issue.assigned_to',
                                      backref='assignee',
                                      lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)

    def is_admin(self):
        return self.role == 'admin'
    
class IssueStatusHistory(db.Model):
    """Model for tracking issue status changes"""
    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)
    old_status = db.Column(db.String(20))
    new_status = db.Column(db.String(20), nullable=False)
    changed_by = db.Column(db.String(100))  # Could be user_id or session token
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f'<StatusChange {self.old_status}->{self.new_status} for Issue {self.issue_id}>'

class Issue(db.Model):
    """Model for storing campus issues"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100))
    media_url = db.Column(db.String(200))  # For uploaded images/videos
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    image_filename = db.Column(db.String(255), nullable=True)

    status_history = db.relationship('IssueStatusHistory', 
                                     backref='issue', 
                                     lazy=True,
                                     order_by='IssueStatusHistory.changed_at.desc()')

    # Foreign keys
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(50))  # Assigned department

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    comments = db.relationship('Comment', backref='issue', lazy=True)
    ratings = db.relationship('Rating', backref='issue', lazy=True)
    
    def __repr__(self):
        return f'<Issue {self.title}>'

#database for comment
class Comment(db.Model):
    """Model for issue comments (shared platform discussion)"""
    id = db.Column(db.Integer, primary_key=True)
    
    issue_id = db.Column(
        db.Integer,
        db.ForeignKey('issue.id'),
        nullable=False
    )
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')

    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edit_token = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return f'<Comment {self.id} on Issue {self.issue_id}>'
    
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)

    score = db.Column(db.Integer, nullable=False)  # 1..5
    feedback = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # NEW
    
    __table_args__ = (
        db.UniqueConstraint('issue_id', 'user_id', name='unique_user_issue_rating'),
    )

# ========== HELPER FUNCTIONS ==========
def get_category_stats():
    """Get statistics for issues by category"""
    return db.session.query(
        Issue.category,
        func.count(Issue.id).label('count')
    ).group_by(Issue.category).order_by(func.count(Issue.id).desc()).all()

def get_status_stats():
    """Get statistics for issues by status"""
    return db.session.query(
        Issue.status,
        func.count(Issue.id).label('count')
    ).group_by(Issue.status).all()

def get_recent_issues(limit=5):
    """Get recent issues"""
    return Issue.query.order_by(Issue.created_at.desc()).limit(limit).all()

def add_sample_data():
    """Add sample data for testing (5 issues only)"""
    sample_issues = [
        Issue(
            title="Broken Chair in Lecture Hall",
            description="Multiple chairs broken in Lecture Hall A, need immediate repair",
            category="Furniture",
            location="Lecture Hall A",
            status="Open",
            priority="High"
        ),
        Issue(
            title="Leaky Faucet in Science Lab",
            description="Faucet in Chemistry Lab 3 leaking continuously, causing water wastage",
            category="Plumbing",
            location="Chemistry Lab 3",
            status="In Progress",
            priority="High"
        ),
        Issue(
            title="WiFi Connectivity Issues",
            description="No WiFi connectivity in Library 2nd floor, affecting student research",
            category="Network",
            location="Library",
            status="Open",
            priority="Medium"
        ),
        Issue(
            title="AC Not Working",
            description="Air conditioner not cooling in Computer Lab 2",
            category="HVAC",
            location="Computer Lab 2",
            status="Resolved",
            priority="Medium"
        ),
        Issue(
            title="Projector Malfunction",
            description="Projector not displaying properly in Room 301",
            category="Equipment",
            location="Room 301",
            status="In Progress",
            priority="Medium"
        )
    ]

    db.session.add_all(sample_issues)
    db.session.commit()
    print(f"✅ Added {len(sample_issues)} sample issues")

# ========== AUTH HELPERS ==========
def role_required(role):
    """Decorator to require a specific role for a route"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ========== ROUTES ==========
@app.route('/')
def home():
    """Home page showcasing all features"""
    # Get basic stats
    total_issues = Issue.query.count()
    open_issues = Issue.query.filter_by(status='Open').count()
    recent_issues = get_recent_issues(5)

    # Get category stats for top categories
    category_stats = get_category_stats()[:3]  # Top 3 categories

    return render_template('home.html',
                         total_issues=total_issues,
                         open_issues=open_issues,
                         recent_issues=recent_issues,
                         category_stats=category_stats)

@app.route('/dashboard')
def dashboard():
    """Analytics dashboard with admin features"""
    total_issues = Issue.query.count()
    open_issues = Issue.query.filter_by(status='Open').count()
    in_progress_issues = Issue.query.filter_by(status='In Progress').count()
    resolved_issues = Issue.query.filter_by(status='Resolved').count()

    category_stats = get_category_stats()
    status_stats = get_status_stats()
    recent_issues = Issue.query.order_by(Issue.created_at.desc()).limit(10).all()

    # Calculate percentages
    open_percentage = round((open_issues / total_issues * 100), 1) if total_issues > 0 else 0
    resolved_percentage = round((resolved_issues / total_issues * 100), 1) if total_issues > 0 else 0

    # Check if user is admin
    """is_admin = current_user.is_admin()"""

    return render_template('dashboard.html',
                         total_issues=total_issues,
                         open_issues=open_issues,
                         in_progress_issues=in_progress_issues,
                         resolved_issues=resolved_issues,
                         open_percentage=open_percentage,
                         resolved_percentage=resolved_percentage,
                         category_stats=category_stats,
                         status_stats=status_stats,
                         recent_issues=recent_issues)

@app.route('/issues')
def issues_list():
    """List all issues with filters"""
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    status = request.args.get('status', '')

    query = Issue.query

    if search:
        query = query.filter(
            (Issue.title.ilike(f'%{search}%')) |
            (Issue.description.ilike(f'%{search}%'))
        )

    if category:
        query = query.filter(Issue.category == category)

    if status:
        query = query.filter(Issue.status == status)

    issues = query.order_by(Issue.created_at.desc()).all()

    categories = db.session.query(Issue.category).distinct().all()
    categories = [c[0] for c in categories]

    statuses = db.session.query(Issue.status).distinct().all()
    statuses = [s[0] for s in statuses]

    return render_template('issue.html',
                         issues=issues,
                         categories=categories,
                         statuses=statuses,
                         search=search,
                         category_filter=category,
                         status_filter=status)

@app.route('/issue/new', methods=['GET', 'POST'])
@login_required
def new_issue():
    """Report new issue (with media upload placeholder)"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        location = request.form.get('location')
        priority = request.form.get('priority')

        if not all([title, description, category, location]):
            flash('Please fill all required fields', 'error')
            return redirect(url_for('new_issue'))

        
        # uploaded image
        image_file = request.files.get('image')
        image_filename = None

        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(save_path)
            image_filename = filename
        
        issue = Issue(
            title=title,
            description=description,
            category=category,
            location=location,
            priority=priority,
            status='Open',
            image_filename=image_filename
        )
        

        db.session.add(issue)
        db.session.commit()

        flash('Issue reported successfully! Our team will review it shortly.', 'success')
        return redirect(url_for('home'))

    categories = ['Furniture', 'Plumbing', 'Electrical', 'Network', 'HVAC',
                  'Equipment', 'Infrastructure', 'Security', 'Cleaning', 'Other']
    priorities = ['Low', 'Medium', 'High', 'Critical']

    return render_template('new_issue.html',
                         categories=categories,
                         priorities=priorities)

@app.route('/issue/<int:issue_id>', methods=['GET', 'POST'])
def view_issue(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    # --- Handle comment post ---
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Please log in to comment.', 'error')
            return redirect(url_for('login'))

        comment_text = request.form.get('comment', '').strip()
        if not comment_text:
            flash('Comment cannot be empty.', 'error')
            return redirect(url_for('view_issue', issue_id=issue.id))

        token = secrets.token_hex(16)

        new_comment = Comment(
            issue_id=issue.id,
            user_id=current_user.id,
            content=comment_text,
            edit_token=token
        )

        db.session.add(new_comment)
        db.session.commit()

        my_tokens = session.get('my_comment_tokens', [])
        my_tokens.append(token)
        session['my_comment_tokens'] = my_tokens

        flash('Comment posted.', 'success')
        return redirect(url_for('view_issue', issue_id=issue.id))

    # --- Rating summary (GET render) ---
    avg_rating = None
    rating_count = 0

    if (issue.status or "").strip().lower() == "resolved":
         avg = db.session.query(func.avg(Rating.score)).filter(Rating.issue_id == issue.id).scalar()
         avg_rating = round(float(avg), 1) if avg else None
         rating_count = Rating.query.filter_by(issue_id=issue.id).count()

    has_rated = False
    if current_user.is_authenticated:
        has_rated = Rating.query.filter_by(issue_id=issue.id, user_id=current_user.id).first() is not None
        
    print("VIEW ISSUE status:", issue.status)
    print("VIEW ISSUE rating count:",
      Rating.query.filter_by(issue_id=issue.id).count())

    ratings = Rating.query.filter_by(issue_id=issue.id).order_by(Rating.created_at.desc()).all()

    return render_template(
        'view_issue.html',
        issue=issue,
        avg_rating=avg_rating,
        rating_count=rating_count,
        has_rated=has_rated,
        ratings=ratings
    )

# ========== ADMIN ROUTES ==========
@app.route('/admin/issues')
@login_required
@role_required('admin')
def admin_issues():
    """Admin: list and filter issues"""
    status = request.args.get('status', '')
    department = request.args.get('department', '')

    query = Issue.query
    if status:
        query = query.filter(Issue.status == status)
    if department:
        query = query.filter(Issue.department == department)

    issues = query.order_by(Issue.created_at.desc()).all()
    staff_users = User.query.filter(User.role.in_(['staff', 'maintenance', 'admin'])).all()

    departments = ['Maintenance', 'Electrical', 'Plumbing', 'Network', 'HVAC', 'Cleaning', 'Security', 'Other']

    return render_template('admin_issues.html', issues=issues, staff_users=staff_users, departments=departments, status_filter=status, department_filter=department)

@app.route('/admin/issue/<int:issue_id>')
@login_required
@role_required('admin')
def admin_view_issue(issue_id):
    """Admin: view an issue and assignment form"""
    issue = Issue.query.get_or_404(issue_id)
    staff_users = User.query.filter(User.role.in_(['staff', 'maintenance', 'admin'])).all()
    departments = ['Maintenance', 'Electrical', 'Plumbing', 'Network', 'HVAC', 'Cleaning', 'Security', 'Other']
    return render_template('admin_view_issue.html', issue=issue, staff_users=staff_users, departments=departments)

@app.route('/admin/issue/<int:issue_id>/assign', methods=['POST'])
@login_required
@role_required('admin')
def admin_assign_issue(issue_id):
    """Admin: assign issue to a user/department and update status/priority"""
    issue = Issue.query.get_or_404(issue_id)
    assigned_to = request.form.get('assigned_to')  # user id or ''
    department = request.form.get('department')
    status = request.form.get('status')
    priority = request.form.get('priority')

    if assigned_to:
        try:
            user = User.query.get(int(assigned_to))
            if user:
                issue.assigned_to = user.id
        except Exception:
            pass
    else:
        issue.assigned_to = None

    if department is not None:
        issue.department = department or None

    if status:
        issue.status = status

    if priority:
        issue.priority = priority

    db.session.commit()
    flash('Issue updated and assignment saved', 'success')
    return redirect(url_for('admin_view_issue', issue_id=issue.id))

# ========== SIMPLE LOGIN (minimal template rendered inline) ==========
LOGIN_PAGE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CampusCare - Login</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    <style>
      .login-card{max-width:420px;margin:6rem auto;padding:2rem;background:#fff;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,.08)}
      .form-input{width:100%;padding:.75rem;border:1px solid #ddd;border-radius:6px;margin-bottom:1rem}
      .btn-primary{background:#4CAF50;color:#fff;padding:.6rem 1.2rem;border-radius:6px;border:none;cursor:pointer}
    </style>
  </head>
  <body>
    <div class="login-card">
      <h2>CampusCare — Login</h2>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="POST" action="{{ url_for('login') }}">
        <label>Username or email</label>
        <input class="form-input" type="text" name="username" required>
        <label>Password</label>
        <input class="form-input" type="password" name="password" required>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn-primary" type="submit">Login</button>
          <a href="{{ url_for('home') }}" class="btn btn-secondary" style="padding:.6rem 1rem;border-radius:6px;text-decoration:none">Cancel</a>
        </div>
      </form>
    </div>
  </body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Simple login page (minimal)"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = None
        if username and '@' in username:
            user = User.query.filter_by(email=username).first()
        else:
            user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
            return render_template_string(LOGIN_PAGE)
    return render_template_string(LOGIN_PAGE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for('home'))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    my_tokens = session.get('my_comment_tokens', [])
    if comment.edit_token not in my_tokens:
        flash("You can only delete your own comment.", "error")
        return redirect(url_for('view_issue', issue_id=comment.issue_id))

    db.session.delete(comment)
    db.session.commit()
    flash("Comment deleted.", "success")
    return redirect(url_for('view_issue', issue_id=comment.issue_id))

@app.route('/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    my_tokens = session.get('my_comment_tokens', [])
    if comment.edit_token not in my_tokens:
        flash("You can only edit your own comment.", "error")
        return redirect(url_for('view_issue', issue_id=comment.issue_id))

    if request.method == 'POST':
        new_text = request.form.get('content', '').strip()
        if not new_text:
            flash("Comment cannot be empty.", "error")
            return redirect(url_for('edit_comment', comment_id=comment.id))

        comment.content = new_text
        comment.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Comment updated.", "success")
        return redirect(url_for('view_issue', issue_id=comment.issue_id))

    return render_template('edit_comment.html', comment=comment)


@app.route('/issue/<int:issue_id>/rate', methods=['POST'])
@login_required
def rate_issue(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    if (issue.status or "").strip().lower() != "resolved":
        flash("You can only rate after the issue is resolved.", "error")
        return redirect(url_for("view_issue", issue_id=issue.id))

    rating_raw = request.form.get("rating")
    feedback = request.form.get("feedback", "").strip()

    try:
        score = int(rating_raw)
    except (TypeError, ValueError):
        flash("Invalid rating.", "error")
        return redirect(url_for("view_issue", issue_id=issue.id))

    if score < 1 or score > 5:
        flash("Rating must be between 1 and 5.", "error")
        return redirect(url_for("view_issue", issue_id=issue.id))

    existing = Rating.query.filter_by(issue_id=issue.id, user_id=current_user.id).first()
    if existing:
        flash("You already rated this issue.", "error")
        return redirect(url_for("view_issue", issue_id=issue.id))

    new_rating = Rating(
        issue_id=issue.id,
        user_id=current_user.id,
        score=score,
        feedback=feedback or None
    )

    db.session.add(new_rating)
    db.session.commit()

    flash("Thanks! Your rating was submitted.", "success")
    return redirect(url_for("view_issue", issue_id=issue.id))


# ========== TEMPLATE FILTERS ==========
@app.template_filter('format_date')
def format_date(value):
    if value:
        return value.strftime('%b %d, %Y')
    return ''

@app.template_filter('get_status_color')
def get_status_color(status):
    colors = {
        'Open': 'status-open',
        'In Progress': 'status-in-progress',
        'Resolved': 'status-resolved'
    }
    return colors.get(status, 'status-default')

@app.template_filter('get_priority_color')
def get_priority_color(priority):
    colors = {
        'Low': 'priority-low',
        'Medium': 'priority-medium',
        'High': 'priority-high',
        'Critical': 'priority-critical'
    }
    return colors.get(priority, 'priority-default')

# ========== APPLICATION SETUP ==========
def setup_database():
    """Initialize database with minimal sample data and seed users"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created")

        # Seed sample issues if none
        if Issue.query.count() == 0:
            add_sample_data()

        # Seed an admin and some staff if no users
        if User.query.count() == 0:
            admin = User(username='admin', email='admin@campus.local', role='admin')
            admin.set_password('adminpass')
            staff1 = User(username='maintenance1', email='maintenance1@campus.local', role='maintenance')
            staff1.set_password('staffpass')
            staff2 = User(username='staff1', email='staff1@campus.local', role='staff')
            staff2.set_password('staffpass')
            db.session.add_all([admin, staff1, staff2])
            db.session.commit()
            print("✅ Seeded admin and staff users (admin/adminpass).")

        else:
            print(f"✅ Database has {User.query.count()} users and {Issue.query.count()} issues")

#=========== Student Registration =========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not all([username, email, password, confirm]):
            flash('Please fill all required fields.', 'error')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email, role='student')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

#========== Student Profile ==========
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if current_user.role != 'student':
        flash('Only students can access profile.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        if not new_username:
            flash('Username cannot be empty.', 'error')
            return redirect(url_for('profile'))

        existing = User.query.filter_by(username=new_username).first()
        if existing and existing.id != current_user.id:
            flash('Username already taken.', 'error')
            return redirect(url_for('profile'))

        current_user.username = new_username
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

# ========== RUN APPLICATION ==========
if __name__ == '__main__':
    setup_database()
    app.run(debug=True)
