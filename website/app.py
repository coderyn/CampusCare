from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc
from datetime import datetime
from werkzeug.utils import secure_filename
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'campuscare-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024   # 5 MB (optional)

# Initialize database
db = SQLAlchemy(app)

# ========== DATABASE MODELS ==========
class User(db.Model):
    """User model (for future authentication)"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')  # student, admin, staff
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships - FIXED: Specify foreign_keys
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
    
    # Foreign keys
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    department = db.Column(db.String(50))  # Assigned department
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Issue {self.title}>'

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
    """Analytics dashboard"""
    total_issues = Issue.query.count()
    open_issues = Issue.query.filter_by(status='Open').count()
    in_progress_issues = Issue.query.filter_by(status='In Progress').count()
    resolved_issues = Issue.query.filter_by(status='Resolved').count()
    
    category_stats = get_category_stats()
    status_stats = get_status_stats()
    recent_issues = get_recent_issues(10)
    
    # Calculate percentages
    open_percentage = round((open_issues / total_issues * 100), 1) if total_issues > 0 else 0
    resolved_percentage = round((resolved_issues / total_issues * 100), 1) if total_issues > 0 else 0
    
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
    
    return render_template('issues.html',
                         issues=issues,
                         categories=categories,
                         statuses=statuses,
                         search=search,
                         category_filter=category,
                         status_filter=status)

@app.route('/issue/new', methods=['GET', 'POST'])
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
        
        # 🔹 handle uploaded image
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
            status='Open'
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

@app.route('/issue/<int:issue_id>')
def view_issue(issue_id):
    """View specific issue details"""
    issue = Issue.query.get_or_404(issue_id)
    return render_template('view_issue.html', issue=issue)

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
    """Initialize database with minimal sample data"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created")
        
        if Issue.query.count() == 0:
            add_sample_data()
            print("✅ Added 5 sample issues")
        else:
            print(f"✅ Database has {Issue.query.count()} issues")

# ========== RUN APPLICATION ==========
if __name__ == '__main__':
    setup_database()
    app.run(debug=True)