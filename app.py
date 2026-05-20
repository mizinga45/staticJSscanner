import os
import re
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from markupsafe import Markup, escape
from models import db, User
from auth.routes import auth_bp, bcrypt as auth_bcrypt
from web.routes import main_bp

app = Flask(__name__)

# Use a fixed secret key so sessions survive server restarts
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secscan-js-secret-key-2026-group16-udom')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


# Jinja2 filter: highlight dangerous syntax in red
HIGHLIGHT_PATTERNS = {
    'SQL Injection': [r'(SELECT|INSERT|UPDATE|DELETE|DROP)', r'(\+\s*\w+)', r'(\$\{[^}]+\})'],
    'Cross-Site Scripting (XSS)': [r'(\.innerHTML)', r'(document\.write)', r'(dangerouslySetInnerHTML)'],
    'Command Injection': [r'(exec|execSync|spawn|execFile|system)\s*\('],
    'Insecure Use of eval()': [r'(eval)\s*\('],
    'Hardcoded Secret': [r'(["\'][A-Za-z0-9_\-]{16,}["\'])'],
    'Prototype Pollution': [r'(\[[^\]]+\])\s*='],
    'Path Traversal': [r'(readFile|readFileSync|writeFile|writeFileSync)\s*\('],
    'Open Redirect': [r'(redirect|location\.href|location\.replace)\s*[\(=]'],
    'Regular Expression DoS (ReDoS)': [r'(\([^)]*[+*][^)]*\)[+*])'],
    'Insecure Randomness': [r'(Math\.random)\s*\('],
    'Angular Security Bypass': [r'(bypassSecurityTrust\w+)'],
}

@app.template_filter('highlight_vuln')
def highlight_vuln(code, vuln_type):
    """Highlight dangerous syntax in red within code snippet."""
    escaped = escape(code)
    text = str(escaped)
    patterns = HIGHLIGHT_PATTERNS.get(vuln_type, [])
    for pattern in patterns:
        text = re.sub(pattern, r'<span class="code-danger">\1</span>', text, flags=re.IGNORECASE)
    return Markup(text)

db.init_app(app)
auth_bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp, url_prefix='/auth')


@app.route('/')
def landing():
    return render_template('landing.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
