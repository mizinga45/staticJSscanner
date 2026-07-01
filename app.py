import os
import re
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from markupsafe import Markup, escape
from models import db, User, ScanJob
from auth.routes import auth_bp, bcrypt as auth_bcrypt
from web.routes import main_bp

app = Flask(__name__)

# Prefer SECRET_KEY from environment; if not set, fall back to a random key for safety
import os as _os
app.config['SECRET_KEY'] = _os.environ.get('SECRET_KEY') or _os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB file size limit for DoS protection


# Jinja2 filter: highlight dangerous syntax in red
HIGHLIGHT_PATTERNS = {
    'SQL Injection': [r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|INTO|VALUES|SET)\b', r'(\$\{[^}]+\})', r'(\+\s*\w+)'],
    'Cross-Site Scripting (XSS)': [r'(\.innerHTML)', r'(document\.write)', r'(dangerouslySetInnerHTML)', r'(\.outerHTML)'],
    'Command Injection': [r'\b(exec|execSync|spawn|execFile|system)\b'],
    'Insecure Use of eval()': [r'\b(eval)\s*\('],
    'Hardcoded Secret': [r'(["\'][A-Za-z0-9_\-/.]{12,}["\'])'],
    'Prototype Pollution': [r'(\[[^\]]+\])'],
    'Path Traversal': [r'\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream|appendFile|unlink|unlinkSync)\b'],
    'Open Redirect': [r'\b(redirect|replace|assign)\b', r'(location\.href)', r'(location\.replace)', r'(window\.location)'],
    'Regular Expression DoS (ReDoS)': [r'(RegExp|\.match|\.test|\.replace)\s*\(', r'(\([^)]*[+*][^)]*\)[+*])'],
    'Insecure Randomness': [r'(Math\.random|Math\.floor)', r'\b(random)\b'],
    'Angular Security Bypass': [r'(bypassSecurityTrust\w+)'],
    'Insecure Deserialization': [r'\b(unserialize|deserialize)\b'],
    'Server-Side Request Forgery (SSRF)': [r'\b(fetch|axios|request|http\.get)\b'],
    'Obfuscation Warning': [],
}


@app.template_filter('highlight_vuln')
def highlight_vuln(code, vuln_type):
    """Highlight dangerous syntax in red within code snippet."""
    if not code:
        return Markup('')
    text = str(code)
    patterns = HIGHLIGHT_PATTERNS.get(vuln_type, [])
    if not patterns:
        return Markup(escape(text))

    # Find all matches and their positions
    highlights = []
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            highlights.append((m.start(), m.end()))

    if not highlights:
        # Fallback: highlight data-flow indicators only (not generic keywords)
        fallback = [r'(location\.\w+)', r'(req\.\w+)', r'(document\.\w+)', r'(window\.\w+)',
                    r'(\.\w+Sync)\b', r'\b(query|params|body|cookies)\b',
                    r'\b(dataset\.\w+)']
        for pattern in fallback:
            for m in re.finditer(pattern, text):
                highlights.append((m.start(), m.end()))

    # If still nothing found, don't force-highlight irrelevant code
    if not highlights:
        return Markup(escape(text))

    if not highlights:
        return Markup(escape(text))

    # Merge overlapping ranges
    highlights.sort()
    merged = [highlights[0]]
    for start, end in highlights[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # Build output with highlighted spans
    result = []
    prev = 0
    for start, end in merged:
        result.append(escape(text[prev:start]))
        result.append(Markup('<span class="code-danger">'))
        result.append(escape(text[start:end]))
        result.append(Markup('</span>'))
        prev = end
    result.append(escape(text[prev:]))

    return Markup(''.join(str(r) for r in result))

db.init_app(app)
auth_bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp, url_prefix='/auth')


@app.route('/favicon.ico')
def favicon():
    from flask import send_from_directory
    return send_from_directory(app.static_folder + '/images', 'hero-bg.svg', mimetype='image/svg+xml')


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/pricing')
def pricing():
    return render_template('pricing.html')


def cleanup_stale_jobs():
    """
    Clean up scan jobs that have been stuck in 'running' state for too long.
    Prevents job table from growing unbounded and prevents locks.
    """
    from datetime import datetime, timedelta
    
    try:
        timeout_minutes = 10
        timeout_threshold = datetime.now() - timedelta(minutes=timeout_minutes)
        
        # Find jobs stuck in 'running' state
        stale_jobs = ScanJob.query.filter(
            ScanJob.status == 'running',
            ScanJob.updated_at < timeout_threshold
        ).all()
        
        if stale_jobs:
            import sqlite3 as sqlite3_mod
            import logging as log_mod
            
            logger = log_mod.getLogger(__name__)
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanner.db')
            
            for job in stale_jobs:
                try:
                    # Use raw SQL update for thread-safe operation
                    conn = sqlite3_mod.connect(db_path, timeout=5.0)
                    cur = conn.cursor()
                    cur.execute(
                        "UPDATE scan_job SET status = ?, message = ?, updated_at = datetime('now') WHERE id = ?",
                        ('error', f'Timeout - job did not complete within {timeout_minutes} minutes', job.id)
                    )
                    conn.commit()
                    conn.close()
                    logger.info(f"Cleaned up stale job {job.id} (stuck since {job.updated_at})")
                except Exception as e:
                    logger.error(f"Failed to cleanup job {job.id}: {e}")
    except Exception as e:
        import logging as log_mod
        logger = log_mod.getLogger(__name__)
        logger.error(f"Error in cleanup_stale_jobs: {e}")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        cleanup_stale_jobs()  # Clean up any stale jobs on startup
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
