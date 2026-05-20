from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanResult', backref='user', lazy=True, order_by='ScanResult.scanned_at.desc()')


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source = db.Column(db.String(500))
    total_vulns = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    extracted_urls = db.Column(db.Text, default='[]')  # JSON list of extracted JS URLs
    results_json = db.Column(db.Text, default='[]')    # Full vulnerability results as JSON
    summary_json = db.Column(db.Text, default='{}')    # Summary data as JSON
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_vulnerabilities(self):
        try:
            return json.loads(self.results_json)
        except (json.JSONDecodeError, TypeError):
            return []

    def get_summary(self):
        try:
            return json.loads(self.summary_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def get_extracted_urls(self):
        try:
            return json.loads(self.extracted_urls)
        except (json.JSONDecodeError, TypeError):
            return []
