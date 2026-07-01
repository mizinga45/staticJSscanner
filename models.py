from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json
import random
import string

db = SQLAlchemy()

# ─────────────────────────────────────────────
# Subscription plans (in TZS)
# ─────────────────────────────────────────────
PLANS = {
    'free':       {'name': 'Free',       'price_tzs': 0,        'scans_per_month': 3,   'label': 'Trial'},
    'pro':        {'name': 'Pro',        'price_tzs': 25000,    'scans_per_month': 100,  'label': 'Pro'},
    'enterprise': {'name': 'Enterprise', 'price_tzs': 75000,    'scans_per_month': -1,   'label': 'Enterprise'},
}
TRIAL_SCANS = 3   # free scans before requiring subscription


class Institution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(30))
    address = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    members = db.relationship('User', backref='institution', lazy=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Roles: admin | manager | developer | institution
    role = db.Column(db.String(20), default='developer')
    institution_id = db.Column(db.Integer, db.ForeignKey('institution.id'), nullable=True)
    # Subscription
    subscription_plan = db.Column(db.String(20), default='free')   # free | pro | enterprise
    trial_scans_used = db.Column(db.Integer, default=0)
    subscription_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    scans = db.relationship('ScanResult', backref='user', lazy=True,
                            order_by='ScanResult.scanned_at.desc()')

    # ── role helpers ──
    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_manager(self):
        return self.role == 'manager'

    @property
    def is_developer(self):
        return self.role == 'developer'

    @property
    def is_institution(self):
        return self.role == 'institution'

    # ── subscription helpers ──
    @property
    def scans_remaining(self):
        if self.subscription_plan == 'enterprise':
            return -1   # unlimited
        if self.subscription_plan == 'pro':
            # Count this month's scans
            from datetime import timedelta
            month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
            count = ScanResult.query.filter(
                ScanResult.user_id == self.id,
                ScanResult.scanned_at >= month_start
            ).count()
            return max(0, PLANS['pro']['scans_per_month'] - count)
        # Free/trial
        return max(0, TRIAL_SCANS - self.trial_scans_used)

    @property
    def can_scan(self):
        if self.subscription_plan in ('pro', 'enterprise'):
            return True
        return self.trial_scans_used < TRIAL_SCANS

    @property
    def plan_info(self):
        return PLANS.get(self.subscription_plan, PLANS['free'])


class ManagerDeveloperLink(db.Model):
    """Manager owns/creates a developer account."""
    id = db.Column(db.Integer, primary_key=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    developer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    manager = db.relationship('User', foreign_keys=[manager_id],
                              backref='managed_developers')
    developer = db.relationship('User', foreign_keys=[developer_id])


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan = db.Column(db.String(20))
    amount_tzs = db.Column(db.Integer)
    reference = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')   # pending | confirmed
    paid_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='payments')


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source = db.Column(db.String(500))
    input_method = db.Column(db.String(20), default='file')   # file | url | folder | batch
    total_vulns = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    extracted_urls = db.Column(db.Text, default='[]')
    results_json = db.Column(db.Text, default='[]')
    summary_json = db.Column(db.Text, default='{}')
    testing_json = db.Column(db.Text, default='{}')
    is_minified = db.Column(db.Boolean, default=False)
    is_obfuscated = db.Column(db.Boolean, default=False)
    was_beautified = db.Column(db.Boolean, default=False)
    deobfuscation_method = db.Column(db.String(100), default=None)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_vulnerabilities(self):
        try:
            return json.loads(self.results_json)
        except Exception:
            return []

    def get_summary(self):
        try:
            return json.loads(self.summary_json)
        except Exception:
            return {}

    def get_extracted_urls(self):
        try:
            return json.loads(self.extracted_urls)
        except Exception:
            return []

    def get_testing_report(self):
        try:
            return json.loads(self.testing_json)
        except Exception:
            return {}
