from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from extensions import db
from datetime import datetime
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class User(UserMixin, db.Model):
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='client') # 'admin' or 'client'
    plan = db.Column(db.String(20), default='free') # 'free' or 'premium'
    
    # Relationships
    client_projects = db.relationship('Project', foreign_keys='Project.client_id', backref='client', lazy=True)
    admin_projects = db.relationship('Project', foreign_keys='Project.admin_id', backref='admin', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String(128), nullable=False)
    client_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.String, db.ForeignKey('user.id'), nullable=True) # Admin assigned later
    target_url = db.Column(db.String(512), nullable=True)
    consent_granted = db.Column(db.Boolean, default=False)
    consent_token = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    logs = db.relationship('Log', backref='project', lazy=True)
    vulnerabilities = db.relationship('Vulnerability', backref='project', lazy=True)

class Log(db.Model):
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    project_id = db.Column(db.String, db.ForeignKey('project.id'), nullable=False)
    action_type = db.Column(db.String(50)) # e.g., 'SCAN_STARTED', 'VULN_FOUND', 'FIX_APPLIED', 'ALERT'
    detail = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Vulnerability(db.Model):
    id = db.Column(db.String, primary_key=True, default=generate_uuid)
    project_id = db.Column(db.String, db.ForeignKey('project.id'), nullable=False)
    vuln_type = db.Column(db.String(50)) # e.g., 'SQLi', 'XSS'
    severity = db.Column(db.String(20), default='Medium') # 'High', 'Medium', 'Low'
    endpoint = db.Column(db.String(256))
    payload = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text)
    ai_explanation = db.Column(db.Text)
    fix_suggestion = db.Column(db.Text)
    is_fixed = db.Column(db.Boolean, default=False)
    mock_before_code = db.Column(db.Text, nullable=True)
    mock_after_code = db.Column(db.Text, nullable=True)
    fixed_at = db.Column(db.DateTime, nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
