from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import User, Project, Log, Vulnerability
from extensions import db
import uuid

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        projects = Project.query.all()
    else:
        projects = Project.query.filter_by(client_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)

@dashboard_bp.route('/create_project', methods=['POST'])
@login_required
def create_project():
    if current_user.role != 'client':
        flash('Only clients can create projects.')
        return redirect(url_for('dashboard.index'))
    
    name = request.form.get('name')
    target_url = request.form.get('target_url')
    
    # In a hackathon demo, we assign the first available admin automatically
    admin = User.query.filter_by(role='admin').first()
    admin_id = admin.id if admin else None

    project = Project(name=name, client_id=current_user.id, admin_id=admin_id, target_url=target_url)
    db.session.add(project)
    
    log = Log(project=project, action_type='PROJECT_CREATED', detail=f'Project {name} created by {current_user.username}')
    db.session.add(log)
    
    db.session.commit()
    flash('Project created successfully.')
    return redirect(url_for('dashboard.index'))

@dashboard_bp.route('/grant_consent/<project_id>', methods=['POST'])
@login_required
def grant_consent(project_id):
    project = Project.query.get_or_404(project_id)
    if project.client_id != current_user.id:
        flash('Unauthorized.')
        return redirect(url_for('dashboard.index'))

    project.consent_granted = True
    project.consent_token = str(uuid.uuid4())
    
    log = Log(project_id=project.id, action_type='CONSENT_GRANTED', detail=f'Access consent granted by {current_user.username}')
    db.session.add(log)
    db.session.commit()
    
    flash('Security scanning consent granted access.')
    return redirect(url_for('dashboard.project_detail', project_id=project.id))

@dashboard_bp.route('/project/<project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.role == 'client' and project.client_id != current_user.id:
        flash('Unauthorized.')
        return redirect(url_for('dashboard.index'))
    
    logs = Log.query.filter_by(project_id=project.id).order_by(Log.timestamp.desc()).all()
    vulns = Vulnerability.query.filter_by(project_id=project.id).order_by(Vulnerability.discovered_at.desc()).all()
    
    return render_template('project_detail.html', project=project, logs=logs, vulns=vulns)

@dashboard_bp.route('/api/project/<project_id>/logs')
@login_required
def get_logs(project_id):
    """API for real-time log polling (simulated sync)"""
    project = Project.query.get_or_404(project_id)
    if current_user.role == 'client' and project.client_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    logs = Log.query.filter_by(project_id=project.id).order_by(Log.timestamp.desc()).limit(20).all()
    return jsonify([
        {"timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "action_type": l.action_type, "detail": l.detail}
        for l in logs
    ])

@dashboard_bp.route('/api/project/<project_id>/vulns')
@login_required
def get_vulns(project_id):
    """API for real-time vulnerability polling"""
    project = Project.query.get_or_404(project_id)
    if current_user.role == 'client' and project.client_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    vulns = Vulnerability.query.filter_by(project_id=project.id).order_by(Vulnerability.discovered_at.desc()).all()
    return jsonify([
        {"id": v.id, "vuln_type": v.vuln_type, "endpoint": v.endpoint, "description": v.description, "fix_suggestion": v.fix_suggestion, "is_fixed": v.is_fixed, "ai_explanation": v.ai_explanation}
        for v in vulns
    ])

@dashboard_bp.route('/api/project/<project_id>/scan', methods=['POST'])
@login_required
def start_scan(project_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Only admins can trigger scans"}), 403
    
    # Run the scan synchronously for hackathon simplicity (or handle in thread)
    from scanner.core import run_scan
    success = run_scan(project_id)
    if success:
        return jsonify({"status": "Scan completed."})
    return jsonify({"error": "Scan failed or not consented"}), 400

@dashboard_bp.route('/api/project/<project_id>/fix', methods=['POST'])
@login_required
def trigger_fix(project_id):
    if current_user.role != 'admin' or current_user.plan != 'premium':
        return jsonify({"error": "Only premium admins can auto-fix"}), 403
    
    project = Project.query.get_or_404(project_id)
    if not project.consent_granted:
        return jsonify({"error": "Client has not granted access"}), 403
        
    import time
    time.sleep(1) # Simulate generating a Github PR
    
    # Mark vulnerabilities as fixed
    vulns = Vulnerability.query.filter_by(project_id=project.id).all()
    for v in vulns:
        v.is_fixed = True
    
    log = Log(project_id=project.id, action_type='FIX_APPLIED', detail='Admin triggered auto-fix: Automated Pull Request successfully opened on target GitHub repository.')
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"status": "Fix applied via PR!"})

