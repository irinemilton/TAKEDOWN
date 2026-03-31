from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import User, Project, Log, Vulnerability
from extensions import db
import uuid
import threading
from datetime import datetime

# ── Scan state tracking (in-memory, per project) ────────────────────────────
# Maps project_id -> True when a stop has been requested
SCAN_STOP_FLAGS  = {}
# Maps project_id -> 'idle' | 'scanning' | 'fixing' | 'done' | 'stopped'
SCAN_STATUS      = {}

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
    """API for real-time vulnerability polling + security score"""
    project = Project.query.get_or_404(project_id)
    if current_user.role == 'client' and project.client_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    vulns = Vulnerability.query.filter_by(project_id=project.id).order_by(Vulnerability.discovered_at.desc()).all()
    
    # ── Security Score Calculation ────────────────────────────────────────────
    score = 100
    severity_deductions = {'High': 20, 'Medium': 10, 'Low': 5}
    for v in vulns:
        if not v.is_fixed:
            score -= severity_deductions.get(v.severity or 'Medium', 10)
    score = max(0, score)  # floor at 0
    
    # Determine rating label
    if score >= 85:
        rating = 'A'
    elif score >= 70:
        rating = 'B'
    elif score >= 50:
        rating = 'C'
    else:
        rating = 'F'
    
    return jsonify({
        'score': score,
        'rating': rating,
        'plan': project.client.plan if project.client else 'free',
        'vulns': [
            {
                'id': v.id,
                'vuln_type': v.vuln_type,
                'severity': v.severity or 'Medium',
                'endpoint': v.endpoint,
                'description': v.description,
                'fix_suggestion': v.fix_suggestion,
                'resolution_summary': v.resolution_summary or '',
                'is_fixed': v.is_fixed,
                'ai_explanation': v.ai_explanation,
                'mock_before_code': v.mock_before_code or '',
                'mock_after_code': v.mock_after_code or '',
                'fixed_at': v.fixed_at.strftime('%Y-%m-%d %H:%M:%S') if v.fixed_at else None,
            }
            for v in vulns
        ]
    })


@dashboard_bp.route('/api/project/<project_id>/scan', methods=['POST'])
@login_required
def start_scan(project_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Only admins can trigger scans"}), 403

    if SCAN_STATUS.get(project_id) == 'scanning':
        return jsonify({"error": "Scan already in progress"}), 409

    # Clear any previous stop flag and mark as scanning
    SCAN_STOP_FLAGS[project_id] = False
    SCAN_STATUS[project_id] = 'scanning'

    from scanner.core import run_scan
    from flask import current_app

    app = current_app._get_current_object()

    def _scan_thread():
        with app.app_context():
            try:
                run_scan(project_id, stop_flags=SCAN_STOP_FLAGS, scan_status=SCAN_STATUS)
            finally:
                # Ensure status is cleaned up even on crash
                if SCAN_STATUS.get(project_id) not in ('stopped',):
                    SCAN_STATUS[project_id] = 'done'

    t = threading.Thread(target=_scan_thread, daemon=True)
    t.start()
    return jsonify({"status": "Scan started in background."})


@dashboard_bp.route('/api/project/<project_id>/scan/stop', methods=['POST'])
@login_required
def stop_scan(project_id):
    """Admin OR the project's client can stop an active scan."""
    project = Project.query.get_or_404(project_id)
    is_owner = (current_user.role == 'admin' or project.client_id == current_user.id)
    if not is_owner:
        return jsonify({"error": "Unauthorized"}), 403

    if SCAN_STATUS.get(project_id) != 'scanning':
        return jsonify({"error": "No active scan to stop"}), 400

    SCAN_STOP_FLAGS[project_id] = True
    SCAN_STATUS[project_id] = 'stopped'

    log = Log(project_id=project_id, action_type='SCAN_STOPPED',
              detail=f'⛔ Scan manually stopped by {current_user.username}.')
    db.session.add(log)
    db.session.commit()
    return jsonify({"status": "Scan stop requested."})


@dashboard_bp.route('/api/project/<project_id>/scan/status')
@login_required
def scan_status(project_id):
    """Returns the current scan state for real-time UI updates."""
    project = Project.query.get_or_404(project_id)
    is_owner = (current_user.role == 'admin' or project.client_id == current_user.id)
    if not is_owner:
        return jsonify({"error": "Unauthorized"}), 403
    status = SCAN_STATUS.get(project_id, 'idle')
    return jsonify({"status": status})

@dashboard_bp.route('/api/project/<project_id>/fix', methods=['POST'])
@login_required
def trigger_fix(project_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Only admins can auto-fix"}), 403
    
    project = Project.query.get_or_404(project_id)
    if not project.consent_granted:
        return jsonify({"error": "Client has not granted access"}), 403
        
    import time
    time.sleep(1) # Simulate generating a Github PR
    
    from utils.ai_engine import generate_resolution_summary
    
    # Mark vulnerabilities as fixed and generate reports
    vulns = Vulnerability.query.filter_by(project_id=project.id).all()
    for v in vulns:
        if not v.is_fixed:
            v.is_fixed = True
            v.fixed_at = datetime.utcnow()
            v.resolution_summary = generate_resolution_summary(v.vuln_type, v.endpoint)
    
    log = Log(project_id=project.id, action_type='FIX_APPLIED', detail='Admin triggered auto-fix: AI resolution reports generated and automated Pull Request successfully opened.')
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"status": "Fix applied via PR!"})

@dashboard_bp.route('/api/project/<project_id>/monitor/toggle', methods=['POST'])
@login_required
def toggle_monitoring(project_id):
    """Toggles continuous background monitoring for any admin."""
    project = Project.query.get_or_404(project_id)
    is_owner = (current_user.role == 'admin' or project.client_id == current_user.id)
    if not is_owner:
        return jsonify({"error": "Unauthorized"}), 403

    # Premium plan required for continuous monitoring
    client = User.query.get(project.client_id)
    admin  = User.query.get(project.admin_id) if project.admin_id else None
    has_premium = (client and client.plan == 'premium') or (admin and admin.plan == 'premium') or (current_user.plan == 'premium')
    if not has_premium:
        return jsonify({'error': 'Continuous monitoring requires a Premium plan.', 'upgrade': True}), 403

    project.is_monitoring = not project.is_monitoring
    db.session.commit()
    
    state = "enabled" if project.is_monitoring else "disabled"
    log = Log(project_id=project.id, action_type='MONITOR_INFO', 
              detail=f'📡 Continuous Monitor {state} by {current_user.username}.')
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"status": state, "is_monitoring": project.is_monitoring})
