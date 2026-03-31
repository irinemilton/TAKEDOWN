import threading
import time
import requests
import random
from models import Project, Log, User
from extensions import db

def monitor_loop(app):
    """
    Background daemon loop that periodically checks active monitored projects.
    """
    with app.app_context():
        while True:
            time.sleep(12)  # Check every 12 seconds for the demo
            
            # Fetch all projects where monitoring is enabled
            monitored_projects = Project.query.filter_by(is_monitoring=True).all()
            
            for project in monitored_projects:
                # First, verify the client or admin is premium (just to be safe)
                client = User.query.get(project.client_id)
                admin = User.query.get(project.admin_id) if project.admin_id else None
                
                # If neither the client nor the admin is premium, turn it off and skip
                if client.plan != 'premium' and (admin is None or admin.plan != 'premium'):
                    project.is_monitoring = False
                    db.session.commit()
                    continue

                target_url = project.target_url
                if not target_url:
                    continue
                
                # We will just use the domain/IP to simulate a ping, but for the demo 
                # we'll pretend we are health-checking their API endpoints.
                
                start_time = time.time()
                try:
                    # In a real scenario, this would be a proper HTTP request to the target
                    # For this SAST demo, since target_url is usually a GitHub repo, 
                    # we just do a quick HEAD request or simulate it if it's GitHub.
                    
                    if "github.com" in target_url:
                        # Just hit the repo to see if it's up
                        res = requests.head(target_url, timeout=5)
                        status_code = res.status_code
                    else:
                        # General URL
                        res = requests.get(target_url, timeout=5)
                        status_code = res.status_code
                        
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    # ── DEMO DRAMATICS ──────────────────────────────────────────────
                    # 10% chance to simulate a fake DB latency spike/outage for presentation
                    if random.random() < 0.10:
                        status_code = 503
                        latency_ms = random.randint(3000, 8000)
                    # ────────────────────────────────────────────────────────────────

                    if status_code < 400:
                        detail = f'API Health Check: 200 OK (Latency: {latency_ms}ms)'
                        action_type = 'MONITOR_INFO'
                    else:
                        detail = f'CRITICAL: Target API unreachable or exhibiting high latency (Status {status_code}, {latency_ms}ms)'
                        action_type = 'MONITOR_ALERT'
                        
                except requests.RequestException as e:
                    # Connection failed entirely
                    detail = f'CRITICAL: Target server is down. Connection refused.'
                    action_type = 'MONITOR_ALERT'

                # Record the telemetry to the live dashboard
                log = Log(
                    project_id=project.id,
                    action_type=action_type,
                    detail=detail
                )
                db.session.add(log)
            
            # Commit all telemetry generated in this loop iteration
            if monitored_projects:
                db.session.commit()

def start_monitoring_daemon(app):
    """
    Initializes and starts the background monitoring thread.
    """
    t = threading.Thread(target=monitor_loop, args=(app,), daemon=True)
    t.start()
    print("📡 [Monitor] Continuous Monitoring Daemon started.")
