from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import subprocess
import json
import os
import time
import threading
from datetime import datetime
from collections import defaultdict

app = Flask(__name__, static_folder='web/static', template_folder='web/templates')
CORS(app)

# In-memory storage for scans
scans_db = {}
scan_id_counter = 0
scan_lock = threading.Lock()

SCAN_DIR = 'scan_results'
os.makedirs(SCAN_DIR, exist_ok=True)

def run_scan_background(scan_id, url, profile, modules, max_rps, evasion):
    """Run vulnscan.py in background thread"""
    global scans_db
    
    output_json = os.path.join(SCAN_DIR, f'scan_{scan_id}.json')
    
    cmd = ['python', 'vulnscan.py', '--url', url, '--json', output_json, '--max-rps', str(max_rps)]
    if evasion:
        cmd.append('--evasion')
    
    if profile and profile != 'custom':
        cmd.extend(['--profile', profile])
    elif modules:
        cmd.extend(['--modules', modules])
    else:
        cmd.append('--all')
    
    try:
        scans_db[scan_id]['status'] = 'running'
        scans_db[scan_id]['start_time'] = datetime.now().isoformat()
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Parse results
        if os.path.exists(output_json):
            with open(output_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                findings = data.get('findings', [])
                
                # Count by severity
                severity_counts = defaultdict(int)
                for f in findings:
                    severity_counts[f['severity']] += 1
                
                scans_db[scan_id]['findings'] = findings
                scans_db[scan_id]['severity_counts'] = dict(severity_counts)
                scans_db[scan_id]['total_findings'] = len(findings)
                modules_used = sorted({f['module'] for f in findings})
                scans_db[scan_id]['modules_used'] = modules_used
        
        scans_db[scan_id]['status'] = 'completed'
        scans_db[scan_id]['end_time'] = datetime.now().isoformat()
        
    except subprocess.TimeoutExpired:
        scans_db[scan_id]['status'] = 'timeout'
        scans_db[scan_id]['error'] = 'Scan timeout (10 min)'
    except Exception as e:
        scans_db[scan_id]['status'] = 'error'
        scans_db[scan_id]['error'] = str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    scans_list = []
    for sid, scan in scans_db.items():
        scans_list.append({
            'id': sid,
            'url': scan['url'],
            'profile': scan['profile'],
            'status': scan['status'],
            'start_time': scan.get('start_time'),
            'end_time': scan.get('end_time'),
            'severity_counts': scan.get('severity_counts', {}),
            'total_findings': scan.get('total_findings', 0)
        })
    return jsonify(scans_list)

@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan with findings"""
    if scan_id not in scans_db:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(scans_db[scan_id])

@app.route('/api/scans', methods=['POST'])
def create_scan():
    """Create new scan"""
    global scan_id_counter
    
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    profile = data.get('profile', 'full')
    modules = data.get('modules', '')
    max_rps = data.get('max_rps', 6)
    evasion = bool(data.get('evasion', False))
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    with scan_lock:
        scan_id_counter += 1
        scan_id = scan_id_counter
    
    scans_db[scan_id] = {
        'id': scan_id,
        'url': url,
        'profile': profile,
        'modules': modules,
        'max_rps': max_rps,
        'evasion': evasion,
        'status': 'pending',
        'findings': [],
        'severity_counts': {},
        'total_findings': 0,
        'modules_used': []
    }
    
    # Start scan in background
    thread = threading.Thread(target=run_scan_background, args=(scan_id, url, profile, modules, max_rps, evasion))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'pending'})

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete scan"""
    if scan_id in scans_db:
        # Clean up JSON file
        output_json = os.path.join(SCAN_DIR, f'scan_{scan_id}.json')
        if os.path.exists(output_json):
            os.remove(output_json)
        del scans_db[scan_id]
        return jsonify({'status': 'deleted'})
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics - only from latest completed scan"""
    total_scans = len(scans_db)
    in_progress = sum(1 for s in scans_db.values() if s['status'] == 'running')
    
    # Get severity counts from latest completed scan only
    severity_totals = {}
    latest_scan = None
    latest_time = None
    
    for scan in scans_db.values():
        if scan['status'] == 'completed' and scan.get('end_time'):
            if latest_time is None or scan['end_time'] > latest_time:
                latest_time = scan['end_time']
                latest_scan = scan
    
    if latest_scan:
        severity_totals = latest_scan.get('severity_counts', {})
    
    return jsonify({
        'total_scans': total_scans,
        'in_progress': in_progress,
        'severity_totals': severity_totals,
        'latest_scan_id': latest_scan['id'] if latest_scan else None
    })

if __name__ == '__main__':
    print("="*50)
    print("VulnScan Web Interface")
    print("="*50)
    print("Server running at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("="*50)
    app.run(debug=False, host='0.0.0.0', port=5000)
