from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import os
import sqlite3
import secrets
from datetime import datetime
import requests
import subprocess
import json
from models import init_db, Scan, Vulnerability
from utils import (
    port_scan, 
    vulnerability_scan, 
    sql_injection_test, 
    xss_test, 
    directory_traversal_test,
    rate_limit_test,
    ssl_check,
    security_headers_check
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return redirect(url_for('scan'))



@app.route('/dashboard')
def dashboard():
    all_scans = Scan.get_all()
    return render_template('dashboard.html', scans=all_scans)

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'comprehensive')
        
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Create scan record
        scan = Scan.create(
            user_id=1,  # Default user since no authentication
            target_url=target,
            scan_type=scan_type,
            status='running'
        )
        
        scan_results = {}
        vulnerabilities = []
        
        # Perform different types of scans based on scan_type
        if scan_type in ['comprehensive', 'network']:
            scan_results['port_scan'] = port_scan(target)
        
        if scan_type in ['comprehensive', 'web']:
            scan_results['sql_injection'] = sql_injection_test(target)
            scan_results['xss_test'] = xss_test(target)
            scan_results['directory_traversal'] = directory_traversal_test(target)
            scan_results['ssl_check'] = ssl_check(target)
            scan_results['security_headers'] = security_headers_check(target)
        
        if scan_type in ['comprehensive', 'vulnerability']:
            scan_results['vulnerability_scan'] = vulnerability_scan(target)
        
        # Parse results and create vulnerability records
        for scan_name, result in scan_results.items():
            if result.get('vulnerabilities'):
                for vuln in result['vulnerabilities']:
                    vulnerability = Vulnerability.create(
                        scan_id=scan['id'],
                        vulnerability_type=vuln.get('type', scan_name),
                        severity=vuln.get('severity', 'medium'),
                        description=vuln.get('description', ''),
                        recommendation=vuln.get('recommendation', '')
                    )
                    vulnerabilities.append(vulnerability)
        
        # Update scan status
        Scan.update_status(scan['id'], 'completed', json.dumps(scan_results))
        
        return jsonify({
            'scan_id': scan['id'],
            'status': 'completed',
            'results': scan_results,
            'vulnerabilities_count': len(vulnerabilities)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan/<int:scan_id>')
def scan_results(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan:
        flash('Scan not found')
        return redirect(url_for('dashboard'))
    
    vulnerabilities = Vulnerability.get_by_scan_id(scan_id)
    results = json.loads(scan['results']) if scan['results'] else {}
    
    return render_template('scan_results.html', scan=scan, vulnerabilities=vulnerabilities, results=results)

@app.route('/api/scans')
def api_scans():
    scans = Scan.get_all()
    return jsonify(scans)

@app.route('/api/vulnerabilities/<int:scan_id>')
def api_vulnerabilities(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    vulnerabilities = Vulnerability.get_by_scan_id(scan_id)
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    init_db()
    print('🚀 Starting SecurePlatform on http://localhost:8080')
    print('🔍 Ready to scan - No authentication required!')
    app.run(debug=True, host='0.0.0.0', port=8080) 