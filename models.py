import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

DATABASE = 'security_platform.db'

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
    with get_db() as conn:
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Scans table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                results TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Vulnerabilities table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Security reports table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                report_type TEXT NOT NULL,
                report_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()

class User:
    @staticmethod
    def create(username, email, password_hash):
        try:
            with get_db() as conn:
                cursor = conn.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                conn.commit()
                return User.get_by_id(cursor.lastrowid)
        except sqlite3.IntegrityError:
            return None
    
    @staticmethod
    def get_by_id(user_id):
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', (user_id,)
            ).fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_by_username(username):
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_by_email(email):
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE email = ?', (email,)
            ).fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def update_last_login(user_id):
        with get_db() as conn:
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user_id,)
            )
            conn.commit()

class Scan:
    @staticmethod
    def create(user_id, target_url, scan_type, status='pending'):
        with get_db() as conn:
            cursor = conn.execute(
                'INSERT INTO scans (user_id, target_url, scan_type, status) VALUES (?, ?, ?, ?)',
                (user_id, target_url, scan_type, status)
            )
            conn.commit()
            return Scan.get_by_id(cursor.lastrowid)
    
    @staticmethod
    def get_by_id(scan_id):
        with get_db() as conn:
            scan = conn.execute(
                'SELECT * FROM scans WHERE id = ?', (scan_id,)
            ).fetchone()
            return dict(scan) if scan else None
    
    @staticmethod
    def get_by_user_id(user_id):
        with get_db() as conn:
            scans = conn.execute(
                'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            ).fetchall()
            return [dict(scan) for scan in scans]
    
    @staticmethod
    def update_status(scan_id, status, results=None):
        with get_db() as conn:
            if status == 'completed':
                conn.execute(
                    'UPDATE scans SET status = ?, results = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?',
                    (status, results, scan_id)
                )
            else:
                conn.execute(
                    'UPDATE scans SET status = ? WHERE id = ?',
                    (status, scan_id)
                )
            conn.commit()
    
    @staticmethod
    def get_all():
        with get_db() as conn:
            scans = conn.execute(
                'SELECT * FROM scans ORDER BY created_at DESC'
            ).fetchall()
            return [dict(scan) for scan in scans]

class Vulnerability:
    @staticmethod
    def create(scan_id, vulnerability_type, severity, description, recommendation):
        with get_db() as conn:
            cursor = conn.execute(
                'INSERT INTO vulnerabilities (scan_id, vulnerability_type, severity, description, recommendation) VALUES (?, ?, ?, ?, ?)',
                (scan_id, vulnerability_type, severity, description, recommendation)
            )
            conn.commit()
            return Vulnerability.get_by_id(cursor.lastrowid)
    
    @staticmethod
    def get_by_id(vuln_id):
        with get_db() as conn:
            vuln = conn.execute(
                'SELECT * FROM vulnerabilities WHERE id = ?', (vuln_id,)
            ).fetchone()
            return dict(vuln) if vuln else None
    
    @staticmethod
    def get_by_scan_id(scan_id):
        with get_db() as conn:
            vulns = conn.execute(
                'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC, created_at DESC',
                (scan_id,)
            ).fetchall()
            return [dict(vuln) for vuln in vulns]
    
    @staticmethod
    def get_by_severity(severity):
        with get_db() as conn:
            vulns = conn.execute(
                'SELECT v.*, s.target_url, s.scan_type FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE v.severity = ? ORDER BY v.created_at DESC',
                (severity,)
            ).fetchall()
            return [dict(vuln) for vuln in vulns]
    
    @staticmethod
    def update_status(vuln_id, status):
        with get_db() as conn:
            conn.execute(
                'UPDATE vulnerabilities SET status = ? WHERE id = ?',
                (status, vuln_id)
            )
            conn.commit()
    
    @staticmethod
    def get_stats():
        with get_db() as conn:
            stats = conn.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_vulns,
                    SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed_vulns
                FROM vulnerabilities
            ''').fetchone()
            return dict(stats) if stats else {}

class SecurityReport:
    @staticmethod
    def create(scan_id, report_type, report_data):
        with get_db() as conn:
            cursor = conn.execute(
                'INSERT INTO security_reports (scan_id, report_type, report_data) VALUES (?, ?, ?)',
                (scan_id, report_type, report_data)
            )
            conn.commit()
            return cursor.lastrowid
    
    @staticmethod
    def get_by_scan_id(scan_id):
        with get_db() as conn:
            reports = conn.execute(
                'SELECT * FROM security_reports WHERE scan_id = ? ORDER BY created_at DESC',
                (scan_id,)
            ).fetchall()
            return [dict(report) for report in reports] 