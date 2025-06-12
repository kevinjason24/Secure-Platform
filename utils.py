import socket
import requests
import ssl
import subprocess
import re
import json
import time
from urllib.parse import urlparse, urljoin
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import nmap
except ImportError:
    nmap = None
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    import whois
except ImportError:
    whois = None

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]

def port_scan(target, ports=None):
    """Perform a port scan on the target"""
    try:
        # Parse URL to get hostname
        if target.startswith(('http://', 'https://')):
            hostname = urlparse(target).hostname
        else:
            hostname = target
        
        if not hostname:
            return {'error': 'Invalid target hostname'}
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return {'error': 'Could not resolve hostname'}
        
        ports_to_scan = ports or COMMON_PORTS
        open_ports = []
        vulnerabilities = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Try to identify service
                    service = get_service_info(ip, port)
                    port_info = {
                        'port': port,
                        'status': 'open',
                        'service': service.get('name', 'unknown'),
                        'version': service.get('version', '')
                    }
                    
                    # Check for known vulnerabilities
                    if port == 21 and 'ftp' in service.get('name', '').lower():
                        vulnerabilities.append({
                            'type': 'ftp_anonymous',
                            'severity': 'medium',
                            'description': f'FTP service detected on port {port}. Check for anonymous access.',
                            'recommendation': 'Disable anonymous FTP access and use secure alternatives like SFTP.'
                        })
                    elif port == 23:
                        vulnerabilities.append({
                            'type': 'telnet_unencrypted',
                            'severity': 'high',
                            'description': f'Telnet service detected on port {port}. Unencrypted communication.',
                            'recommendation': 'Replace Telnet with SSH for secure remote access.'
                        })
                    elif port == 80 and not any(p['port'] == 443 for p in open_ports):
                        vulnerabilities.append({
                            'type': 'http_no_https',
                            'severity': 'medium',
                            'description': 'HTTP service without HTTPS detected.',
                            'recommendation': 'Implement HTTPS to encrypt web traffic.'
                        })
                    
                    return port_info
            except Exception:
                pass
            return None
        
        # Parallel port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports_to_scan]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return {
            'target': hostname,
            'ip': ip,
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities,
            'scan_time': time.time()
        }
    
    except Exception as e:
        return {'error': str(e)}

def get_service_info(ip, port):
    """Get service information for an open port"""
    if nmap:
        try:
            nm = nmap.PortScanner()
            result = nm.scan(ip, str(port), '-sV')
            
            if ip in result['scan'] and port in result['scan'][ip]['tcp']:
                port_info = result['scan'][ip]['tcp'][port]
                return {
                    'name': port_info.get('name', 'unknown'),
                    'version': port_info.get('version', ''),
                    'product': port_info.get('product', ''),
                    'extrainfo': port_info.get('extrainfo', '')
                }
        except Exception:
            pass
    
    # Fallback to basic service detection
    common_services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
        995: 'pop3s', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql'
    }
    
    return {'name': common_services.get(port, 'unknown'), 'version': ''}

def vulnerability_scan(target):
    """Perform a comprehensive vulnerability scan"""
    vulnerabilities = []
    
    if not nmap:
        return {
            'target': target,
            'vulnerabilities': [],
            'error': 'Nmap not available for vulnerability scanning'
        }
    
    try:
        # Use nmap for vulnerability scanning
        nm = nmap.PortScanner()
        
        # Parse target
        if target.startswith(('http://', 'https://')):
            hostname = urlparse(target).hostname
        else:
            hostname = target
        
        # Run vulnerability scripts
        result = nm.scan(hostname, arguments='--script vuln -sV')
        
        if hostname in result['scan']:
            host_info = result['scan'][hostname]
            
            # Parse nmap script results
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if 'vuln' in script_name.lower():
                                vulnerabilities.append({
                                    'type': script_name,
                                    'severity': 'medium',
                                    'description': f'Vulnerability detected on port {port}: {script_output}',
                                    'recommendation': 'Update the service to the latest version and apply security patches.'
                                })
        
        return {
            'target': hostname,
            'vulnerabilities': vulnerabilities,
            'scan_time': time.time()
        }
        
    except Exception as e:
        return {'error': str(e)}

def sql_injection_test(target):
    """Test for SQL injection vulnerabilities"""
    vulnerabilities = []
    
    try:
        # Basic SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 'a'='a",
            "1' AND (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        # Common parameters to test
        test_params = ['id', 'user', 'username', 'email', 'search', 'q', 'category']
        
        for payload in payloads:
            for param in test_params:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        'mysql_fetch_array',
                        'ORA-01756',
                        'Microsoft Access Driver',
                        'SQLServer JDBC Driver',
                        'MySQL server version',
                        'PostgreSQL query failed',
                        'sqlite3.OperationalError',
                        'Unclosed quotation mark',
                        'SQLSTATE'
                    ]
                    
                    for indicator in error_indicators:
                        if indicator.lower() in response.text.lower():
                            vulnerabilities.append({
                                'type': 'sql_injection',
                                'severity': 'high',
                                'description': f'Potential SQL injection vulnerability found at parameter "{param}" with payload: {payload}',
                                'recommendation': 'Use parameterized queries and input validation to prevent SQL injection attacks.'
                            })
                            break
                            
                except requests.RequestException:
                    continue
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'test_count': len(payloads) * len(test_params)
        }
        
    except Exception as e:
        return {'error': str(e)}

def xss_test(target):
    """Test for Cross-Site Scripting (XSS) vulnerabilities"""
    vulnerabilities = []
    
    try:
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>"
        ]
        
        # Common parameters to test
        test_params = ['q', 'search', 'name', 'comment', 'message', 'input', 'data']
        
        for payload in payloads:
            for param in test_params:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'xss_reflected',
                            'severity': 'medium',
                            'description': f'Potential reflected XSS vulnerability found at parameter "{param}"',
                            'recommendation': 'Implement proper input validation and output encoding to prevent XSS attacks.'
                        })
                        
                except requests.RequestException:
                    continue
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'test_count': len(payloads) * len(test_params)
        }
        
    except Exception as e:
        return {'error': str(e)}

def directory_traversal_test(target):
    """Test for directory traversal vulnerabilities"""
    vulnerabilities = []
    
    try:
        # Directory traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
        ]
        
        # Common parameters that might be vulnerable
        test_params = ['file', 'path', 'page', 'document', 'template', 'include']
        
        for payload in payloads:
            for param in test_params:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for file content indicators
                    if ('root:' in response.text and '/bin/bash' in response.text) or \
                       ('# localhost' in response.text and '127.0.0.1' in response.text):
                        vulnerabilities.append({
                            'type': 'directory_traversal',
                            'severity': 'high',
                            'description': f'Directory traversal vulnerability found at parameter "{param}"',
                            'recommendation': 'Implement proper input validation and restrict file access to safe directories.'
                        })
                        
                except requests.RequestException:
                    continue
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'test_count': len(payloads) * len(test_params)
        }
        
    except Exception as e:
        return {'error': str(e)}

def rate_limit_test(target):
    """Test for rate limiting implementation"""
    vulnerabilities = []
    
    try:
        # Send multiple requests rapidly
        request_count = 20
        responses = []
        
        start_time = time.time()
        
        for i in range(request_count):
            try:
                response = requests.get(target, timeout=5)
                responses.append(response.status_code)
            except requests.RequestException:
                responses.append(0)
        
        end_time = time.time()
        
        # Check if all requests were successful (no rate limiting)
        successful_requests = sum(1 for code in responses if code == 200)
        
        if successful_requests == request_count:
            vulnerabilities.append({
                'type': 'no_rate_limiting',
                'severity': 'medium',
                'description': f'No rate limiting detected. {request_count} requests completed successfully in {end_time - start_time:.2f} seconds.',
                'recommendation': 'Implement rate limiting to prevent abuse and DoS attacks.'
            })
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'requests_sent': request_count,
            'successful_requests': successful_requests,
            'duration': end_time - start_time
        }
        
    except Exception as e:
        return {'error': str(e)}

def ssl_check(target):
    """Check SSL/TLS configuration"""
    vulnerabilities = []
    
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        if parsed_url.scheme != 'https':
            vulnerabilities.append({
                'type': 'no_ssl',
                'severity': 'medium',
                'description': 'No SSL/TLS encryption detected',
                'recommendation': 'Implement HTTPS to encrypt data in transit.'
            })
            return {
                'target': target,
                'vulnerabilities': vulnerabilities
            }
        
        # Check SSL certificate
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                not_after = cert['notAfter']
                exp_date = time.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                exp_timestamp = time.mktime(exp_date)
                current_timestamp = time.time()
                days_until_expiry = (exp_timestamp - current_timestamp) / (24 * 3600)
                
                if days_until_expiry < 30:
                    severity = 'high' if days_until_expiry < 7 else 'medium'
                    vulnerabilities.append({
                        'type': 'ssl_expiring',
                        'severity': severity,
                        'description': f'SSL certificate expires in {int(days_until_expiry)} days',
                        'recommendation': 'Renew SSL certificate before expiration.'
                    })
                
                # Check for weak cipher suites
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5']):
                        vulnerabilities.append({
                            'type': 'weak_cipher',
                            'severity': 'medium',
                            'description': f'Weak cipher suite detected: {cipher_name}',
                            'recommendation': 'Configure server to use strong cipher suites only.'
                        })
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'certificate_info': cert if 'cert' in locals() else None
        }
        
    except Exception as e:
        return {'error': str(e)}

def security_headers_check(target):
    """Check for security headers"""
    vulnerabilities = []
    
    try:
        response = requests.get(target, timeout=10)
        headers = response.headers
        
        # Check for missing security headers
        security_headers = {
            'X-Content-Type-Options': {
                'expected': 'nosniff',
                'severity': 'low',
                'description': 'X-Content-Type-Options header missing'
            },
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'severity': 'medium',
                'description': 'X-Frame-Options header missing (clickjacking protection)'
            },
            'X-XSS-Protection': {
                'expected': '1; mode=block',
                'severity': 'low',
                'description': 'X-XSS-Protection header missing'
            },
            'Strict-Transport-Security': {
                'expected': None,
                'severity': 'medium',
                'description': 'Strict-Transport-Security header missing (HSTS)'
            },
            'Content-Security-Policy': {
                'expected': None,
                'severity': 'medium',
                'description': 'Content-Security-Policy header missing'
            },
            'Referrer-Policy': {
                'expected': None,
                'severity': 'low',
                'description': 'Referrer-Policy header missing'
            }
        }
        
        for header_name, header_info in security_headers.items():
            if header_name not in headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': header_info['severity'],
                    'description': header_info['description'],
                    'recommendation': f'Add {header_name} header to improve security.'
                })
        
        # Check for information disclosure headers
        info_disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in info_disclosure_headers:
            if header in headers:
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'description': f'{header} header reveals server information: {headers[header]}',
                    'recommendation': f'Remove or obfuscate {header} header to prevent information disclosure.'
                })
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'headers': dict(headers)
        }
        
    except Exception as e:
        return {'error': str(e)}

def dns_enumeration(target):
    """Perform DNS enumeration"""
    if not dns:
        return {
            'target': target,
            'error': 'DNS resolver not available'
        }
        
    try:
        hostname = urlparse(target).hostname if target.startswith(('http://', 'https://')) else target
        
        results = {
            'target': hostname,
            'records': {},
            'subdomains': []
        }
        
        # DNS record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(hostname, record_type)
                results['records'][record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results['records'][record_type] = []
        
        # Common subdomain enumeration
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'blog']
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{hostname}"
                dns.resolver.resolve(full_domain, 'A')
                results['subdomains'].append(full_domain)
            except:
                pass
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

def whois_lookup(target):
    """Perform WHOIS lookup"""
    if not whois:
        return {
            'target': target,
            'error': 'WHOIS module not available'
        }
        
    try:
        hostname = urlparse(target).hostname if target.startswith(('http://', 'https://')) else target
        domain_info = whois.whois(hostname)
        
        return {
            'target': hostname,
            'domain_info': domain_info
        }
        
    except Exception as e:
        return {'error': str(e)} 