# SecurePlatform - Web Security Scanner

A web application security testing platform I built to learn full-stack development and security. It performs automated vulnerability scans and generates detailed security reports.


## What it does

This app helps identify common web application vulnerabilities by running automated security tests. I built it to understand how security scanners work and to practice building full-stack applications.

**Key Features:**
- **Vulnerability Detection**: SQL injection, XSS, directory traversal testing
- **Network Scanning**: Port scanning and service detection  
- **SSL Analysis**: Certificate and encryption strength checks
- **Security Headers**: HTTP security configuration analysis
- **Interactive Dashboard**: View scan results with charts and statistics
- **REST API**: Programmatic access for automation

### Installation

1. **Clone and setup:**
```bash
git clone https://github.com/kevinjason24/SecurePlatform.git
cd security-platform
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Initialize database:**
```bash
python -c "from models import init_db; init_db()"
```

4. **Run the application:**
```bash
python app.py
```

5. **Access the platform:**
   - Open http://localhost:8080 in your browser

<!-- ### Docker Option
```bash
docker build -t secureplatform .
docker run -p 8080:8080 secureplatform
``` -->

## How to Use

1. **Start a Scan**: Enter a target URL and select scan type
2. **View Results**: Check the dashboard for scan progress and results
3. **Analyze Vulnerabilities**: Review detailed findings with severity ratings
4. **Export Reports**: Get recommendations for fixing identified issues

### Scan Types
- **Comprehensive**: Full security assessment (network + web app)
- **Web Application**: Focus on OWASP Top 10 vulnerabilities
- **Network**: Port scanning and service enumeration

### API Usage
```bash
# Start a new scan
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "web"}'

# Get scan results
curl http://localhost:8080/scan/1
```

## Technical Details

### Built With
- **Backend**: Python, Flask, SQLite
- **Frontend**: Bootstrap 5, Chart.js, HTML/CSS/JavaScript
- **Security Tools**: python-nmap, requests, cryptography
- **Testing**: unittest, 450+ test cases

### Flowchart
![Screenshot 2025-06-12 at 3 11 36 PM](https://github.com/user-attachments/assets/229e4a48-8c7e-4a7b-9af1-c8cb5e319b72)

### Screenshots 
![Comprehensive scan ](https://github.com/user-attachments/assets/4b9f2da2-5343-4b91-ab93-289e754e5ef8)

![Scan History](https://github.com/user-attachments/assets/0163a2f7-6aff-452b-bde6-2bb69e41c9fe)

![Scan results ](https://github.com/user-attachments/assets/d7bed3c9-2fdc-465c-aa93-eb8ac7b467e1)
![Scan results 2 ](https://github.com/user-attachments/assets/824e55e4-b3b4-4b39-8c95-b117fa35f365)


### Security Modules
- **SQL Injection Tester**: Tests common injection patterns
- **XSS Scanner**: Detects reflected and stored XSS
- **Directory Traversal**: Checks for path manipulation vulnerabilities
- **SSL Analyzer**: Validates certificates and cipher strength
- **Security Headers**: Checks for missing protective headers
- **Port Scanner**: Network reconnaissance with service detection

## What I Learned

This project helped me understand:
- **Web Security**: OWASP Top 10, common attack vectors, defense mechanisms
- **Full-Stack Development**: Flask backend, responsive frontend, database design
- **API Design**: RESTful endpoints, JSON responses, error handling
- **Testing**: Unit tests, security testing methodologies
<!-- - **DevOps**: Docker containerization, deployment considerations -->

<!-- ## Running Tests

```bash
# Run all tests
python -m unittest tests.py -v

# Test specific vulnerability scanner
python -c "from utils import sql_injection_test; print(sql_injection_test('https://httpbin.org'))"
``` -->

## Important Notes

⚠️ **Ethical Use Only**: This tool is for educational purposes and authorized testing only. Only scan websites you own or have explicit permission to test.

## Future Improvements

- [ ] Add more vulnerability tests (CSRF, XXE, SSRF)
- [ ] Implement user authentication and multi-tenancy  
- [ ] Add real-time scan progress updates
- [ ] Integrate with CVE databases

## License

MIT License - feel free to use this for learning or building upon.

---

**This project demonstrates my interest in cybersecurity and ability to build full-stack applications with real-world functionality.** 
