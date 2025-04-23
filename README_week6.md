**Internship Task:** Final Security Audit & Deployment Hardening

**Intern Name:** Rabia Khawaja  
**Date:** 24th April 2025

* * *

### 🛡️ Week 6: Advanced Security Audits & Final Deployment Security

**Goal:**  
Perform security audits, ensure compliance with security standards, and prepare the application for secure deployment.

* * *

### 🔍 Task 1: Security Audits & Compliance

#### What We Did:

*   **OWASP ZAP:**
    
    *   Intercepted traffic by setting browser proxy to ZAP.
        
    *   Ran Active Scan on local Node.js app.
        
    *   Identified potential XSS and cookie misconfigurations.
        
    *   Generated and saved full vulnerability report.
        
    
    **Code Snippet - Set ZAP as proxy in browser:**
    
        Proxy IP: 127.0.0.1
        Proxy Port: 8080
    
*   **Nikto:**
    
    *   Command used:
        
    
        nikto -h http://127.0.0.1:3000
    
    *   Detected outdated headers and server info leakage.
        
*   **Lynis:**
    
    *   Installed and executed:
        
    
        sudo apt install lynis
        sudo lynis audit system
    
    *   Provided insights into missing firewall rules and unused services.
        
*   **OWASP Top 10 Check:**
    
    *   Mapped detected issues from ZAP and Nikto to Top 10 risks.
        
    *   Applied fixes to mitigate Injection, Security Misconfiguration, and Broken Authentication risks.
        

* * *

### 🐳 Task 2: Secure Deployment Practices

#### What We Did:

*   **Automatic Security Updates:**
    
    *   Enabled using:
        
    
        sudo apt install unattended-upgrades
        sudo dpkg-reconfigure --priority=low unattended-upgrades
    
*   **Dependency Scanning:**
    
    *   Used:
        
    
        npm audit fix
        npm audit
    
    *   Fixed vulnerabilities and noted unresolved issues manually.
        
*   **Docker Image Hardening:**
    
    *   Scanned image using:
        
    
        docker scan <image-name>
    
    *   Dockerfile best practices:
        
    
        FROM node:slim
        WORKDIR /app
        COPY . .
        RUN npm install
        USER node
        CMD ["node", "index.js"]
    
    *   Created `.dockerignore`:
        
    
        node_modules
        npm-debug.log
        .env
    

* * *

### 💣 Task 3: Final Penetration Testing

#### What We Did:

*   **Burp Suite:**
    
    *   Intercepted and modified login and form submissions.
        
    *   Attempted CSRF and XSS payloads.
        
    *   Verified CSRF protection with invalid token tests.
        
    
    **Example XSS Payload:**
    
        <script>alert('XSS')</script>
    
*   **Metasploit:**
    
    *   Opened console:
        
    
        msfconsole
    
    *   Used relevant web module:
        
    
        use exploit/multi/http/nodejs_templating_rce
        set RHOST 127.0.0.1
        run
    

#### Findings:

| Vulnerability | Tool Used | Risk Level | Fix Applied |
| --- | --- | --- | --- |
| XSS in login form | Burp Suite | Medium | Input sanitization + CSP |
| Missing HTTPOnly flags | OWASP ZAP | Medium | Secure cookie configuration |
| CSRF Token Bypass | Burp Suite | High | Implemented csurf middleware |

* * *

### 📄 Summary:

*   Completed comprehensive audits with 3 industry tools.
    
*   Mapped and fixed OWASP Top 10 vulnerabilities.
    
*   Hardened server and Docker container.
    
*   Performed full penetration testing.
    
*   Documented findings and applied remediations.
    

