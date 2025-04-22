
# Web Application Security Assessment

## Internship Task: Security Assessment of Web Application

**Intern Name:** Rabia Khawaja  
**Date:** 22nd April 2025  

---

## Week 5: Ethical Hacking & Exploiting Vulnerabilities

###  Goal:
Learn ethical hacking techniques, exploit vulnerabilities in a test environment, and enhance web application security.

---

## 1.  Ethical Hacking Basics

Ethical hacking involves legally probing systems for security flaws to fix them before attackers can exploit them.

### Tools Used:
- **Kali Linux**  A popular Linux distro packed with penetration testing tools.
- **Nmap**  Used for network discovery and security auditing.
- **Nikto**  A web server vulnerability scanner.

### Actions Performed:
1. Checked system IP:
    ```bash
    ifconfig
    ```
2. Ran Nmap to identify open ports and services:
    ```bash
    nmap -sV -p 3000 127.0.0.1
    ```
3. Used Nikto to scan for vulnerabilities:
    ```bash
    nikto -h http://127.0.0.1:3000
    ```

---

## 2.  SQL Injection & Exploitation

**SQL Injection (SQLi)** is when a malicious user tricks a database query into executing unintended commands.

### Step-by-step:
- Tested the login page for SQLi using:
    ```bash
    sqlmap -u "http://127.0.0.1:3000/login?username=test&password=test" --batch --risk=3 --level=5
    ```

### Why it's dangerous:
If your query looks like:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```
Attackers can **bypass authentication**, retrieve sensitive data, or even modify your database.

---

###  Fix: Prepared Statements

Prepared statements ensure user inputs are treated as data, not code — making SQL injection attacks useless.

#### Implementation (Node.js + SQLite3):
```javascript
const express = require('express');
const winston = require('winston');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = process.env.PORT || 3000;

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ],
});

// SQLite DB setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) return console.error(err.message);
    console.log('Connected to SQLite database');
});

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
`);

app.get('/login', (req, res) => {
    const { username, password } = req.query;
    const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';

    db.get(sql, [username, password], (err, row) => {
        if (err) {
            logger.error(`DB Error: ${err.message}`);
            return res.status(500).send('Internal Server Error');
        }
        if (row) {
            logger.info(`Successful login for user: ${username}`);
            res.send('Login successful');
        } else {
            logger.warn(`Failed login attempt for user: ${username}`);
            res.send('Invalid credentials');
        }
    });
});

app.listen(PORT, () => {
    logger.info(` Server running on port ${PORT}`);
});
```

---

## 3.  Cross-Site Request Forgery (CSRF) Protection

**CSRF** is an attack that tricks users into performing unwanted actions while they’re logged in (like changing a password or making a purchase).



### Protection with `csurf`:
- CSRF tokens ensure that the request is coming from a trusted source.

#### Implementation:
```bash
npm install csurf cookie-parser
```
```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({ cookie: true }));

app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
```

### Testing CSRF with Burp Suite:
1. Intercept a request using Burp.
2. Modify or remove the CSRF token.
3. Forward the request.
4. The request should fail if the token is invalid or missing.

---

##  Deliverables:

-  Ethical hacking performed with Nmap and Nikto.
-  SQL Injection vulnerability identified with SQLMap.
-  Prepared statements implemented to fix SQLi.
-  CSRF protection enabled using `csurf`.
-  Manual CSRF test performed using Burp Suite.
-  Secure login and token verification routes implemented.
-  Logs maintained via `winston` logger.

---

**End of Week 5 Report**
