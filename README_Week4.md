
# Web Application Security Assessment

## Internship Task: Security Assessment of Web Application

**Intern Name:** Rabia Khawaja  
**Date:** 12th April 2025  

---

## Week 4: Advanced Threat Detection & Web Security Enhancements

### Goal:
Implement advanced security measures, detect threats in real-time, and secure API endpoints.

---

### 1. Intrusion Detection & Monitoring

#### Tool: **Fail2Ban** (on Kali Linux)
- **Purpose:** Detect and mitigate brute-force attacks.
- **Setup:**
  - Installed Fail2Ban on the Kali Linux environment.
  - Configured `/etc/fail2ban/jail.local` to monitor SSH and application logs.
  - Set thresholds to ban IPs after multiple failed login attempts.

---

### 2. API Security Hardening

#### Objective:
- Prevent brute-force attacks using rate limiting.
- Restrict unauthorized cross-origin access using CORS.
- Secure API access using API keys or OAuth.

#### Implementation:

**Rate Limiting with `express-rate-limit`:**
```bash
npm install express-rate-limit
```
```javascript
const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});

app.use(limiter);
```

**CORS Configuration:**
```bash
npm install cors
```
```javascript
const cors = require("cors");

app.use(cors({
  origin: "https://yourfrontend.com",
  methods: ["GET", "POST"],
  credentials: true
}));
```

**API Key Authentication:**
```javascript
app.use((req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== process.env.MY_API_KEY) return res.status(401).send('Unauthorized');
  next();
});
```

**Environment Variables (.env):**
```env
PORT=3000
API_KEY=supersecureapikey123
```

**API Test:**
```bash
curl -H "x-api-key: supersecureapikey123" http://localhost:3000/secure-data
```

---

### 3. Security Headers & Content Security Policy (CSP)

#### Tool: **Helmet.js**

```bash
npm install helmet
```

**Helmet Setup:**
```javascript
const helmet = require("helmet");
app.use(helmet());
```

**Custom CSP Policy:**
```javascript
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trustedscripts.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
```

**HSTS Configuration:**
```javascript
app.use(
  helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  })
);
```

---

### 4. Logging & Monitoring Enhancements

#### Logger: **Winston**
```bash
npm install winston
```
```javascript
const winston = require('winston');

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

logger.info(' Application started');
```

---

### 5. Deliverables

-  Real-time threat detection using Fail2Ban.
-  Rate limiting and API authentication implemented.
-  CORS configuration and secure HTTP headers in place.
-  Content Security Policy (CSP) and HSTS enabled via Helmet.js.
-  Logging implemented using Winston.
-  Source code committed to GitHub with documentation.

---

**End of Week 4 Report**
