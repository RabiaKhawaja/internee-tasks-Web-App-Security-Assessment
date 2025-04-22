
# Web Application Security Internship (Week 4)

Welcome to the Week 4 report of the Web Application Security Internship by **Rabia Khawaja**.  
This document outlines the advanced threat detection and web security measures implemented in a Node.js-based web application.

##  Project Objective

To secure a Node.js web application by integrating real-time threat detection, API hardening techniques, and robust authentication mechanisms.

##  Technologies Used

- Node.js  
- Express.js  
- Fail2Ban  
- Helmet  
- Winston  
- Rate Limiter  
- CORS  
- dotenv

##  Features Implemented

- Intrusion Detection using Fail2Ban  
- Rate Limiting with `express-rate-limit`  
- Secure HTTP headers using Helmet  
- API Key Authentication  
- Custom logging using Winston  
- CORS restrictions for controlled frontend communication

##  Installation & Usage

1. Clone the repository.  
2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file:

```env
PORT=3000
API_KEY=yourapikey123
```

4. Start the server:

```bash
node index.js
```

##  API Authentication

All API routes are protected using an API key middleware.  
Requests must include the `x-api-key` header with a valid key.

##  Testing Secure Endpoints

Use the following curl command to test access:

```bash
curl -H "x-api-key: yourapikey123" http://localhost:3000/secure-data
```

##  Deliverables

- Complete server code  
- `.env.example` file  
- README documentation  
- Fail2Ban configuration sample  
- Security logs via Winston

##  Author

**Rabia Khawaja**  
Cybersecurity Intern  
Week 4 – April 2025
