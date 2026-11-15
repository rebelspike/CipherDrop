# Security Audit Instructions
## [Your Application Name]

This document lets someone unfamiliar with the project reproduce the security audit
independently. Follow SETUP.md first to get the application running.

---

## Prerequisites

* Application is running per SETUP.md
* [Any additional tools: e.g., `curl`, Burp Suite Community Edition, `sqlmap`]
* Test accounts created: admin@example.com (admin role), viewer@example.com (viewer role)

---

## Audit Scenario 1 — [e.g., Brute-Force Login]

**Security property tested:** Accounts  
**Expected result:** Rate limiting activates after 5 failed attempts

### Steps

1. Open a terminal and run the following script:

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:5000/login \
    -d "email=admin@example.com&password=wrongpassword"
done
```

2. Observe the HTTP status codes returned.

### Expected Output (defended)

```
401
401
401
401
401
429    ← rate limit activates here
429
429
...
```

### Actual Result (from our audit)

[What actually happened when you ran this test — include exact output]

### Response

[Fixed / Mitigated / Accepted — explain what you did]

---

## Audit Scenario 2 — [e.g., Key Exposure in Logs]

**Security property tested:** Encryption  
**Expected result:** No key material or plaintext appears in logs

### Steps

1. Enable verbose logging: [describe how]
2. Perform an encryption operation: [describe steps]
3. Search log output:

```bash
grep -i -E "key|secret|password|plaintext" app.log
```

4. Also check stdout during the operation for any leaked values.

### Expected Output (defended)

```
(no matches)
```

### Actual Result

[What happened]

### Response

[Fixed / Mitigated / Accepted]

---

## Audit Scenario 3 — [e.g., Privilege Escalation]

**Security property tested:** RBAC  
**Expected result:** Viewer-role token cannot access admin endpoints

### Steps

1. Log in as `viewer@example.com` and capture the session cookie:

```bash
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "email=viewer@example.com&password=viewerpass"
```

2. Attempt to call an admin-only endpoint with the viewer's session:

```bash
curl -b cookies.txt -X DELETE http://localhost:5000/admin/users/1
```

### Expected Output (defended)

```
HTTP/1.1 403 Forbidden
{"error": "Insufficient permissions"}
```

### Actual Result

[What happened]

### Response

[Fixed / Mitigated / Accepted]

---

## AI Red-Team Findings

### AI Tool Used

[Claude / ChatGPT / Gemini]

### Prompt Used

```
[Paste the main prompt you used to ask the AI to find vulnerabilities]
```

### Findings Summary

| # | Finding | Property | Tested | Result | Status |
|---|---|---|---|---|---|
| 1 | [e.g., Session fixation] | Accounts | Yes | [Vulnerable / Defended] | [Fixed / Accepted] |
| 2 | [e.g., Insecure direct object reference] | RBAC | Yes | [Result] | [Status] |
| 3 | [Finding] | [Property] | [Yes/No] | [Result] | [Status] |

---

## Known Residual Risks

| Risk | Severity | Justification for Accepting |
|---|---|---|
| [e.g., No CSRF protection on file delete] | Medium | [e.g., Application is not publicly deployed; would fix before production] |
| [Risk] | [Low/Med/High] | [Reason] |
