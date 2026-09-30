# Project Proposal
## CSCI 4531/6531 — Milestone 1

**Team Members:**
| Name | GWID | Email | Role |
|---|---|---|---|
| First Last | G12345678 | name@gwu.edu | Security Architect |
| First Last | G12345679 | name@gwu.edu | Security Engineer |

**Application:** [Name of your application — Menu Item #N or Custom]

---

## Section 1 — Product Description

*Describe your application as if writing a one-page brief for a new teammate. Answer:*
*• What does it do, and who uses it?*
*• Which security properties will you implement, and how specifically?*

[Your description here — 2–3 paragraphs. Be concrete: not just "encryption" but
"AES-256-GCM for stored files, with a per-user key derived from the master password
using Argon2id with a random 16-byte salt."]

---

## Section 2 — Timeline

*Week-by-week plan from Oct 2 (proposal) to Nov 20 (final submission).*
*Account for HW3 (due Oct 30) and HW4 (due Dec 5) competing for your time.*

| Week | Dates | Planned Work | Owner (role) |
|---|---|---|---|
| 1 | Oct 2–9 | [e.g., Scaffold project, set up repo and CI, first login flow] | Engineer |
| 2 | Oct 9–16 | [e.g., Encryption module complete and tested] | Engineer + Architect |
| 3 | Oct 16–23 | [e.g., RBAC layer; demo-ready build for Milestone 2] | Engineer |
| 4 | Oct 23–30 | [e.g., Complete remaining features; HW3 due Oct 30] | All |
| 5 | Oct 30–Nov 6 | [e.g., Security audit begins; start audit-plan execution] | Auditor |
| 6 | Nov 6–13 | [e.g., Audit complete; fixes applied; report draft] | All |
| 7 | Nov 13–20 | [e.g., Final report, slides, video recording] | All |

---

## Section 3 — Design Plan and Mockups

*Include visual mockups of the key screens. These may be created with AI tools,*
*Figma, hand-drawn sketches, or any other method. Label each and explain what*
*the user is doing and what security mechanism is in play.*

### Mockup 1 — [Primary screen name, e.g., "File Upload"]

[Insert mockup image or describe the screen]

**User action:** [What the user is doing on this screen]
**Security mechanism:** [What security property is enforced here and how]

### Mockup 2 — [Login / Account Creation]

[Insert mockup image or describe the screen]

**User action:**
**Security mechanism:**

### Mockup 3 — [Admin or Role-Differentiated View, if applicable]

[Insert mockup image or describe the screen]

**User action:**
**Security mechanism:**

### Architecture Diagram

[Insert a diagram showing: frontend, backend, database, and any other components.
Show data flows with arrows. Label where each security property is enforced.
You may use draw.io, Excalidraw, Mermaid, or a hand-drawn scan.]

---

## Section 4 — Security Design

### Security Constraints

*What must your system always guarantee? State these as invariants.*

1. [e.g., No file content is ever stored or transmitted in plaintext.]
2. [e.g., A viewer-role user can never delete or modify records.]
3. [e.g., Failed login attempts are rate-limited to 5 per minute per IP.]

### Threat Model

**Assets:**
* [e.g., User credentials (passwords, session tokens)]
* [e.g., Encrypted file contents]
* [e.g., Access control state (who has which role)]

**Adversaries:**
* [e.g., External attacker with network access but no account]
* [e.g., Malicious insider with a valid viewer-role account]
* [e.g., Attacker with read access to the database]

**Threats (at least 3):**

| # | Threat | Design Response |
|---|---|---|
| 1 | An attacker who can intercept network traffic could steal session tokens to impersonate a user. | All traffic over TLS; session tokens are HttpOnly and SameSite=Strict cookies. |
| 2 | An attacker who gains read access to the database could extract file contents. | Files are encrypted at rest with AES-256-GCM; keys are never stored in the database. |
| 3 | [An attacker who can [capability] could [action] to compromise [asset].] | [How your design addresses this, or: Out of scope — justification.] |

### Agentic Coding Plan

**Tools we plan to use:**
* [e.g., Claude for architecture discussions and boilerplate generation]
* [e.g., Cursor for in-editor completion during implementation]

**Division of work:**
* [e.g., AI will generate scaffold; all security-critical code (auth, crypto) will be manually reviewed line-by-line]
* [e.g., AI will propose test cases; engineer will verify and extend them]

**Verification approach for AI-generated security code:**
* [e.g., Any code touching passwords, tokens, or encryption keys will be reviewed against the OWASP ASVS checklist before merging]
* [e.g., We will ask the AI to explain its security choices and cross-reference with library documentation]
