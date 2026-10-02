# Project Proposal
## CSCI 4531/6531 — Milestone 1

**Team Members:**
| Name | GWID | Email | Role |
|---|---|---|---|
| Richard Webb | G31162428 | r.webb1@gwu.edu | Security Architect |
| Kamran Ahmad | G37094725 | kamran.ahmad@gwu.edu | Security Engineer |
| Eric Torres | G3790557 | eric.torres@gwu.edu | Security Auditor |

**Application:** [CipherDrop - Menu Item #2]

---

## Section 1 — Product Description

*Describe your application as if writing a one-page brief for a new teammate. Answer:*
*• What does it do, and who uses it?*
*• Which security properties will you implement, and how specifically?*

[The application will store and manage files, doing end-to-end encyrption using AES-256-GCM via Python cryptographic library, in order to protect and prevent attacks on the database from influencing the files stored there. This protection will also allow for the safe and secure sending of files to persons of interest without worry that they will be intercepted, as even if intercepted the data will be encyrpted and thus impossible to obtain.

The application will use accounts, specifically using Argon2id via argon2-cffi, in order to allow the user to upload files that only they can see while maintaining confidentiality and allowing for only authorized users to see their specific files.

The application will then use a tamper evident cryptographically chained audit log to check exactly what damage was done from an attack and store information about every change to a file, what could have potentially been compromised, and ensure users are only authorized to access their files and nobody elses.

This is a meaningful security appliaction as the application is ensuring that files are easily accessible to their authorized user while maintaining confidentiality and privacy for the one who has the files, a big problem of todays society is hackers being able to attack databases and steal information. What this application hopes to accomplish is the ability to prevent file information from being stolen by encrypting them, ensuring security. ]

---

## Section 2 — Timeline

*Week-by-week plan from Oct 2 (proposal) to Nov 20 (final submission).*
*Account for HW3 (due Oct 30) and HW4 (due Dec 5) competing for your time.*

| Week | Dates | Planned Work | Owner (role) |
|---|---|---|---|
| 1 | Oct 2–9 | [Set up repo, Flask project scaffold, SQLite DB, basic registration/login with Argon2id] | Engineer |
| 2 | Oct 9–16 | [Encryption module (AES-256-GCM, per-file keys) with unit tests (maybe, could skip this); figure out key management design] | Engineer + Architect |
| 3 | Oct 16–23 | [File upload/download/delete with per-user access control; demo-ready build for Milestone 2] | Engineer |
| 4 | Oct 23–30 | [Figure out audit log and begin finalizing it, file sharing and session handling] | All |
| 5 | Oct 30–Nov 6 | [Do security audits: Attempt to attack the application using methods such as log tampering] | Auditor |
| 6 | Nov 6–13 | [Figure out audit findings, fix any bugs in application] | All |
| 7 | Nov 13–20 | [Final report, slides, finish the demo] | All |

---

## Section 3 — Design Plan and Mockups

*Include visual mockups of the key screens. These may be created with AI tools,*
*Figma, hand-drawn sketches, or any other method. Label each and explain what*
*the user is doing and what security mechanism is in play.*

### Mockup 1 — [Primary screen name, e.g., "File Upload"]

[There would be an upload file button along with a table of the users files that would include the name, size, and upload date.
Then there would be a download/share button per row.]

**User action:** [The user would select a file to upload, or they would download an existing file or share a file]
**Security mechanism:** [The file is encrypted with AES-256-GCM using a newly generated random key before being written to storage. The file key itself is encrypted with a key derived from the users password. Every request would check that the logged in user owns the file. The GCM tag would also detect any tampering with that file when it is decrypted.]

### Mockup 2 — [Login / Account Creation]

[A simple form with a username, password, and a Register/Login button.]

**User action:** [The user would create an account or log in.]
**Security mechanism:** [Passwords would be hashed with Argon2id (argon2-cffi) and never stored in plaintext. Login attempts would be rate limited, and error messages would be generic enough to avoid revealing whether or not the account exists.]

### Mockup 3 — [Audit Log View]

[A table that would show a timestamp, user, action (upload, download, share, delete, login), file ID, and a verify integrity button]

**User action:** [Reviews activity on their files and verifies the log hasnt been altered]
**Security mechanism:** [Each log entry stores a SHA-256 hash of its contents plus the previous entry's hash. Editing or deleting any past entry breaks every hash after it, which makes tampering easy to see. Users only see their own entries and cant view somebody elses.] 

### Architecture Diagram

[Insert a diagram showing: frontend, backend, database, and any other components.
Show data flows with arrows. Label where each security property is enforced.
You may use draw.io, Excalidraw, Mermaid, or a hand-drawn scan.]

![Architecture](<Frontend to Backend Crypto-2026-10-02-232809.png>) made using mermaid.live

---

## Section 4 — Security Design

### Security Constraints

*What must your system always guarantee? State these as invariants.*

1. [No file content is ever stored or transmitted in plaintext. (This literally)]
2. [Passwords should only be stored as Argon2id hashes, and encryption keys are never stored unwrapped]
3. [A user can never read or modify another users file without being granted access]
4. [Every file operation should produce an Audit Log]
5. [Any modification to an Audit Entry should be detectable]

### Threat Model

**Assets:**
* [User credentials (passwords, session tokens)]
* [ Encrypted file contents and their encyrption keys]
* [Audit log integrity]
* [Only those who own files can access them (Access control state)]

**Adversaries:**
* [External attacker with network access but no account]
* [Authenticated users with mal intent trying to access other users files]
* [A leaked backup causing an attacker to have read access to the database or storage]

**Threats (at least 3):**

| # | Threat | Design Response |
|---|---|---|
| 1 | An attacker who can intercept network traffic could steal session tokens to impersonate a user. | All traffic over TLS; session tokens are HttpOnly and SameSite=Strict cookies. |
| 2 | An attacker who gains read access to the database could extract file contents. | Files are encrypted at rest with AES-256-GCM; keys are never stored in the database. |
| 3 | An attacker who can repeatedly submit login requests could brute-force or credential-stuff passwords to compromise user accounts. | Argon2id makes offline attempts difficult; online attempts are rate-limited; generic error messages.|
| 4 | A logged-in user could change a file ID in a request to access another user's file.| Every file request checks the owner or share list server-side, not just that the user is logged in.|
| 5 | An attacker with database write access could edit or delete audit entries to hide their actions. | The audit log is hash-chained, so any change would be noticeable AND break the verification.|

### Agentic Coding Plan

**Tools we plan to use:**
* [ Chatgpt for flask routes, database schema, and generating test cases]
* [Github to maintain different versions and teamwork via push and pull requests along with branches]

**Division of work:**
* [Ai will generate the overall scaffold and give us an understanding of how it is done.]
* [All actually sensitive code is written and scrutinized by a team member and no Ai generation will be allowed for that part unless required for understanding]
* [Ai would propose test cases, but they must be thoroughly understood by team members and functional before implementation]

**Verification approach for AI-generated security code:**
* [Check every crypto and auth call against the official documentation]
* [Ask the Ai to explain its decision making, then check that over with known facts and our general understanding]
* [Write tests that attempt to break the application, anything that could potentially cause bugs]
* [Require the other teamates to approve any pull requests that relate to authorization, audit log, or any other sensitive part of the code]
