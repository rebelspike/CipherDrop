# Milestone 3 — How to Complete This Template

Use these AI prompts to help draft each document. Your security audit, reflection,
and analysis sections must represent your own thinking — prompts below are structured
to draw out your actual experience, not generate fictional content.

---

## manifest.yaml

Fill in all fields with accurate information from your completed project.
The manifest is used for AI-assisted pre-grading — inaccurate fields will be caught
during review and may result in grade deductions.

**Prompt:**

```
Fill in this Milestone 3 manifest for my security course project.

Team:
[Name, GWID, email, role — one entry per member]

Application name: [name]
Security properties actually implemented and working: [list]

Submission facts:
- Report page count: [number]
- Slide count: [number]
- Presentation video URL: [URL]

Security audit results:
- Total vulnerabilities found by AI red-team: [number]
- Fixed before submission: [number]
- Remaining as known limitations: [number]
- Total attack scenarios run: [number]

AI tools used: [list]
Used AI for red-teaming: [yes/no]

Set all checklist items to true only if the item is genuinely present in the submission.
Keep all YAML field names and structure exactly as in the template.
```

---

## security-checklist.yaml

Go through each field honestly. This checklist is read by an AI grader before human review.

**Prompt for reviewing your implementation against the checklist:**

```
I need to fill out a security self-assessment checklist for my [application name] project.
Help me determine the correct answer for each field based on my implementation.

Here is how I implemented each security property:

[Paste your relevant code or describe the implementation for each property]

For each field in the checklist, tell me:
1. What the field is checking
2. Whether my implementation satisfies it (yes/no)
3. If no, what would need to change

Fields to evaluate:
- For encryption: keys_stored_securely, plaintext_ever_logged, iv_unique_per_operation
- For accounts: password_hashing algorithm, rate_limiting, session_invalidation_on_logout, tokens_httponly
- For rbac: server_side_enforcement, privilege_escalation_tested
- For audit_log: tamper_evident, sensitive_data_excluded
```

---

## report.pdf (12–18 pages)

The report has six required sections. Use these prompts for each.

### Section 1 — Product Overview

**Prompt:**

```
Write Section 1 (Product Overview) of a final security course project report.

Application: [name and purpose]
Implemented security properties: [list each with specific mechanism]

This section should include:
- What the application does and who it is for (1 paragraph)
- Which security properties are implemented, with specific implementation details
  (algorithms, libraries, parameter choices — not just "encryption")
- References to screenshots I will insert (use placeholders like [Figure 1: Login screen])

The screenshots I will include are: [describe what each screenshot shows]

Write clearly for a technical audience (computer science instructor and peers).
```

### Section 2 — Architecture and Implementation

**Prompt:**

```
Write Section 2 (Architecture and Implementation) of my security project report.

My application's components: [describe — frontend, backend, database, etc.]
Technology stack: [language, framework, key libraries]
How each security property maps to code components:
[describe which files/modules implement which properties]

Key implementation decisions:
[describe important choices — e.g., why you chose SQLite over PostgreSQL,
why you used Flask-Login vs. hand-rolling sessions]

Write this section to explain the architecture and justify the security-relevant
decisions. Include a note that I will insert an architecture diagram as [Figure N].
```

### Section 3 — Security Audit

This section cannot be generated — it must document your actual red-team results.
Use this prompt to help structure what you found:

**Prompt:**

```
Help me write the Security Audit section of my project report based on my actual findings.

Here are the attack scenarios I ran and what happened:
[For each scenario: describe the attack, what you did, what the result was,
and how you responded — fixed, mitigated, or accepted]

AI red-team process:
[Describe the AI tool you used, the prompts you sent, and the suggestions it made]

Residual risks remaining:
[List each, its severity, and why you accepted it]

Organize this as a structured audit report with:
- Executive summary (1 paragraph: how many findings, how many fixed, residual risk level)
- Per-scenario entries with: attack description, test method, result, response
- Residual risks table
- Overall security posture assessment
```

### Section 4 — UX and Documentation Review

**Prompt:**

```
Help me write the UX and Documentation Review section of my security project report.

My application's interface: [describe the main screens and flows]
My CLI (if applicable): [describe commands and --help output]

Based on my review of the application, here is what I found:

Interface issues: [list anything unclear, confusing, or potentially leaking information]
Security UX wins: [list what works well — clear error messages, obvious security indicators]
CLI documentation status: [is --help complete? are exit codes documented?]
Setup reproducibility: [did someone else test SETUP.md? what happened?]

Write an honest 1–2 page review covering interface, CLI, and documentation.
Do not pretend everything is perfect — identify real weaknesses and what you would fix.
```

### Section 5 — Agentic Coding Reflection

This is one of the most important sections. It must reflect your real experience.

**Prompt:**

```
Help me structure the Agentic Coding Reflection section of my security project report.
I will provide the content — you help me organize and articulate it clearly.

My experience using AI tools during this project:

What AI tools I used: [list]
What AI got right:
[specific examples — code it generated that worked well]

What AI got wrong or I had to fix:
[specific examples — especially security-related corrections]

Security-critical sections I handled carefully:
[sections where I verified AI output especially thoroughly, and why]

Surprising moments:
[things that surprised me about working with AI on a security project]

What I would do differently:
[specific changes to how I would use AI tools next time]

Organize this into a coherent 1.5–2 page reflection. Avoid generic statements
like "AI was helpful" — focus on specific, concrete examples from our project.
```

### Section 6 — Known Limitations and Future Work

**Prompt:**

```
Write the Known Limitations and Future Work section of my security project report.

Known limitations and residual risks:
[list each — be honest about what your application does not protect against and why]

What I would implement with more time:
[list specific features or hardening steps]

Write this as an honest professional assessment. It is fine to acknowledge real
limitations — that is the expected and valued approach in security engineering.
```

---

## slides.pdf (10–15 slides)

**Prompt:**

```
Create a slide-by-slide outline for a 10–15 slide presentation of my security project.

Application: [name and purpose]
Team: [names and roles]
Key security properties: [list]
Most interesting audit finding: [describe]
Main lesson from agentic coding: [describe]

Required sections:
1. Title slide
2. Product overview — what it does and who it is for
3. Architecture diagram slide (I will insert diagram)
4. Security property deep-dive (1–2 slides — pick the most interesting one)
5. Demo highlights (2–3 slides with screenshots — I will insert them)
6. Security audit findings — what was found, fixed, residual
7. Agentic coding reflection — key lessons
8. Known limitations and future work
9. Conclusion / Q&A

For each slide, write: slide title, 3–5 bullet points or talking points,
and a note on what visual (diagram, screenshot, chart) to include.
Keep bullets short — 6 words or less per bullet. Favor visuals over text.
```

---

## src/AUDIT.md

Use the completed audit scenarios from Section 3 of your report to populate AUDIT.md.

**Prompt:**

```
Convert my security audit findings into step-by-step audit instructions that someone
unfamiliar with the project could follow.

For each scenario, I need:
- Prerequisites (what accounts, tools, and environment setup are needed)
- Numbered steps with exact commands (curl, scripts, or browser actions)
- Expected output if the application is defended correctly
- The actual output we observed when we ran the test

Here are my audit scenarios:
[paste each scenario with what you did and what happened]

Write these as clear, reproducible instructions. Include a tools list at the top.
```

---

## dependency-scan.txt

Run the appropriate command for your language and paste the output:

```bash
# Python
pip audit

# Node.js
npm audit

# Go
govulncheck ./...
```

If the scan finds high-severity vulnerabilities, address them in your report's
Known Limitations section. Note that `pip audit` and `npm audit` often flag
vulnerabilities in test or development dependencies that are not present in
production — explain this context in your report.

---

## Submission Checklist

Before zipping and submitting:

- [ ] `manifest.yaml` — all fields accurate, checklist items reflect reality
- [ ] `report.pdf` — 12–18 pages, all 6 sections present
- [ ] `slides.pdf` — 10–15 slides, visual-first
- [ ] `presentation.pdf` — one-pager with video URL clearly visible
- [ ] `ai-usage-final.pdf` — includes real transcripts from red-team phase
- [ ] `dependency-scan.txt` — actual output from running the scan tool
- [ ] `security-checklist.yaml` — honest self-assessment completed
- [ ] `src/README.md` — describes application and security property map
- [ ] `src/SETUP.md` — tested from a clean environment by a teammate
- [ ] `src/AUDIT.md` — step-by-step, reproducible audit instructions
- [ ] All source code in `src/`
- [ ] ZIP named `lastname1-lastname2-lastname3.m3.zip` using your actual GWIDs
