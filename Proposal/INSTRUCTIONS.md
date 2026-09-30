# Milestone 1 — How to Complete This Template

You can use an AI coding agent (Claude, Cursor, Codex, etc.) to help fill out these
templates. The prompts below are designed to produce high-quality, rubric-aligned output.

---

## Step 1 — Fill in manifest.yaml first

Open `manifest.yaml` and replace all placeholder values with your team's information.
This file is read by the autograder — accuracy matters.

**Prompt for your AI agent:**

```
I am working on a university security course project. Here is my team's information:

Team members:
- [Name], GWID [G12345678], email [name@gwu.edu], role: [architect/engineer/auditor]
- [Name], GWID [G12345679], email [name@gwu.edu], role: [engineer]

We are building: [brief description — e.g., "a password manager web app"]
from menu item [#] on the project page.
Our three security properties are: [encryption, accounts, audit_log]

Please fill in the manifest.yaml template with this information, keeping all
field names and YAML structure exactly as they are. Set checklist items to true
only for sections we have actually completed.
```

---

## Step 2 — Draft Section 1 (Product Description) in proposal-template.md

**Prompt for your AI agent:**

```
I am writing a project proposal for a university computer security course.
My team is building: [describe your application — what it does, who uses it,
what security problem it solves].

We will implement these three security properties:
1. [Property 1] — specifically using [mechanism, e.g., AES-256-GCM via Python cryptography library]
2. [Property 2] — specifically using [mechanism, e.g., Argon2id via argon2-cffi]
3. [Property 3] — specifically using [mechanism]

Write Section 1 (Product Description) of our proposal. It should be 2–3 paragraphs,
written for a technical audience (computer science students and instructor), and explain:
- What the application does and who it is for
- Which security properties we implement and exactly how (be specific about algorithms
  and libraries, not just "encryption")
- Why this is a meaningful security application

Do not be vague — if we say "encryption," specify the algorithm, mode, and library.
```

---

## Step 3 — Draft Section 2 (Timeline)

**Prompt for your AI agent:**

```
Help me create a realistic week-by-week project timeline for the following:

Project: [your application]
Team size: [2 or 3 people]
Roles: Architect ([Name]), Engineer ([Name]), Auditor ([Name] — if 3 people)

Key dates:
- Milestone 1 (proposal): Oct 2
- Milestone 2 (working build + audit plan): Oct 23
- HW3 due: Oct 30 (competing deadline — all team members)
- Milestone 3 (final report): Nov 20
- HW4 due: Dec 5 (after final, but plan accordingly)

Security properties to implement: [list them]

Create a table with columns: Week, Dates, Planned Work, Owner (role).
The plan should show that by Oct 23 we have a substantially working application
(not just a scaffold). Account for HW3 taking time in week 4.
Be realistic about what can be done in each week.
```

---

## Step 4 — Draft Section 3 (Mockups and Architecture)

For the mockups, you can ask an AI to describe what screens your application needs,
then use a visual tool (draw.io, Excalidraw, Figma, or even hand-drawn sketches) to
create them. You can also ask an AI image tool to generate rough UI mockups.

**Prompt for your AI agent (architecture diagram description):**

```
I am building [describe your application]. It has these components:
[e.g., a React frontend, a Python Flask backend, a SQLite database, and file storage]

The security properties implemented are:
[list them and where they are enforced]

Describe the architecture in terms of:
1. What components exist
2. What data flows between them (and in what direction)
3. Where each security property is enforced in the stack
4. What the trust boundary is (what is inside the system vs. outside)

I will use this description to draw an architecture diagram.
```

---

## Step 5 — Draft Section 4 (Security Design)

**Prompt for your AI agent:**

```
Help me write the Security Design section of a project proposal for a [describe application].

We are implementing: [list security properties with specific mechanisms].

Please write:

1. Security Constraints (3–5 invariants the system must always maintain — stated as rules,
   e.g., "No file content is ever stored or transmitted in plaintext")

2. Threat Model with:
   - Assets (what we are protecting)
   - Adversaries (who might attack and what capabilities they have)
   - At least 4 specific threats in the format:
     "An attacker who can [capability] could [action] to compromise [asset]."
     For each threat, state how our design addresses it.

3. Agentic Coding Plan: which AI tools we plan to use, how we will divide work between
   AI and manual effort, and how we will verify AI-generated security-critical code.

Be specific and technical. This is for a computer security course, not a general audience.
```

---

## Final Step — Convert to PDF

Once you have completed all sections in `proposal-template.md`, convert it to PDF:
- **Google Docs:** File → Open → upload the .md file, then File → Download → PDF
- **VS Code:** Install the "Markdown PDF" extension, then right-click → Export PDF
- **Pandoc (command line):** `pandoc proposal-template.md -o proposal.pdf`
- **Any word processor:** paste the content and export as PDF

Name the final file `proposal.pdf` and place it in your submission ZIP alongside `manifest.yaml`.

---

## Submission Checklist

Before zipping and submitting:

- [ ] `manifest.yaml` — all fields filled in, all checklist items set to `true` for completed sections
- [ ] `proposal.pdf` — all four sections present with real content (not placeholder text)
- [ ] ZIP named `lastname1-lastname2-lastname3.m1.zip` using your actual GWIDs
