# Compass Bug Bounty Program: Zero-to-Advanced Testing Playbook
**Program-Specific Methodology, Guardrails, Step-by-Step Workflow, Practical Examples & Reporting Guide**

> **Program Compliance First**: This playbook is tailored strictly to the **Compass Bug Bounty Policy** on HackerOne. Always stay within Compass-owned in-scope assets, enforce rate discipline, include your mandatory `X-Bug-Bounty` header on every request, and stop immediately if you encounter non-test PII.

---

## Table of Contents

1. [Compass Program Snapshot & Hard Guardrails](#1-compass-program-snapshot--hard-guardrails)
2. [Zero-to-Ready Lab Setup for Compass](#2-zero-to-ready-lab-setup-for-compass)
3. [End-to-End Compass Testing Workflow](#3-end-to-end-compass-testing-workflow)
4. [Phase 1: Policy-Compliant Reconnaissance & JS Mining](#4-phase-1-policy-compliant-reconnaissance--js-mining)
5. [Phase 2: Consumer Feature Mapping (What to Test vs. Skip)](#5-phase-2-consumer-feature-mapping-what-to-test-vs-skip)
6. [Phase 3: Access Control Testing (IDOR / BOLA / BFLA)](#6-phase-3-access-control-testing-idor--bola--bfla)
7. [Phase 4: Authentication, Sessions, JWT & OAuth](#7-phase-4-authentication-sessions-jwt--oauth)
8. [Phase 5: Server-Side & Injection Testing (Manual & Safe)](#8-phase-5-server-side--injection-testing-manual--safe)
9. [Phase 6: Client-Side & Modern Browser Attacks](#9-phase-6-client-side--modern-browser-attacks)
10. [Phase 7: APIs, GraphQL, File Uploads, Races & Cache](#10-phase-7-apis-graphql-file-uploads-races--cache)
11. [Phase 8: Verification, Impact & Compass Report Template](#11-phase-8-verification-impact--compass-report-template)

---

## 1. Compass Program Snapshot & Hard Guardrails

### Program Highlights
- **Platform**: HackerOne (Public, `0.0+` Signal required)
- **Safe Harbor**: Gold Standard Safe Harbor
- **Response & Payout**: >90% response efficiency, ~5 business days first response, ~10 business days triage, ~1 week 6 days average time to bounty
- **Average Bounties**: Low `$300` | Medium `$800` | High `$3,000` | Critical `$6,000`
- **Account Classes**: `Consumer (Buyer/Seller)` -> `Agent` -> `Staff`

### Non-Negotiable Rules (Violating These = N/A or Ban)
1. **Mandatory Custom Header** on *all* requests:
   ```http
   X-Bug-Bounty: HackerOne-<your_username>
   ```
2. **Search Box = MANUAL TESTING ONLY**: Never run `ffuf`, `sqlmap`, `nuclei`, or Intruder against search endpoints.
3. **Never Trigger Agent or Staff Notifications**: Do **not** test "Work with an Agent", agent contact forms, or anything that creates support tickets.
4. **Consumer Accounts Only**: Self-register **only** Buyer/Seller accounts using `@wearehackerone.com`. Never attempt to register or social-engineer an Agent account.
5. **Out-of-Scope Assets**:
   - Agent marketing sites on Squarespace/Wix/etc.
   - `https://www.compass.com/notifications/emails/*`
   - GitHub Wiki pages, public Google Calendars, Iorad links
   - **Anywhere Real Estate** (`hackerone.com/anywhererealestate`)
6. **Known Expected Behaviors (Do NOT Report)**:
   - `personIDs` are **not** secret.
   - Agent PII (names, emails, phones, addresses) is intentionally public—even on "private" profiles.
   - **Collections**: Invited users removing anyone/listings or inviting other users without an invitation is expected.
   - Client-side Google Maps API keys (unless you prove direct abuse/restriction bypass).
   - Untested credential dumps or non-employee `@compass.com` agent credentials on third-party sites.

---

## 2. Zero-to-Ready Lab Setup for Compass

### Step 2.1: Create Your Workspace
```bash
mkdir -p ~/bounty/compass/{recon,endpoints,js,notes,pocs}
cd ~/bounty/compass
```

### Step 2.2: Configure Burp Suite / Caido
1. **Scope**: Add Compass's in-scope domains from the HackerOne Scope tab (e.g., `^.*\.compass\.com$`) and enable **"Don't send items to Proxy history if out of scope"**.
2. **Mandatory Header (Match & Replace)**:
   - Burp -> **Proxy** -> **Proxy Settings** -> **Match and Replace** -> **Add**:
     - **Type**: `Request header`
     - **Match**: *(leave empty)*
     - **Replace**: `X-Bug-Bounty: HackerOne-<your_username>`
   - Verify in **Proxy -> HTTP history** that every outgoing request carries this header.

### Step 2.3: Create Two Consumer Test Accounts
1. Install **Firefox Multi-Account Containers**.
2. Open **Container 1 (Red)** -> register **Buyer A**: `<your_h1_username>+buyerA@wearehackerone.com`.
3. Open **Container 2 (Blue)** -> register **Buyer B**: `<your_h1_username>+buyerB@wearehackerone.com`.
4. Confirm both accounts work before running any tests.

---

## 3. End-to-End Compass Testing Workflow

```text
[1. Setup] -> Header X-Bug-Bounty set + Buyer A & Buyer B logged in
     │
     ▼
[2. Passive Recon & JS Mining] -> Find Compass-owned APIs, subdomains, & hidden routes
     │                            (Skip Squarespace/Wix & never fuzz search)
     ▼
[3. Manual Consumer Walkthrough] -> Map Profile, Saved Searches, Collections, Uploads, Auth
     │
     ▼
[4. Access Control (High ROI)] -> Buyer A vs Buyer B IDOR + Consumer -> Agent/Staff BFLA
     │
     ▼
[5. Auth, OAuth & Session] -> Reset flows, SSO/OAuth, JWT/Cookies, 2FA
     │
     ▼
[6. Injection & Server-Side] -> Manual SQLi, SSRF (images/exports), SSTI, Path Traversal
     │
     ▼
[7. Client-Side & Modern] -> Stored/DOM XSS, CORS, postMessage, Prototype Pollution, GraphQL
     │
     ▼
[8. Verify & Report] -> Minimal PoC, no real PII saved, clear Impact + Remediation
```

---

## 4. Phase 1: Policy-Compliant Reconnaissance & JS Mining

Because `compass.com` is a large, mature platform, **passive recon + JavaScript analysis** is far more effective (and safer) than noisy brute-force scanning.

### Step 4.1: Passive Subdomain Discovery
```bash
# Passive enumeration (zero traffic to Compass servers)
subfinder -d compass.com -all -silent -o recon/subs_subfinder.txt

curl -s "https://crt.sh/?q=%25.compass.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > recon/subs_crtsh.txt

cat recon/subs_*.txt | sort -u > recon/all_subs.txt
```

### Step 4.2: Gentle Live Probing (Respecting Rate & Scope)
```bash
# Resolve DNS
dnsx -l recon/all_subs.txt -silent -o recon/resolved_subs.txt

# Probe gently (10 req/s) WITH the mandatory X-Bug-Bounty header
httpx -l recon/resolved_subs.txt \
  -H "X-Bug-Bounty: HackerOne-<your_username>" \
  -sc -title -td -cl -location \
  -rate-limit 10 \
  -o recon/live_hosts.txt

cut -d' ' -f1 recon/live_hosts.txt > recon/live_urls.txt
```
- **Filter Out Noise**: Ignore third-party CNAMEs pointing to Squarespace, Wix, Zendesk, or Anywhere Real Estate. Focus on Compass-owned APIs, staging/dev hosts, and internal portals.

### Step 4.3: Mining Compass JavaScript Bundles
While browsing `compass.com` as Buyer A, Burp collects all `.js` bundles. You can also extract JS URLs from passive archives:
```bash
gau --subs compass.com | grep -Ei "\.js(\?|$)" | sort -u > js/js_files.txt

# Download JS files gently and grep for internal API routes & GraphQL queries
mkdir -p js/downloaded
xargs -a js/js_files.txt -P 3 -I {} sh -c 'curl -sL -H "X-Bug-Bounty: HackerOne-<your_username>" --max-time 10 "$1" -o "js/downloaded/$(printf %s "$1" | md5sum | cut -d" " -f1).js"' _ {}

grep -Erho "(/api/v[0-9]+/[a-zA-Z0-9_/{}-]+|/graphql|/gql|/internal/[a-zA-Z0-9_/-]+)" js/downloaded/ | sort -u > endpoints/js_routes.txt
```
- **What to look for in `js_routes.txt`**:
  - Endpoints containing `admin`, `agent`, `staff`, `export`, `import`, `webhook`, `upload`, `token`, `billing`, `internal`.
  - Feature flags or beta routes hidden in the UI.

---

## 5. Phase 2: Consumer Feature Mapping (What to Test vs. Skip)

Browse `compass.com` as Buyer A and map each feature:

| Feature | Testable? | What to Look For |
| :--- | :--- | :--- |
| **Account Profile & Settings** | **Yes** | IDOR on profile update, email/phone change auth bypass, Stored XSS in name/bio |
| **Saved Searches & Alerts** | **Yes (Manual)** | IDOR on saved search IDs, Stored XSS in saved search names, CSRF |
| **Collections** | **Careful** | Remember: invited users removing users/listings or inviting without invite is **expected**. Test only *uninvited* / *non-member* IDOR or XSS in collection names/notes! |
| **Search Bar** | **Manual Only** | Manual XSS / SQLi / GraphQL probing only—**zero automation** |
| **Work with an Agent / Support** | **NO** | **Do not test**—triggers emails/tickets to real agents/staff |
| **Document / Image Uploads** | **Yes** | SVG XSS, metadata/EXIF, SSRF in image URL import, path traversal in filenames |
| **Login / SSO / Password Reset** | **Yes** | OAuth `redirect_uri`, `state` CSRF, reset token leakage, 2FA bypass |

---

## 6. Phase 3: Access Control Testing (IDOR / BOLA / BFLA)

This is your highest-probability area on a multi-role platform (`Consumer` vs `Agent` vs `Staff`).

### Step 6.1: Horizontal IDOR (Buyer A -> Buyer B)
1. As **Buyer B** (Blue container), perform actions on private consumer data:
   - View/edit account settings
   - View/edit/delete a saved search
   - Create a private collection (without inviting Buyer A) and add a note
2. Send each request to **Burp Repeater**.
3. Replace Buyer B's session cookie / `Authorization` token with **Buyer A's** token.
4. **What counts as a valid bug**:
   - Buyer A can **read, modify, or delete** Buyer B's private saved search, private collection (when not invited), or private profile/preferences.
   - *(Remember: `personIDs` themselves are not secret—you must prove unauthorized access to private data or state-changing actions!)*

### Step 6.2: Vertical Privilege Escalation (Consumer -> Agent / Staff BFLA)
Using the hidden endpoints you found in `endpoints/js_routes.txt`:
1. Send a request to an Agent-only or Staff-only endpoint (e.g., `/api/v1/agent/...` or `/api/v1/staff/...`) using **Buyer A's** token.
2. If you get `403 Forbidden`, test BFLA bypasses:
   - **Method swap**: `GET` -> `POST`, `PUT`, `PATCH`, or add `X-HTTP-Method-Override: GET`.
   - **Path normalization**: `/api/v1/agent/stats/` or `/api/v1/agent/stats;.json` or `/api/v1/./agent/stats`.
   - **Parameter pollution**: `?role=consumer&role=agent` or JSON `{"accountType": "agent"}` during profile update (Mass Assignment).

> **Safety Rule**: If a Staff/Admin endpoint returns real customer or agent PII, **stop immediately**, take a single redacted screenshot of the response structure, and report it without enumerating further records.

---

## 7. Phase 4: Authentication, Sessions, JWT & OAuth

### Step 7.1: Session & Token Lifecycle
- **Session Invalidation**: Log out of Buyer A, then replay an authenticated request in Burp Repeater. Does the old session cookie/JWT still work?
- **Password Change**: Change Buyer A's password in Container 1—does Container 2's active session get invalidated?
- **JWT Auditing** (if Compass APIs use JWTs):
  ```bash
  # Inspect claims and test alg:none / signature stripping safely
  python3 jwt_tool.py "<BUYER_A_JWT>" -M at
  ```

### Step 7.2: OAuth / SSO Testing
During "Continue with Google / Apple" login:
1. Intercept `/oauth/authorize` in Burp.
2. Test `redirect_uri` validation:
   ```text
   https://www.compass.com.evil.com/callback
   https://www.compass.com@evil.com/callback
   https://www.compass.com/callback/../../logout?next=https://evil.com
   ```
3. Test **Login CSRF**: Drop the `state` parameter—if the callback still succeeds, an attacker could bind their OAuth account to a victim's Compass account.

### Step 7.3: Password Reset Flow
- Intercept `POST` to the forgot-password endpoint and test:
  - `X-Forwarded-Host: evil.com` (Password Reset Poisoning).
  - HTTP Parameter Pollution: `email=buyerA@wearehackerone.com&email=buyerB@wearehackerone.com`.

---

## 8. Phase 5: Server-Side & Injection Testing (Manual & Safe)

### Step 8.1: Manual SQL Injection (Non-Search Endpoints)
Test JSON fields, `sort=`, `order=`, and filter parameters on REST/GraphQL endpoints **manually** in Burp Repeater:
```sql
'
"
' AND 1=1-- -
' AND 1=2-- -
(CASE WHEN (1=1) THEN id ELSE created_at END)
```
- Look for `500 Internal Server Error`, stack traces, or boolean response differences. Never use automated `sqlmap` on search or high-volume endpoints.

### Step 8.2: SSRF (Image Import, Webhooks, PDF/Share Previews)
1. Start an OOB listener:
   ```bash
   interactsh-client
   ```
2. Wherever Compass accepts an external URL (avatar URL, link preview, document/PDF export), submit `http://<your-id>.oast.fun`.
3. If you receive a callback, test if internal/metadata IPs are reachable using safe bypasses (`http://[::ffff:127.0.0.1]/`, `http://2130706433/`, `http://localtest.me/`, or a `302` redirect).

### Step 8.3: SSTI & Path Traversal
- **SSTI**: Test custom names, collection titles, or export templates with `{{7*7}}` and `${7*7}` (look for `49` in exported PDFs or emails).
- **Path Traversal**: Test any `?file=`, `?path=`, or `?template=` parameter with `../../../../etc/hostname` and `..%2f..%2f..%2fetc%2fhostname`.

---

## 9. Phase 6: Client-Side & Modern Browser Attacks

### Step 9.1: Context-Aware XSS
Test every user-controlled string that renders back in the browser (Buyer A's display name, collection title, saved search name, URL parameters):
1. Inject canary `xss991"'><` and inspect the DOM in Firefox DevTools.
2. Pick the matching payload:
   - HTML body: `<img src=x onerror=alert(document.domain)>`
   - Attribute: `" autofocus onfocus=alert(document.domain) x="`
   - JS string: `';alert(document.domain);//`
   - Link/Markdown: `javascript:alert(document.domain)`

### Step 9.2: CORS Misconfigurations
On authenticated API endpoints (e.g., `/api/v1/me` or user preferences), send:
```http
Origin: https://evil.com
```
Also test `Origin: https://compass.com.evil.com`, `Origin: https://attackercompass.com`, and `Origin: null`. If the response returns `Access-Control-Allow-Origin: https://evil.com` **and** `Access-Control-Allow-Credentials: true`, you can read authenticated user data cross-origin.

### Step 9.3: Modern Client-Side Checks
- **`postMessage` DOM-XSS**: Search downloaded JS files (`js/downloaded/`) for `addEventListener("message"`. Check if `event.origin` is strictly validated before `event.data` is used.
- **Client-Side Path Traversal (CSPT)**: Check if frontend `fetch()` calls concatenate URL params directly without `encodeURIComponent()`.
- **Prototype Pollution**: Test `?__proto__[polluted]=1` in URLs and check `Object.prototype.polluted` in Firefox Console.

---

## 10. Phase 7: APIs, GraphQL, File Uploads, Races & Cache

### Step 10.1: GraphQL Testing
If Compass exposes a `/graphql` endpoint:
1. Check if introspection is enabled: `{"query":"{__schema{types{name,fields{name}}}}"}`.
2. If disabled, test field suggestions (`{"query":"{ user { pass } }"}`) to map hidden fields.
3. Test **object-level authorization** on every query/mutation (can Buyer A query Buyer B's private node ID?).

### Step 10.2: File Uploads (Profile / Document Uploads)
- Test uploading an `.svg` containing `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`—check if it renders inline on `compass.com` (Stored XSS) rather than forcing `Content-Disposition: attachment` on a sandboxed domain.
- Test path traversal in `filename="../test.txt"` during multipart upload.

### Step 10.3: Race Conditions (Burp Single-Packet Attack)
Test one-time actions (invites, likes/saves, promo/referral redemptions, or token generation) by grouping 15–20 identical requests in Burp Repeater and clicking **Send group in parallel (single-packet attack)**.

### Step 10.4: Cache Poisoning (With Cache-Buster Only!)
Always append a unique query parameter (`?cb=918273`) so you **never** affect real Compass users:
```http
GET /?cb=918273 HTTP/1.1
Host: www.compass.com
X-Forwarded-Host: evil.com
```

---

## 11. Phase 8: Verification, Impact & Compass Report Template

### Before Clicking "Submit"
1. **Verify against Exclusions**: Confirm it is *not* `personIDs`, Agent public PII, expected Collections permissions, Squarespace/Wix, or a search-box automation finding.
2. **Confirm Header & Clean PoC**: Include the `X-Bug-Bounty: HackerOne-<username>` header you used and provide exact `curl` / HTTP steps between Buyer A and Buyer B.
3. **Patience on Triage**: Compass peer-reviews Medium/Low weekly (and High/Critical immediately).

### Compass-Ready Report Template
````markdown
## Title
[Vulnerability Type] on [Endpoint] allows [Consumer/Unauthenticated] user to [Impact]

## Summary
A brief 2–3 sentence summary of the root cause, affected Compass endpoint, and security impact.

## Severity
CVSS v3.1: [Score] ([Vector])

## Test Accounts & Header Used
- Buyer A: `<username>+buyerA@wearehackerone.com`
- Buyer B: `<username>+buyerB@wearehackerone.com`
- Custom Header: `X-Bug-Bounty: HackerOne-<username>`

## Steps to Reproduce
1. Authenticate as **Buyer B** and create/access `[private resource]`.
2. Authenticate as **Buyer A** and send the following request:
   ```http
   GET /api/v1/example/<BUYER_B_RESOURCE_ID> HTTP/1.1
   Host: www.compass.com
   X-Bug-Bounty: HackerOne-<username>
   Cookie: <BUYER_A_SESSION>
   ```
3. Observe HTTP `200 OK` returning Buyer B's private data.

## Proof of Concept (PoC)
Attach redacted screenshot / `curl` command.

## Impact
Explain the realistic business impact (e.g., any Buyer/Seller account can read or modify another user's private data).

## Remediation
Enforce server-side ownership checks (`resource.owner_id == current_user.id`) before returning or modifying the resource.
````
