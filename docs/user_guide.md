# BoundaryX User Guide

Welcome to BoundaryX! This guide walks you through the entire end-to-end workflow of conducting comprehensive authorization security assessments and multi-tenant boundary analysis using BoundaryX.

---

## 1. Project Creation & Workspace Configuration

Every authorization assessment in BoundaryX is encapsulated within a **Project Workspace**.

1. Launch BoundaryX:
   ```bash
   boundaryx
   # Or in portable mode:
   boundaryx --portable
   ```
2. Navigate to **Projects** from the sidebar and click **Create Project**.
3. Fill in the project metadata:
   - **Name**: e.g., `Acme Cloud Platform Authorization Audit`
   - **Description**: Target scope overview, test objectives, and scope constraints.
   - **Execution Settings**:
     - *Default Mode*: `Preview` (recommended for initial setup).
     - *Rate Limit (RPS)*: `5.0` requests per second.
     - *Max Concurrency*: `2-4` parallel workers.
     - *TLS Verification*: Enabled (recommended; disable only when testing local staging with self-signed certificates).
4. Click **Save Project**.

---

## 2. Defining Target Scope & Safety Boundaries

BoundaryX enforces strict scope boundaries. Requests to hosts not explicitly authorized will be denied before reaching the network.

1. Navigate to the **Scope** page.
2. Click **Add Rule** to define authorized target endpoints:
   - **Rule Type**: `Allow (In-Scope)`
   - **Hostname**: `api.target.com` (Do NOT include protocol or path here).
   - **Scheme**: `HTTPS`
   - **Port**: `443`
   - **Path Prefix**: `/api/v1` (Only endpoints starting with `/api/v1` will be tested).
   - **Excluded Paths**: Add paths that must never be touched, such as:
     - `/api/v1/auth/logout`
     - `/api/v1/admin/purge-database`
     - `/api/v1/billing/charge-credit-card`
3. Click **Add Rule** to define explicit exclusions:
   - **Rule Type**: `Exclude (Blocked)`
   - **Hostname**: `internal-vault.target.com`
4. Use the **Scope Preview** tab to test sample URLs against your rules to verify that in-scope URLs are allowed and out-of-scope URLs are blocked.

---

## 3. Modeling Identities, Roles & Authentication Profiles

To test authorization, BoundaryX models the subjects attempting to access resources.

### 3.1 Creating Identities
1. Navigate to **Identities**.
2. Click **Add Identity**:
   - **Alice**: Role `ADMIN`, Tags: `tenant-alpha`, `admin`.
   - **Bob**: Role `EDITOR`, Tags: `tenant-alpha`, `staff`.
   - **Charlie**: Role `TENANT_MEMBER`, Tags: `tenant-beta`, `external`.
   - **Anonymous**: Role `ANONYMOUS`, Tags: `unauthenticated`.

### 3.2 Creating Authentication Profiles
Credentials and tokens are decoupled from identity profiles and stored in the encrypted security vault:
1. In the **Auth Profiles** tab, click **Add Profile**.
2. Define the authentication method:
   - **Bearer Token**: Enter header name (`Authorization`) and the Bearer token string.
   - **Cookie**: Enter session cookie string (e.g., `sessionid=xyz; csrf_token=abc`).
   - **Custom Header**: Specify API key headers (e.g., `X-API-Key: secret-key-123`).
3. Link the authentication profile to the corresponding identity.

---

## 4. Multi-Tenant Partitioning & Resource Catalog

### 4.1 Defining Tenants
1. Navigate to **Tenants**.
2. Create your tenant boundaries:
   - **Tenant 1**: `Alpha Corp` (Owner: `Alice`)
   - **Tenant 2**: `Beta Ltd` (Owner: `Charlie`)
3. Assign memberships:
   - Assign `Alice` as `admin` in `Alpha Corp`.
   - Assign `Bob` as `member` in `Alpha Corp`.
   - Assign `Charlie` as `member` in `Beta Ltd`.

### 4.2 Cataloging Resources
1. Navigate to **Resources**.
2. Click **Add Resource** to register objects:
   - **Resource 1**: `Alpha Customer Orders`
     - *Type*: `ORDER`
     - *Owning Tenant*: `Alpha Corp`
     - *Sensitivity*: `CONFIDENTIAL`
     - *Associated Endpoints*: `/api/v1/orders/{id}`
   - **Resource 2**: `Alpha Tax Invoice`
     - *Type*: `INVOICE`
     - *Owning Tenant*: `Alpha Corp`
     - *Sensitivity*: `RESTRICTED`
     - *Associated Endpoints*: `/api/v1/invoices/{id}`

---

## 5. Writing Authorization Policies & Invariants

Authorization policies define what *should* happen according to the application's security model.

1. Navigate to **Policies**.
2. Click **Create Policy**:
   - **Policy Name**: `Cross-Tenant Isolation Invariant`
   - **Subject Selector**: Tenant `Beta Ltd`
   - **Resource Selector**: Tenant `Alpha Corp`
   - **Action**: `READ`
   - **Expected Decision**: `DENY`
   - **Confidence Source**: `DOCUMENTATION`
3. Click **Create Policy**:
   - **Policy Name**: `Editor Resource Modification`
   - **Subject Selector**: Role `EDITOR`, Tenant `Alpha Corp`
   - **Resource Selector**: Resource Type `ORDER`, Tenant `Alpha Corp`
   - **Action**: `WRITE`
   - **Expected Decision**: `ALLOW`
4. The **Policy Engine** automatically runs conflict detection across all policies to highlight contradictory or overlapping rules.

---

## 6. Importing Traffic Captures (HAR / Raw HTTP)

Instead of manually creating test cases from scratch, import real HTTP traffic from your proxy tools.

1. Navigate to **Traffic Explorer**.
2. Click **Import Traffic** and choose your source format:
   - **HAR 1.2 File**: Exported from Burp Suite (`Copy as HAR` or `Save HAR`), OWASP ZAP, or Browser DevTools Network tab.
   - **Raw HTTP Text**: Paste raw RFC 7230 request and response text blocks.
   - **BoundaryX JSON**: Native project exchange format.
3. BoundaryX parses the entries, checks for size limits, normalizes the URLs, and populates the traffic table.
4. Select any traffic entry to inspect request/response headers, body content, and elapsed response times.

---

## 7. Executing Tests in the Test Lab

The **Test Lab** allows you to execute authorization test matrices safely.

### Execution Modes:
- **Offline Mode**: Replays and checks policies against existing traffic records and cached evidence without sending any packets.
- **Preview Mode**: Simulates the test execution, showing resolved URLs, template parameter substitutions, and injected headers without making live network requests.
- **Active Mode**: Dispatches real HTTP requests to the target application with token-bucket rate limiting and real-time scope enforcement.

### Running a Test:
1. Navigate to **Test Lab**.
2. Click **New Test Case** or generate cases automatically from cataloged resources.
3. Configure the test case:
   - **Subject**: `Charlie King` (Beta Ltd)
   - **Target Resource**: `Alpha Customer Orders (Order #98210)`
   - **Action**: `READ`
   - **Template**: `GET https://api.target.com/api/v1/orders/{resource_id}`
   - **Expected Decision**: `DENY`
4. Select **Active Mode** and click **Run Test**.
5. BoundaryX executes the request, verifies scope, applies the authentication profile, captures the response, and compares the observed decision against expectations.
6. If the application returns `200 OK` with sensitive order data when a `DENY` was expected, BoundaryX immediately flags a **BOLA/IDOR Violation Defect**.

---

## 8. Analyzing Relationships in the Interactive Graph

1. Navigate to **Trust Graph**.
2. The interactive NetworkX graph visualizes relationships:
   - Green edges: Validated authorized access (`HAS_ACCESS`).
   - Red dashed edges: Confirmed policy violations (`VIOLATES`).
   - Blue edges: Membership and ownership (`MEMBER_OF`, `OWNS`).
3. Click any node (Identity, Tenant, or Resource) to inspect connected edges, effective permissions, and shortest path privilege escalation paths.

---

## 9. Reviewing & Triaging Findings

1. Navigate to **Findings**.
2. Review detected vulnerabilities categorized by severity:
   - **Critical**: Cross-Tenant Data Access (BOLA/IDOR) on confidential resources.
   - **High**: Broken Function Level Authorization (BFLA) on administrative endpoints.
   - **Medium**: Inconsistent permission fallback across API versions.
3. Click a finding to view:
   - **Confidence Explanation**: Detailed reasoning explaining why the finding was confirmed (e.g. HTTP 200 returned, sensitive fields present, reproducible).
   - **Reproduction Steps**: Automated step-by-step instructions.
   - **Linked Evidence**: SHA-256 verifiable HTTP exchange snapshots.
   - **Remediation Advice**: Recommended code-level fixes.
4. Triage finding status: `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, or `FIXED`.

---

## 10. Generating Audit Reports & Evidence Bundles

When your assessment is complete, generate comprehensive reports for stakeholders, auditors, and engineering teams.

1. Navigate to **Reports**.
2. Select your export format:
   - **Standalone HTML**: Self-contained, responsive offline HTML report with interactive styling, executive metrics, and collapsible evidence.
   - **Markdown (`.md`)**: Complete 14-section audit report formatted for GitHub/GitLab repositories.
   - **Structured JSON**: Machine-readable assessment data for CI/CD pipeline integration and SIEM ingestion.
   - **CSV**: Tabular vulnerability inventory for spreadsheet tracking.
3. Click **Generate Report**.
4. To export cryptographically sealed proof packages, click **Export Evidence Bundle (ZIP)**. This generates an archive containing sanitized evidence JSON files, the full assessment report, and a `manifest.json` with SHA-256 integrity digests.
