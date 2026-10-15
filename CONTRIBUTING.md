# Contributing to BoundaryX

Thank you for your interest in contributing to BoundaryX! We welcome high-quality contributions from security practitioners, software engineers, and researchers to make desktop authorization security testing rigorous, safe, and reliable.

---

## Code of Conduct

All contributors and maintainers are expected to maintain a professional, respectful, and collaborative environment. Treat fellow contributors with kindness, provide constructive code reviews, and focus on engineering excellence and security integrity.

---

## Architectural Principles & Constraints

BoundaryX is structured strictly following **Clean Layered Architecture** with distinct layer separation. When contributing code, you must respect these architectural boundaries:

```
+-----------------------------------------------------------+
|                    Presentation (UI)                      |  PySide6 Qt Pages, Dialogs,
|                                                           |  Components, Resources
+-----------------------------------------------------------+
                              |
                              v
+-----------------------------------------------------------+
|                    Application Layer                      |  Services (Scope, Projects,
|                                                           |  Test Cases, Reporting)
+-----------------------------------------------------------+
                 |                           |
                 v                           v
+---------------------------------+  +----------------------+
|          Domain Layer           |  |    Security Layer    |
|  Pure Entities, Policy Engine,  |  |  Scope, Redaction,   |
|  Pydantic Models, Trust Graph   |  |  Secrets, Audit      |
+---------------------------------+  +----------------------+
                 ^                           ^
                 |                           |
+-----------------------------------------------------------+
|                   Infrastructure Layer                    |  SQLAlchemy Database,
|                                                           |  HTTPX Client, Importers
+-----------------------------------------------------------+
```

### Layer Rules:
1. **Domain Layer (`boundaryx.domain`)**:
   - Must contain pure business logic, domain models, selectors, and policy evaluation algorithms.
   - **Constraint**: Must NEVER import from `boundaryx.infrastructure`, `boundaryx.application`, or `boundaryx.ui`.
   - Uses Pydantic 2.x for validation and immutable structures.

2. **Security Layer (`boundaryx.security`)**:
   - Encapsulates cross-cutting security primitives: `ScopeManager`, `RedactionEngine`, `SecretManager`, and `AuditLogger`.
   - Must fail safely: Any ambiguous state in scope evaluation or encryption must result in a safe denial or exception (`ScopeViolationError`, `SecurityError`).

3. **Infrastructure Layer (`boundaryx.infrastructure`)**:
   - Implements database persistence via SQLAlchemy 2.x declarative models and repositories.
   - Implements HTTP transport via HTTPX (`HttpClient`) with token bucket rate limiting and manual redirect checking.
   - Implements traffic importers (`HarImporter`, `RawHttpImporter`, `BoundaryXImporter`) and exporters (`ReportExporter`, `EvidenceExporter`, `ProjectExporter`).

4. **Application Layer (`boundaryx.application`)**:
   - Orchestrates use cases, coordinates repository persistence with domain logic, and triggers audit events.
   - Exposes clean APIs for UI consumption.

5. **Presentation Layer (`boundaryx.ui`)**:
   - Implements PySide6 (Qt) widgets, views, and dialogs.
   - **Constraint**: UI components must never execute direct SQL queries or bypass application services. Background execution must utilize `AsyncWorker` threads (`boundaryx.workers`) to keep the Qt UI event loop responsive.

---

## Coding Standards

### 1. Python & Style Guidelines
- **Python Version**: `>= 3.12` strictly. Utilize modern features (e.g., `StrEnum`, `datetime.UTC`, pattern matching, standard generic types `list[str]`, `dict[str, Any]`).
- **Formatting and Linting**: We use **Ruff** for high-performance formatting and linting.
  ```bash
  ruff check src tests scripts
  ```
- **Line Length**: Target 120 characters maximum.
- **Type Hints**: Type annotations are required on **all** public functions, methods, parameters, and return types. No untyped public APIs.
- **Docstrings**: Google or Sphinx-style docstrings are required for all public classes, methods, and functions. Explain parameters, return values, and raised exceptions.
- **No Incomplete Code**: No `TODO`, `pass`, or `NotImplementedError` stubs in critical execution paths. Code submitted in PRs must be complete and fully functional.

### 2. Error Handling & Security Invariants
- Never silently catch exceptions (`except Exception: pass` is prohibited unless explicitly justified in a localized fallback with logging).
- Do not log credentials, tokens, cookies, or encryption keys. Ensure all loggers use the `SecretFilter` infrastructure.
- Always use parameterized queries through SQLAlchemy ORM; never construct raw SQL via string formatting or concatenation.

---

## Development Setup

### 1. Clone the Repository
```bash
git clone https://github.com/boundaryx/boundaryx.git
cd boundaryx
```

### 2. Create Virtual Environment
```bash
python -m venv .venv

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# On Linux / macOS:
source .venv/bin/activate
```

### 3. Install in Editable Mode with Development Dependencies
```bash
python -m pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"
```

### 4. Verify Installation
```bash
# Verify CLI launcher
python -m boundaryx.app --version

# Seed demonstration database
python scripts/seed_demo_data.py --db dev_demo.db --clean
```

---

## Testing Guidelines

BoundaryX maintains a comprehensive automated test suite spanning unit tests, security invariant tests, and integration workflows.

### Running Tests
```bash
# Run entire test suite
pytest

# Run tests with short traceback
pytest -v --tb=short

# Run only security invariant tests
pytest tests/security/

# Run unit tests
pytest tests/unit/

# Run tests with code coverage report
pytest --cov=boundaryx --cov-report=term --cov-report=xml
```

### Writing Tests
- Place unit tests under `tests/unit/` and security boundary tests under `tests/security/`.
- Every bug fix must include a regression test reproducing the original issue and verifying the fix.
- Every new feature must include comprehensive positive and negative test cases (including boundary edge conditions, invalid inputs, and error states).
- Use temporary directories (`tmp_path` fixture) for test databases, export files, or logs to ensure tests remain isolated and side-effect free.

---

## Submitting a Pull Request

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Commit Hygiene**:
   - Write clear, concise commit messages following standard conventional commits:
     - `feat: add support for custom header authentication profiles`
     - `fix: prevent path traversal in evidence bundle export`
     - `docs: update scope configuration guide`
     - `test: add regression test for IDN punycode matching`

3. **Verify Local Quality Checks**:
   - [ ] `ruff check src tests scripts` passes with zero errors.
   - [ ] `pytest` passes with all tests green.
   - [ ] No temporary files or database artifacts are left in the tree.

4. **Open Pull Request**:
   - Provide a clear summary of changes, rationale, and testing methodology in the PR description.
   - Link related issues or security considerations.
   - Reviewers will evaluate the PR against the architecture rules, security invariants, and test coverage before merging.
