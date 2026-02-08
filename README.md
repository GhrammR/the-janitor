# 🧹 The Janitor: Stop the Slop. Start the Engineering.

[![Release: v3.9.1](https://img.shields.io/badge/release-v3.9.1-blue.svg)](https://github.com/GhrammR/the-janitor/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker: Ready](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/thejanitor/janitor)

---

## 🚫 The Problem: AI Slop

We are drowning in **AI-generated code bloat**. LLMs hallucinate dependencies, duplicate logic, and generate functions that are never called. Every coding session leaves behind:

- **Orphaned imports**
- **Dead classes**
- **Zombie test fixtures**
- **Duplicate logic**

The best developers measure success in **Negative Net Lines of Code**. Every line deleted is one less bug, one less security vulnerability, and one less cognitive burden.

**The Janitor makes negative LOC your default.**

---

## 💰 ROI: The Business Case for Negative LOC

**Break-even point: 0.5 developer hours.** After that, you're printing money.

At **$100/hr**, preventing a single production hotfix yields an immediate **800% ROI**. Here's why:

| Scenario | Cost Without Janitor | Cost With Janitor | Savings |
|----------|---------------------|-------------------|---------|
| **Production Hotfix** | $800 (8 hours debugging dead imports) | $100 (1 hour automated cleanup) | **$700** |
| **Onboarding Delay** | $400 (4 hours navigating zombie code) | $50 (30 min clean codebase) | **$350** |
| **Security Audit** | $1,200 (12 hours auditing unused attack surface) | $200 (2 hours validated by Janitor) | **$1,000** |

**Every unused function is:**
- **1 more attack vector** for security vulnerabilities
- **1 more file** slowing down your IDE's autocomplete
- **1 more cognitive burden** for new developers
- **1 more import** breaking when you upgrade dependencies

The Janitor eliminates this tax **before** it compounds.

---

## 🔬 Why The Janitor Beats a Linter

**Traditional linters (Ruff, Knip, ESLint) merely identify mess. The Janitor executes surgical deletions with a transactional sandbox guarantee.**

| Feature | Traditional Linters | The Janitor |
|---------|-------------------|-------------|
| **Analysis Depth** | Text patterns | AST + type inference |
| **Action** | Report warnings | **Execute deletions** |
| **Safety** | None | Sandbox + auto-rollback |
| **Framework Support** | Generic rules | 100+ framework patterns |
| **False Positives** | High | Near-zero |

Linters tell you there's a problem. **The Janitor solves it.**

---

## ⚙️ The Three Pillars

### 🔬 The Anatomist: Multi-Language AST Dependency Mapping
- **Tree-sitter parsers** for Python, JavaScript, TypeScript
- **Type-aware tracking** with Variable Type Registry
- **Cross-module resolution** with compiler-grade import analysis
- **Inheritance mapping** for framework lifecycle protection

### 🧠 The Brain: Safe-Proxy Deduplication (v3.8+)
- **Vector embeddings** detect semantic duplicates (not just syntax)
- **Safe Proxy Pattern** preserves function signatures (zero breaking changes)
- **AST validation** rejects invalid LLM suggestions before they reach your code
- **Wrapper functions** extract shared logic without touching call sites

### ⚔️ The Reaper: Sandbox-Verified Cleanup
- **Backup first**: Files staged in `.janitor_trash` before modification
- **AST-based surgery**: Surgical removal (not regex replacement)
- **Test verification**: Your test suite runs in an isolated sandbox
- **100% auto-rollback**: If tests fail, changes are instantly reverted

---

![The Janitor in Action](https://raw.githubusercontent.com/GhrammR/the-janitor/main/docs/assets/demo.gif)

---

## ⚡ Key Features

### 🌐 Polyglot Intelligence
One tool for your entire stack. The Janitor understands the semantics of your code, not just text matching.
- **Python**: Flask, Django, FastAPI, Pytest (Pydantic forward refs, async teardown, SQLAlchemy polymorphism)
- **JavaScript/TypeScript** (v3.4.0): React hooks, Express routes, **application-aware tree shaking** for JS/TS
  - **Library mode** (`--library`): Protects ALL exports (Axios: 0 false positives)
  - **App mode** (default): Detects unused named exports (lodash: 15 dead exports found)

### ⚡ TURBO Engine: Sub-Second Cached Audits (v3.0)
**Instant repeat audits. Work at the speed of thought.**

The Janitor v3.0 includes a **TURBO engine** with SQLite-based caching that delivers **sub-1.2 second repeat audits**:
- **First run**: Full AST extraction and analysis (~50s on FastAPI)
- **TURBO run**: O(1) cached analysis (**~1.0 second** on FastAPI)
- **Smart invalidation**: Uses mtime + size for instant dirty-bit detection
- **Cached data**: Symbol definitions, metaprogramming danger, dependency graph edges, complete analysis results

```bash
# First run (builds cache)
janitor audit .
# → Phase 1-3: Full analysis (~50s)

# TURBO run (100% cache hit)
janitor audit .
# → [!] Instant analysis from cache (1.00s)

# Partial invalidation (1 file changed)
# Modified routing.py
janitor audit .
# → Phase 2-3: Partial analysis (~6s)

# Clear cache if needed
janitor cache clear .
```

**Performance Impact**:
- **TURBO cache hit**: ~1.0s (**50x faster** than cold run)
- **Partial invalidation**: ~6s (only re-analyzes changed files)
- **Perfect for CI/CD**: Pre-commit hooks now run in under 2 seconds

### 🛡️ Safety First: The Sandbox
**Delete with zero fear.**
The Janitor refuses to break your build. Every deletion is transactionally verified:
1.  **Backup**: Files are safely staged in `.janitor_trash`.
2.  **Surgery**: Dead code is surgically removed (AST-based).
3.  **Verification**: Your tests (`pytest`, `npm test`) are executed in a sandbox.
4.  **Auto-Rollback**: **If tests fail, everything is instantly restored.**

### 📚 Library Mode
Building a public package? Use `--library` to protect your public API.
The Janitor will aggressively clean internal dead code while preserving all exported symbols, `__all__` definitions, and public interfaces.

### 🧠 Semantic Deduplication
Find duplicates by **meaning**, not just syntax. The Janitor uses vector embeddings to identify logic that *does the same thing* even if it looks different, and uses an LLM to suggest a merged refactor.

### 🛡️ Safe-Proxy Deduplication (v3.7.0)
**Merge duplicates without breaking your build.**

Traditional dedup tools suggest refactors that **change function signatures**, breaking every call site in your codebase. The Janitor solves this with the **Safe Proxy Pattern**.

**The Innovation:**
When The Janitor finds duplicate functions like `add(a, b)` and `sum_vals(x, y)`, it doesn't create a single merged function with new parameters. Instead, it uses an **AI-powered Wrapper Pattern**:

```python
# Traditional tools break your code:
def merged_function(x, y, mode='add'):  # ❌ Breaks all call sites
    return x + y

# The Janitor preserves interfaces:
def _merged_logic(val1, val2):         # ✅ Internal helper
    return val1 + val2

def add(a, b):                          # ✅ Original signature preserved
    return _merged_logic(a, b)

def sum_vals(x, y):                     # ✅ Original signature preserved
    return _merged_logic(x, y)
```

**ZERO Breaking Changes:** Your existing code continues to work. All call sites remain valid. Tests pass.

**AST Validation:** Every AI-generated suggestion is validated with `ast.parse()` before being shown to you. Invalid syntax is automatically discarded. No LLM slop enters your codebase.

**Brain Safety:**
- Preserves all side effects (logging, telemetry, error handling)
- Never removes defensive `try/except` blocks
- Maintains backward compatibility by design

Run `janitor dedup .` to find structural duplicates and get safe, production-ready merge suggestions.

### 🔬 Type-Aware Reference Tracking (v2.0)
**Zero false positives.** The Janitor now includes a compiler-grade type inference engine:
- **Variable Type Registry**: Tracks `x = ClassName()` assignments to resolve indirect method calls
- **Type Narrowing**: Understands `isinstance()` checks and applies narrowed types within scope
- **Inheritance Mapping**: Auto-protects framework lifecycle methods (unittest.TestCase, Django models)
- **Cross-Module Linking**: Precise import resolution across files with multi-line import parsing

Tested on production codebases like [Black](https://github.com/psf/black) with **100% True Positive accuracy**.

---

## 💎 Premium Features (v3.0)

**Enterprise-Grade Dead Code Detection**

The Janitor v3.0 transforms from a "fancy grep" into a **semantic heuristic engine** that understands the implicit contracts of modern frameworks. These premium features are always enabled and justify production-grade confidence:

### 🌐 Configuration Parsing (Cross-Language References)
**Infrastructure-as-Code Awareness**

Modern applications aren't just Python files—they're distributed systems defined across YAML, JSON, and configuration modules. The Janitor now scans:

- **AWS Lambda/Serverless**: Handler definitions in `serverless.yml` and `template.yaml`
  ```yaml
  handler: handlers.process_image  # process_image is protected
  ```

- **Django Settings**: `INSTALLED_APPS` and `MIDDLEWARE` string references
  ```python
  INSTALLED_APPS = ['myapp.users']  # 'users' module is protected
  ```

- **Docker Compose**: Command and entrypoint specifications
  ```yaml
  command: python -m myapp.worker  # worker module is protected
  ```

- **Airflow DAGs**: Task IDs and `python_callable` references
  ```python
  PythonOperator(python_callable=process_data)  # process_data is protected
  ```

- **JavaScript/TypeScript (NEW in v3.0)**: npm scripts, bin entries, and path mappings
  ```json
  // package.json
  {
    "scripts": {
      "start": "node server.js"  // server.js is protected
    },
    "bin": {
      "my-cli": "./bin/cli.js"   // cli.js is protected
    }
  }

  // tsconfig.json
  {
    "compilerOptions": {
      "paths": {
        "@utils/*": ["src/utils/*"]  // utils module is protected
      }
    }
  }
  ```

**Value Proposition**: Prevents catastrophic deletion of code that looks unused but is vital for deployment across Python AND JavaScript/TypeScript ecosystems.

### 🛡️ Metaprogramming Safety Net
**Dynamic Execution Detection**

The Janitor detects files using metaprogramming patterns that make static analysis impossible:

- `getattr()` / `setattr()` / `hasattr()` / `delattr()`
- `eval()` / `exec()` / `compile()`
- `importlib.import_module()` / `__import__()`
- Dynamic class creation with `type()`

**When detected**: ALL symbols in these files are marked as `[Premium] Metaprogramming Danger` and protected from deletion. This conservative approach prevents breaking code that dynamically calls methods at runtime.

**Example**:
```python
# File uses getattr - everything is protected
method_name = "process_" + data_type
getattr(handler, method_name)()  # process_csv, process_json, etc.
```

### 🧬 Deep Inheritance Tracking
**Framework-Aware Lifecycle Detection**

Advanced framework heuristics that understand implicit call patterns:

#### Pydantic v2: Alias Generator Fields
```python
class UserModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel)
    user_name: str  # Protected - accessed as "userName" in JSON
```

#### FastAPI: Dependency Overrides
```python
def override_auth():
    return {"user": "test"}

app.dependency_overrides[get_current_user] = override_auth  # Protected
```

#### pytest: Fixture Detection
```python
@pytest.fixture
def db_connection():  # Protected - called implicitly by pytest
    return setup_db()
```

#### SQLAlchemy: Metaprogramming Decorators
```python
class User(Base):
    @declared_attr
    def __tablename__(cls):  # Protected - called by SQLAlchemy metaclass
        return cls.__name__.lower()
```

#### Qt: Auto-Connection Slots
```python
class MainWindow(QMainWindow):
    def on_button_clicked(self):  # Protected - auto-connected by Qt
        pass
```

**Performance**: FastAPI analysis went from **3 hours 38 minutes → 10 seconds** (99.95% faster) with these optimizations.

---

## 🚀 Installation

### Option 1: Docker (Recommended)
Guaranteed environment compatibility. No dependency hell.

```bash
# Pull the image
docker pull thejanitor/janitor:latest

# Run audit on current directory
docker run --rm -v $(pwd):/app/src thejanitor/janitor audit /app/src

# Run clean (interactive mode needed for confirmation)
docker run --rm -it -v $(pwd):/app/src thejanitor/janitor clean /app/src
```

### Option 2: Pip (Local)
Requires Python 3.11+.

```bash
# Install globally
pip install the-janitor

# Verify installation
janitor --help
```

---

## 📖 Usage

### 1. Audit Your Codebase
Scan for dead files and symbols without making changes.

```bash
janitor audit .
```

### 2. Deep Clean Symbols
Remove unused functions and classes from within files.

```bash
# Standard clean
janitor clean --mode symbols .

# Library mode (Protects public structure)
janitor clean --mode symbols --library .

# Force cleanup without confirmation (CI/CD)
janitor clean --mode symbols --yes .
```

### 3. Clean Everything (Files & Symbols)
The full negative-LOC experience.

```bash
janitor clean --mode both .
```

### 4. Find Duplicates
Identify copy-pasted logic.

```bash
janitor dedup . --threshold 0.9
```

### 5. Cache Management
Manage the analysis cache for performance optimization.

```bash
# Clear cache (forces full re-analysis on next run)
janitor cache clear .

# View cache statistics
janitor cache stats .
```

**When to clear cache:**
- After major refactoring
- When switching between branches
- If audit results seem stale

**Performance:** The TURBO cache delivers sub-second repeat audits. Clear only when needed.

---

## 🛠️ Configuration

Create a `.env` file for advanced configuration (AI-powered deduplication):

```bash
JANITOR_AI_KEY=your_api_key_here
JANITOR_MODEL=your_preferred_model  # Optional
```

---

## 📜 Licensing: Open Core Model

The Janitor uses an **Open Core** licensing model to protect our intellectual property while keeping the analysis engine accessible:

### MIT Licensed (Open Source)
**The Engine** — All code in `src/` is MIT licensed. You can:
- Fork and modify the codebase engine
- Use it commercially without restrictions
- Contribute improvements back to the community

### Proprietary (Commercial)
**The Wisdom Registry** — Pattern databases in `rules/` are proprietary:
- **Community Rules** (`rules/community/`): Free tier with 30+ essential framework patterns (MIT licensed)
- **Premium Wisdom Pack** (`rules/premium/`): Enterprise-grade pattern library covering:
  - Advanced framework lifecycle detection (Django ORM, SQLAlchemy, React hooks)
  - Cloud-native patterns (AWS Lambda, Azure Functions, GCP triggers)
  - Enterprise JavaScript frameworks (Next.js, Nuxt, SvelteKit)
  - Database ORM magic methods
  - Microservice patterns (gRPC, message queues)

The engine runs perfectly with Community Rules. Premium rules make the immortality detection more intelligent for complex, production codebases.

**Want Premium?** Contact: [sales@thejanitor.app](mailto:sales@thejanitor.app)

---

## 🤝 Contributing

Contributions to the **engine** (`src/`) are welcome! We accept:
- Bug fixes
- Performance improvements
- New language support (Go, Rust, Java)
- Better AST manipulation

Please ensure all tests pass before submitting a PR.

**Contributions to Wisdom Rules** are proprietary. If you'd like to submit new framework patterns, contact us for licensing arrangements.

---

## 📄 License

- **Engine**: MIT License (see `LICENSE`)
- **Wisdom Registry**: Proprietary (see `rules/premium/README.md`)
