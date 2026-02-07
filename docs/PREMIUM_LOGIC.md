# Premium Logic: The 4-Stage Shield System

**The Janitor v3.0 Enterprise Heuristics**

This document explains the architecture behind The Janitor's dead code detection, focusing on the Premium Tier heuristics that justify the $49 price point.

---

## Philosophy: Architectural Empathy

**The Problem with Traditional Tools:**
Other dead code detectors are "fancy grep" - they match method names globally without understanding context. They produce false positives (delete vital code) and false negatives (keep dead code).

**The Janitor's Approach:**
We understand **framework lifecycles** and **implicit dependencies**. Code that looks unused may be critical for deployment, metaprogramming, or framework callbacks.

---

## The 4-Stage Shield System

Every symbol passes through 4 sequential shields before being marked as dead. If protected by ANY shield, the symbol is saved.

```
Symbol → Stage 0 → Stage 1 → Stage 2 → Stage 3 → Stage 4 → DEAD
           ↓         ↓         ↓         ↓         ↓
        Protected Protected Protected Protected Protected
```

---

## Stage 0: Contextual Immortality (Directory Shield)

**Question**: Is the symbol in a protected directory?

**Protected Directories**:
- `tests/` - Test files are never deleted
- `examples/` - Example code is documentation
- `docs/` - Documentation code is intentional
- `scripts/` - Utility scripts are entry points
- `benchmarks/` - Performance test code
- `tutorial/` - Educational code

**Rationale**: Code in these directories serves a purpose beyond production runtime. Even if unused elsewhere, it has value.

**Example**:
```python
# tests/test_utils.py
def test_helper_function():  # Never marked dead, even if unused elsewhere
    pass
```

---

## Stage 1: Cross-File References

**Question**: Is the symbol imported or called by another file?

**Detection**:
- Import statements: `from module import symbol`
- Direct calls: `module.function()`
- Class instantiation: `obj = ClassName()`

**Universal Scalpel Mode**: Precise cross-module linking
- Resolves relative imports (`.module`, `..module`)
- Multi-line import parsing (parenthesized imports)
- Tracks target file paths for each import

**Example**:
```python
# utils.py
def process_data():  # Used in main.py → PROTECTED
    pass

# main.py
from utils import process_data  # Stage 1 protection
process_data()
```

**Constructor Shield** (Sub-stage 1.1):
When a class is instantiated, ALL dunder methods are automatically protected:
```python
# models.py
class User:
    def __init__(self):  # Protected by Constructor Shield
        pass
    def __repr__(self):  # Protected by Constructor Shield
        return "User"

# main.py
user = User()  # Triggers Constructor Shield for ALL User dunders
```

---

## Stage 2: Framework/Meta Immortality (Wisdom Registry)

**Question**: Does the symbol match a known framework pattern?

**Community Rules** (Free Tier):
- Python: `if __name__ == "__main__"`, `setUp`, `tearDown`
- Flask: `@app.route`, `before_request`, `after_request`
- Django: `save`, `delete` on Model subclasses
- FastAPI: `@app.get`, `lifespan`
- pytest: `test_*` functions

**Premium Rules** (v3.0):
- Type Hint Analysis (FastAPI/Pydantic)
- String-to-Symbol Resolution (Celery)
- Qt Magic Naming (`on_*_*` auto-connection)
- SQLAlchemy Metaprogramming (`@declared_attr`, `__abstract__`)
- Inheritance Context (ORM-aware lifecycle methods)

### Sub-stage 2.1: Library Mode Shield
In `--library` mode, ALL public symbols (not starting with `_`) are protected:
```python
# mylib.py
def public_api():  # Protected in library mode
    pass

def _internal_helper():  # Can be deleted even in library mode
    pass
```

### Sub-stage 2.2: Package Export Shield
Symbols exported via `__init__.py` are part of the public API:
```python
# mylib/__init__.py
from .module import PublicClass  # PublicClass protected

# mylib/module.py
class PublicClass:  # Protected by Package Export Shield
    pass
```

---

### ⭐ Stage 2.7: Config File References (PREMIUM - PRIORITY ONE)

**Infrastructure-as-Code Awareness**

**Question**: Is the symbol referenced in YAML/JSON config files?

Modern applications aren't just code - they're distributed systems defined across multiple languages. The Janitor scans:

#### AWS Lambda / Serverless Framework
```yaml
# serverless.yml
functions:
  upload:
    handler: handlers.image_upload.upload_image
```
→ `upload_image` function is **[Premium] Config Reference: Lambda Handler**

#### AWS SAM
```yaml
# template.yaml
Resources:
  UploadFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.lambda_handler
```
→ `lambda_handler` function is **[Premium] Config Reference: SAM Handler**

#### Django Settings
```python
# settings.py
INSTALLED_APPS = [
    'myapp.users',  # 'users' module protected
    'myapp.orders',  # 'orders' module protected
]

MIDDLEWARE = [
    'middleware.auth.AuthMiddleware',  # AuthMiddleware class protected
]
```
→ All referenced modules/classes are **[Premium] Config Reference: Django INSTALLED_APPS**

#### Docker Compose
```yaml
# docker-compose.yml
services:
  worker:
    command: python -m celery.worker  # worker module protected
  api:
    command: python manage.py runserver  # manage module protected
```
→ All command references are **[Premium] Config Reference: Docker command**

#### Airflow DAGs
```python
# dags/pipeline.py
task1 = PythonOperator(
    task_id='process_data',
    python_callable=process_data  # process_data function protected
)
```
→ All `python_callable` references are **[Premium] Config Reference: Airflow python_callable**

**Value Proposition**: Prevents catastrophic deletion of serverless handlers, Django apps, and infrastructure code that looks unused but is vital for deployment.

---

### ⭐ Stage 2.8: Metaprogramming Danger Shield (PREMIUM - PRIORITY TWO)

**Dynamic Execution Detection**

**Question**: Does the file use metaprogramming patterns that make static analysis impossible?

**Detected Patterns**:
- `getattr(obj, method_name)` - Dynamic attribute access
- `setattr(obj, attr, value)` - Dynamic attribute setting
- `eval(expression)` - String code execution
- `exec(code)` - Dynamic code execution
- `importlib.import_module(name)` - Dynamic imports
- `__import__(name)` - Dynamic imports
- `type(name, bases, dict)` - Dynamic class creation
- `.__dict__` - Direct dict manipulation

**Protection Strategy**: When ANY of these patterns are detected, **ALL symbols in that file** are protected.

**Example**:
```python
# dynamic_handler.py
class DynamicHandler:
    def process_csv(self):  # Protected
        return "CSV"

    def process_json(self):  # Protected
        return "JSON"

    def handle(self, data_type):
        # This pattern makes static analysis impossible
        method_name = f"process_{data_type}"
        method = getattr(self, method_name)  # Dynamic call
        return method()
```

→ File detected as: **[Premium] Metaprogramming Danger (getattr/eval/exec detected)**
→ **ALL methods** in this file are protected, even if they appear unused.

**Rationale**: Conservative but necessary. Static analysis cannot trace dynamic execution paths. Better to keep potentially dead code than break production.

---

## Stage 3: Lifecycle Methods (Dunder Methods)

**Question**: Is this a dunder method of a used class?

**Constructor Shield**: When a class is instantiated anywhere, ALL its dunder methods are protected:
- `__init__`, `__new__` (creation)
- `__str__`, `__repr__` (string representation)
- `__eq__`, `__hash__` (comparison)
- `__iter__`, `__next__` (iteration)
- `__enter__`, `__exit__` (context manager)
- `__call__` (callable objects)
- `__getattr__`, `__setattr__` (attribute access)
- All other dunder methods

**Example**:
```python
# models.py
class Product:
    def __init__(self, name):  # Protected by Constructor Shield
        self.name = name

    def __repr__(self):  # Protected by Constructor Shield
        return f"Product({self.name})"

    def __eq__(self, other):  # Protected by Constructor Shield
        return self.name == other.name

# main.py
p = Product("Widget")  # Instantiation triggers Constructor Shield
```

---

## Stage 4: Entry Point Detection

**Question**: Is this a known entry point?

**Entry Point Patterns**:
- `if __name__ == "__main__"` blocks
- `main()` function in root directory
- FastAPI app creation: `app = FastAPI()`
- Flask app creation: `app = Flask(__name__)`
- Django settings: `DJANGO_SETTINGS_MODULE`

**Example**:
```python
# main.py
def main():  # Entry point → PROTECTED
    run_application()

if __name__ == "__main__":
    main()
```

---

## ⭐ Premium Heuristics (Stage 2+)

These advanced checks run alongside Stage 2 (Framework/Meta Immortality).

### Enterprise Edge Case 1: Type Hint Analysis (FastAPI/Pydantic)

**Problem**: Dependency injection functions look unused because they're only referenced in type hints.

**Detection**:
```python
from typing import Annotated
from fastapi import Depends

def get_database():  # Appears unused → FALSE POSITIVE
    return Database()

def get_user(db: Annotated[Database, Depends(get_database)]):
    # get_database is ONLY referenced in the type hint!
    return db.query_user()
```

**Protection**: Scan `Annotated[Type, Depends(...)]` patterns and extract callable names.

→ `get_database` is **[Premium Protection] Rule: Meta**

---

### Enterprise Edge Case 2: String-to-Symbol Resolution (Celery/Django)

**Problem**: Tasks referenced by string names in workflows look unused.

**Detection**:
```python
# tasks.py
def process_video():  # Appears unused → FALSE POSITIVE
    return "Processing..."

# workflows.py
from celery import signature
task = signature('process_video')  # String reference!
```

**Protection**: Scan `signature('name')`, `s('name')`, `si('name')` and protect matching functions.

→ `process_video` is **[Premium] String Reference**

---

### Enterprise Edge Case 3: Qt Auto-Connection Slots

**Problem**: Qt auto-connects slots by naming convention, no explicit connection in code.

**Detection**:
```python
class MainWindow(QMainWindow):
    def on_button_clicked(self):  # Appears unused → FALSE POSITIVE
        print("Button clicked")  # Auto-connected by Qt runtime!
```

**Pattern**: `on_<widget>_<signal>` in Qt widget subclasses.

→ **[Premium] Qt Auto-Connection Slot**

---

### Enterprise Edge Case 4: SQLAlchemy Metaprogramming

**Problem**: Declarative ORM uses decorators and class variables that look unused.

**Detection**:
```python
class User(Base):
    __abstract__ = True  # Appears unused → FALSE POSITIVE

    @declared_attr
    def __tablename__(cls):  # Appears unused → FALSE POSITIVE
        return cls.__name__.lower()

    @hybrid_property
    def full_name(self):  # Appears unused → FALSE POSITIVE
        return f"{self.first} {self.last}"
```

**Protection**: Detect `@declared_attr`, `@hybrid_property`, `__abstract__`, `__tablename__`.

→ **[Premium] SQLAlchemy Metaprogramming**

---

### Enterprise Edge Case 5: Inheritance Context (ORM-Aware)

**Problem**: Generic method names like `save()` are common but only special in ORM contexts.

**Detection**:
```python
class Model(Base):  # Inherits from ORM base
    def save(self):  # PROTECTED - ORM lifecycle
        db.commit()

class RandomClass:  # No ORM inheritance
    def save(self):  # NOT protected - not an ORM
        with open('file.txt', 'w') as f:
            f.write("data")
```

**Protection**: Only protect `save`, `delete`, `update`, `create` if class inherits from ORM bases (`Model`, `Base`, `db.Model`).

→ Model.save: **[Premium] ORM Lifecycle Method**
→ RandomClass.save: NOT protected (correctly marked as dead if unused)

---

### ⭐ Pydantic v2: Alias Generator (v3.0)

**Problem**: Fields with alias_generator look unused because JSON uses camelCase while Python uses snake_case.

**Detection**:
```python
from pydantic import BaseModel, ConfigDict

class UserModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel)

    user_name: str  # Accessed as "userName" in JSON - looks unused!
    email_address: str  # Accessed as "emailAddress" - looks unused!
```

**Protection**: Detect `ConfigDict(alias_generator=...)` and protect ALL fields in that model.

→ **[Premium] Pydantic v2 Alias Generator**

---

### ⭐ FastAPI: Dependency Overrides (v3.0)

**Problem**: Test dependency overrides look unused.

**Detection**:
```python
def override_db():  # Appears unused → FALSE POSITIVE
    return MockDatabase()

app.dependency_overrides[get_real_db] = override_db  # Assignment to dict!
```

**Protection**: Detect `app.dependency_overrides[...] = function_name`.

→ **[Premium] FastAPI Dependency Override**

---

### ⭐ pytest: Fixture Detection (v3.0)

**Problem**: Fixtures are called implicitly by pytest, not directly by test code.

**Detection**:
```python
@pytest.fixture
def database_connection():  # Appears unused → FALSE POSITIVE
    return setup_db()

def test_query(database_connection):  # Fixture injected by pytest!
    assert database_connection.query(...)
```

**Protection**: Detect `@pytest.fixture` decorator and conftest.py patterns.

→ **[Premium] pytest Fixture**

---

## Stage 5: Grep Shield (Optional, Slow)

**Question**: Does the symbol name appear as a string anywhere else?

**Enabled with**: `--grep-shield` flag

**WARNING**: Slow on large codebases (3000+ files).

**Use Case**: Final safety net for dynamic usage patterns not covered by other shields.

**Example**:
```python
# registry.py
def process_payment():  # No direct calls, but...
    pass

# dispatcher.py
task_name = user_input  # "process_payment"
globals()[task_name]()  # Dynamic execution via string!
```

→ Grep shield detects "process_payment" string and protects the function.

---

## Shield Priority and Composition

**All shields run in parallel** within their stage. A symbol is protected if **ANY** shield activates.

**Example with multiple protections**:
```python
# models.py
class User(Base):  # Inherits from ORM
    def save(self):  # Multiple protections!
        db.commit()

# Main application
user = User()  # Stage 1: Cross-file reference
user.save()     # Stage 2.5: Inheritance Context (ORM Lifecycle)
                # Stage 2: Framework/Meta (Django/SQLAlchemy rules)
```

The symbol is protected by MULTIPLE shields. Output shows the first match.

---

## Performance Optimizations

### Lazy Analysis
**Problem**: Analyzing 1000+ files in tests/ is wasteful.

**Solution**: Skip symbol extraction for immortal directories.
```
Phase 2: Extracted 371 symbols (skipped 1204 immortal files) [OK]
```

### Graph Filtering at Source
**Problem**: Vendored code (.tox, node_modules) pollutes the dependency graph.

**Solution**: Filter vendored directories before building graph.
```python
excluded_dirs = {
    '.tox', 'node_modules', 'site-packages', 'vendor',
    '.venv', '__pycache__', 'dist', 'build'
}
```

**Impact**: FastAPI analysis went from 3h 38min → 10 seconds (99.95% faster).

### Grep Shield Cache
**Problem**: Re-reading 3000+ files for each symbol is slow.

**Solution**: Build cache once, reuse for all symbols.
```python
grep_cache = self._build_grep_shield_cache()  # Read all files once
```

---

## Comparison with Other Tools

| Feature | Vulture | Deadcode | The Janitor v3.0 |
|---------|---------|----------|-------------------|
| **Lexical Matching** | ✅ | ✅ | ✅ |
| **Cross-File Imports** | ✅ | ✅ | ✅ |
| **Framework Patterns** | ❌ | ❌ | ✅ |
| **Config File Parsing** | ❌ | ❌ | ✅ Premium |
| **Metaprogramming Detection** | ❌ | ❌ | ✅ Premium |
| **Inheritance-Aware** | ❌ | ❌ | ✅ Premium |
| **Type Hint Analysis** | ❌ | ❌ | ✅ Premium |
| **String-to-Symbol** | ❌ | ❌ | ✅ Premium |

**The Janitor's Advantage**: Understands **implicit dependencies** that other tools miss.

---

## Value Proposition: Why $49?

**Free Tier (Community Rules)**: 30+ framework patterns, basic lifecycle detection.

**Premium Tier ($49)**:
1. **Config File Parsing** - AWS, Django, Docker, Airflow
2. **Metaprogramming Danger Shield** - Conservative safety for dynamic code
3. **Advanced Heuristics** - Pydantic v2, FastAPI, pytest, Qt, SQLAlchemy
4. **Inheritance Context** - ORM-aware method protection
5. **Type Hint Analysis** - FastAPI Depends() patterns

**ROI**: One false positive deletion in production costs >$1000 in developer time + downtime. Premium Tier pays for itself immediately.

---

## Future Enhancements (v3.1+)

1. **Caching** - Repeat audits under 2 seconds
2. **TypeScript Config Parsing** - package.json, tsconfig.json
3. **Next.js/Nuxt Auto-Routing** - Page-based routing protection
4. **GraphQL Resolver Detection** - Schema-to-code mapping
5. **Prisma ORM** - Schema file references

---

## Architecture Summary

```
Input: Codebase
  ↓
Phase 1: Graph Building (Dependency Map)
  ↓
Phase 2: Symbol Extraction (AST Parsing)
  ↓
Phase 3: Reference Linking (Cross-File Analysis)
  ↓
Phase 4: Shield System (4-Stage Protection)
  ├─ Stage 0: Directory Shield
  ├─ Stage 1: Cross-File References + Constructor Shield
  ├─ Stage 2: Framework/Meta + Library Mode + Package Exports
  │   ├─ 2.7: Config File References (PREMIUM)
  │   └─ 2.8: Metaprogramming Danger (PREMIUM)
  ├─ Stage 3: Lifecycle Methods (Dunder)
  ├─ Stage 4: Entry Points
  └─ Stage 5: Grep Shield (Optional)
  ↓
Output: Dead Symbols + Protected Symbols
```

**Design Principle**: **Conservative by default**. Better to keep potentially dead code than risk breaking production.

---

For troubleshooting, see **TROUBLESHOOTING.md**.
For usage examples, see **README.md**.
