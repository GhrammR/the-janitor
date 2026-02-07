# Architecture: The 4-Stage Shield

The Janitor uses a **compiler-grade, multi-layered defense system** to achieve near-zero false positives in dead code detection.

## Overview: How The Janitor Works

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: AST Extraction                                     │
│ Parse Python/JS/TS files into Abstract Syntax Trees        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Symbol Definition                                  │
│ Extract all functions, classes, variables, exports         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Reference Tracking                                 │
│ Build a dependency graph of who-calls-who                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Immortality Shield                                 │
│ Protect framework methods, metaprogramming, config refs     │
└─────────────────────────────────────────────────────────────┘
                              ↓
                      Dead Code Report
```

## Stage 1: AST Extraction

The Janitor uses **tree-sitter** parsers to convert source code into Abstract Syntax Trees (ASTs). This provides:

- **Language-agnostic parsing**: Same infrastructure for Python, JavaScript, TypeScript
- **Error-tolerant parsing**: Can analyze incomplete or invalid syntax
- **Fast performance**: Written in C, optimized for speed

### Supported Languages

- **Python**: Full support for 3.11+ (including match statements, type hints)
- **JavaScript**: ES2023 support (including import.meta, top-level await)
- **TypeScript**: Full support (including generics, decorators, namespaces)

## Stage 2: Symbol Definition

The **Extractor** module walks the AST and catalogs every symbol in your codebase:

### Python Symbols
- Functions (`def`, `async def`)
- Classes and methods
- Module-level variables
- Imports (absolute, relative, aliased)

### JavaScript/TypeScript Symbols
- Named exports (`export function`, `export const`)
- Default exports (`export default`)
- Class declarations
- Arrow functions assigned to variables

### Key Innovation: Type-Aware Tracking

The Janitor maintains a **Variable Type Registry** to resolve indirect method calls:

```python
# The Janitor tracks that 'app' is a Flask instance
app = Flask(__name__)

# Later, it knows this is Flask.route()
@app.route('/api')
def handle_request():
    pass  # Protected: Flask route handler
```

## Stage 3: Reference Tracking

The **Reference Tracker** builds a directed graph of dependencies using a **three-phase resolution strategy**:

### Phase 1: Cross-Module References
Detects imports and resolves them to actual file paths:

```python
# File: api/routes.py
from .handlers import process_payment  # Resolved to api/handlers.py
```

### Phase 2: Class-Context Resolution
Understands method calls within class hierarchies:

```python
class UserManager(BaseManager):
    def create_user(self):
        self.validate()  # Resolved to BaseManager.validate()
```

### Phase 3: Name Matching
Fallback heuristic for dynamic or metaprogramming patterns:

```python
# If type inference fails, name matching protects
getattr(obj, 'dynamic_method')()  # 'dynamic_method' protected
```

## Stage 4: Immortality Shield

The **final defense layer** that prevents false positives through framework-specific heuristics.

### 🛡️ Shield 1: Inheritance Tracking

Automatically protects framework lifecycle methods:

=== "Django"
    ```python
    class User(models.Model):
        def save(self):  # Protected: Django ORM lifecycle
            super().save()
    ```

=== "unittest"
    ```python
    class TestAPI(unittest.TestCase):
        def setUp(self):  # Protected: unittest lifecycle
            pass
    ```

=== "FastAPI"
    ```python
    @app.on_event("startup")
    async def startup():  # Protected: FastAPI event handler
        pass
    ```

### 🛡️ Shield 2: Wisdom Registry

**100+ framework patterns** cataloged from production codebases:

#### Python Frameworks
- **Pydantic v2**: Alias generator fields, validators, root models
- **pytest**: Fixtures, auto-use fixtures, parametrize
- **SQLAlchemy**: Declared attributes, polymorphic discriminators
- **Django**: Signal receivers, admin actions, middleware
- **FastAPI**: Dependency overrides, background tasks

#### JavaScript/TypeScript Frameworks
- **React**: Hooks dependencies (`useEffect`, `useCallback`, `useMemo`)
- **Express**: Route middleware, error handlers
- **Next.js**: API routes, getServerSideProps, middleware
- **Vue**: Lifecycle hooks, watchers, computed properties

### 🛡️ Shield 3: Metaprogramming Detection

Files using dynamic execution are **fully protected**:

```python
# This file uses getattr - all symbols protected
method_name = "process_" + data_type
getattr(handler, method_name)()  # Could call ANY method
```

**Triggers:**
- `getattr()`, `setattr()`, `hasattr()`, `delattr()`
- `eval()`, `exec()`, `compile()`
- `importlib.import_module()`, `__import__()`
- Dynamic class creation with `type()`

### 🛡️ Shield 4: Configuration Parsing

**Cross-language reference protection** for infrastructure-as-code:

=== "AWS Lambda"
    ```yaml
    # serverless.yml
    functions:
      processImage:
        handler: handlers.process_image  # handlers.py protected
    ```

=== "Docker Compose"
    ```yaml
    # docker-compose.yml
    services:
      worker:
        command: python -m myapp.worker  # myapp/worker.py protected
    ```

=== "package.json"
    ```json
    {
      "scripts": {
        "start": "node server.js"  // server.js protected
      },
      "bin": {
        "my-cli": "./bin/cli.js"   // cli.js protected
      }
    }
    ```

## Performance: TURBO Engine

The Janitor v3.0+ includes **SQLite-based caching** for instant repeat audits:

| Run Type | FastAPI Codebase | Performance |
|----------|------------------|-------------|
| **Cold Run** | ~50 seconds | Full AST extraction |
| **TURBO Run** | **~1 second** | 100% cache hit ✅ |
| **Partial Change** | ~6 seconds | Only re-analyze changed files |

### Cache Invalidation Strategy

- **Dirty-bit detection**: Uses `mtime + size` for O(1) cache checks
- **Smart re-analysis**: Only processes files that changed
- **Clear cache**: `janitor audit . --clear-cache` for fresh start

## Export Logic: Application-Aware Tree Shaking

**JavaScript/TypeScript export analysis** adapts to your project type:

### Library Mode (`--library`)
**Protects ALL exports** (you're building a public API):

- Axios: 0 false positives ✅
- React: 0 false positives ✅
- Express: 0 false positives ✅

### Application Mode (default)
**Detects unused named exports** (internal code):

- lodash: 15 dead exports detected ✅
- `export default` always protected (your entry point)

## Architectural Principles

1. **Conservative by Default**: When in doubt, protect the symbol
2. **Layered Defense**: Multiple heuristics must agree before flagging as dead
3. **Type-Aware**: Use compiler techniques, not text matching
4. **Framework-First**: Framework patterns are first-class citizens
5. **Fast Feedback**: Sub-second cached audits for iterative development

## Next Steps

- [Learn about safety mechanisms](safety.md)
- [Explore Premium features](premium.md)
- [View GitHub repository](https://github.com/GhrammR/the-janitor)
