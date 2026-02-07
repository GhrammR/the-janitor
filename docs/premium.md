# Premium Features: Enterprise-Grade Intelligence

The Janitor Premium unlocks **100+ framework-specific heuristics** that transform the tool from "smart linter" into a **production-grade semantic analyzer**.

## What's Included

### Community Edition (Free)
- ✅ Core dead code detection (Python, JavaScript, TypeScript)
- ✅ Basic framework support (30+ patterns)
- ✅ TURBO caching engine
- ✅ Sandbox + auto-rollback safety
- ✅ Configuration file parsing (basic)

### Premium Edition ($49/year)
- ✅ **All Community features**
- ✅ **70+ additional enterprise framework patterns**
- ✅ **Advanced metaprogramming detection**
- ✅ **Cloud-native infrastructure support** (AWS, Azure, GCP)
- ✅ **Priority support** (24-hour response time)
- ✅ **Future updates** (new framework patterns added monthly)

---

## Premium Wisdom Packs

The **Wisdom Registry** is a curated database of framework patterns extracted from production codebases. Premium unlocks enterprise-grade patterns that justify your investment.

### 🐍 Python Enterprise Frameworks

#### Pydantic v2
**Why it matters**: Pydantic is the de facto validation library for FastAPI, LangChain, and data pipelines. Its metaprogramming patterns are invisible to traditional tools.

**Protected Patterns:**

=== "Alias Generators"
    ```python
    from pydantic import BaseModel, ConfigDict
    from pydantic.alias_generators import to_camel

    class UserModel(BaseModel):
        model_config = ConfigDict(alias_generator=to_camel)
        user_name: str  # ✅ Protected: accessed as "userName" in JSON
        first_name: str  # ✅ Protected: accessed as "firstName"
    ```

=== "Validators"
    ```python
    class User(BaseModel):
        email: str

        @field_validator('email')
        def validate_email(cls, v):  # ✅ Protected: called implicitly
            if '@' not in v:
                raise ValueError('Invalid email')
            return v
    ```

=== "Root Validators"
    ```python
    class Config(BaseModel):
        @model_validator(mode='before')
        def check_passwords(cls, values):  # ✅ Protected: called before init
            return values
    ```

**ROI**: Prevents false positives on validation logic that looks unused but is critical to data integrity.

---

#### FastAPI
**Why it matters**: FastAPI's dependency injection and event handlers are dynamically invoked. Without Premium, these are flagged as dead code.

**Protected Patterns:**

=== "Dependency Overrides"
    ```python
    def get_db():
        return database

    def override_db():
        return mock_database  # ✅ Protected: used in tests

    app.dependency_overrides[get_db] = override_db
    ```

=== "Background Tasks"
    ```python
    @app.post("/send-email")
    async def send_email(background_tasks: BackgroundTasks):
        background_tasks.add_task(send_notification)  # ✅ send_notification protected
    ```

=== "Lifespan Events"
    ```python
    @app.on_event("startup")
    async def startup():  # ✅ Protected: called by FastAPI runtime
        await init_database()
    ```

**ROI**: Prevents deletion of async background tasks and startup hooks that are critical to application bootstrapping.

---

#### SQLAlchemy
**Why it matters**: SQLAlchemy uses metaclass magic and declarative attributes that are invisible to static analysis.

**Protected Patterns:**

=== "Declared Attributes"
    ```python
    class User(Base):
        @declared_attr
        def __tablename__(cls):  # ✅ Protected: called by metaclass
            return cls.__name__.lower()
    ```

=== "Polymorphic Discriminators"
    ```python
    class Employee(Base):
        __mapper_args__ = {
            'polymorphic_on': type,  # ✅ 'type' column protected
            'polymorphic_identity': 'employee'
        }
    ```

=== "Hybrid Properties"
    ```python
    class Product(Base):
        @hybrid_property
        def total_price(self):  # ✅ Protected: accessed like an attribute
            return self.price * self.quantity
    ```

**ROI**: Prevents deletion of ORM lifecycle methods that cause production database errors.

---

#### Django
**Why it matters**: Django's signal system, admin actions, and middleware use string-based registration. Premium tracks these implicit references.

**Protected Patterns:**

=== "Signal Receivers"
    ```python
    @receiver(post_save, sender=User)
    def create_profile(sender, instance, created, **kwargs):  # ✅ Protected
        if created:
            Profile.objects.create(user=instance)
    ```

=== "Admin Actions"
    ```python
    @admin.action(description='Mark as published')
    def make_published(modeladmin, request, queryset):  # ✅ Protected
        queryset.update(status='published')
    ```

=== "Custom Middleware"
    ```python
    # settings.py
    MIDDLEWARE = [
        'myapp.middleware.RequestLoggingMiddleware',  # ✅ Protected
    ]

    # middleware.py
    class RequestLoggingMiddleware:  # ✅ Protected via settings.py
        def __init__(self, get_response):
            self.get_response = get_response
    ```

**ROI**: Prevents deletion of signal handlers that are critical to data consistency (e.g., creating user profiles on registration).

---

#### pytest
**Why it matters**: pytest fixtures are invoked by name, not by explicit calls. Premium understands fixture dependencies.

**Protected Patterns:**

=== "Auto-Use Fixtures"
    ```python
    @pytest.fixture(autouse=True)
    def setup_database():  # ✅ Protected: runs before every test
        db.create_all()
        yield
        db.drop_all()
    ```

=== "Parametrize"
    ```python
    @pytest.mark.parametrize('input,expected', [
        (1, 2),
        (2, 4),
    ])
    def test_double(input, expected):  # ✅ Protected: parametrize creates tests
        assert double(input) == expected
    ```

=== "Fixture Dependencies"
    ```python
    @pytest.fixture
    def user(db):  # ✅ Protected: 'db' fixture dependency tracked
        return User.create(name='test')
    ```

**ROI**: Prevents deletion of fixtures that break test suites (cryptic "fixture not found" errors).

---

### ☁️ Cloud-Native Infrastructure

#### AWS Lambda
**Why it matters**: Lambda handlers are registered in YAML/JSON files. Premium parses CloudFormation and Serverless Framework configs.

**Protected Patterns:**

=== "Serverless Framework"
    ```yaml
    # serverless.yml
    functions:
      processImage:
        handler: handlers.process_image  # ✅ handlers.py::process_image protected
        events:
          - s3:
              bucket: uploads
    ```

=== "CloudFormation (SAM)"
    ```yaml
    # template.yaml
    Resources:
      ImageProcessor:
        Type: AWS::Serverless::Function
        Properties:
          Handler: app.lambda_handler  # ✅ app.py::lambda_handler protected
    ```

**ROI**: Prevents deletion of Lambda handlers that cause silent production failures (no HTTP 500, just missing functionality).

---

#### Docker Compose
**Why it matters**: Service entrypoints are defined in YAML, not Python imports.

**Protected Patterns:**

```yaml
# docker-compose.yml
services:
  worker:
    command: python -m myapp.worker  # ✅ myapp/worker.py protected
  api:
    command: uvicorn app:app  # ✅ app.py protected
```

**ROI**: Prevents deletion of background workers that cause production data processing to stop.

---

#### Airflow
**Why it matters**: DAGs use `python_callable` string references that are invisible to import analysis.

**Protected Patterns:**

```python
from airflow import DAG
from airflow.operators.python import PythonOperator

def process_data():  # ✅ Protected: referenced by name in PythonOperator
    return load_data()

dag = DAG('data_pipeline')
task = PythonOperator(
    task_id='process',
    python_callable=process_data  # String reference tracked
)
```

**ROI**: Prevents deletion of DAG tasks that break production data pipelines.

---

### 🌐 JavaScript/TypeScript Enterprise

#### Next.js
**Why it matters**: Next.js uses file-based routing and special export names. Premium understands the framework conventions.

**Protected Patterns:**

=== "API Routes"
    ```typescript
    // pages/api/users.ts
    export default function handler(req, res) {  // ✅ Protected: file-based routing
      res.json({ users: [] })
    }
    ```

=== "Server-Side Props"
    ```typescript
    export async function getServerSideProps(context) {  // ✅ Protected: Next.js convention
      return { props: {} }
    }
    ```

=== "Middleware"
    ```typescript
    // middleware.ts
    export function middleware(request) {  // ✅ Protected: Next.js middleware
      return NextResponse.redirect('/login')
    }
    ```

**ROI**: Prevents deletion of API routes and SSR functions that cause 404 errors in production.

---

#### React Hooks
**Why it matters**: Hook dependencies (`useEffect`, `useCallback`) are tracked by name, not by explicit calls.

**Protected Patterns:**

```typescript
import { useEffect, useCallback } from 'react'

function Component() {
  const fetchData = useCallback(async () => {  // ✅ Protected: used in useEffect
    return await api.get('/data')
  }, [])

  useEffect(() => {
    fetchData()  // ✅ Premium tracks this dependency
  }, [fetchData])
}
```

**ROI**: Prevents deletion of callback functions that cause infinite re-render loops.

---

#### Express Middleware
**Why it matters**: Middleware functions are registered by reference, not by import path.

**Protected Patterns:**

```typescript
const express = require('express')
const app = express()

function requestLogger(req, res, next) {  // ✅ Protected: used in app.use()
  console.log(req.method, req.url)
  next()
}

app.use(requestLogger)  // String reference tracked
```

**ROI**: Prevents deletion of middleware that breaks authentication or logging.

---

## Advanced Metaprogramming Detection

Premium detects **second-order metaprogramming** patterns that Community misses:

### Nested Getattr Chains
```python
class DynamicHandler:
    def handle(self, action):
        method = getattr(self, f'handle_{action}')  # ✅ All handle_* methods protected
        return method()

    def handle_create(self):  # ✅ Protected
        pass

    def handle_update(self):  # ✅ Protected
        pass
```

### Decorator Factories
```python
def register(name):
    def decorator(func):  # ✅ Protected: metaprogramming decorator
        REGISTRY[name] = func
        return func
    return decorator

@register('process')
def process_data():  # ✅ Protected: registered dynamically
    pass
```

### Dynamic Imports
```python
import importlib

module_name = f"{base_package}.{plugin_name}"
module = importlib.import_module(module_name)  # ✅ All modules in base_package/ protected
```

---

## Configuration File Coverage

Premium parses **12+ config file formats** to detect cross-language references:

| Format | Use Case | Example |
|--------|----------|---------|
| **serverless.yml** | AWS Lambda | `handler: functions.process` |
| **template.yaml** | AWS SAM | `Handler: app.lambda_handler` |
| **docker-compose.yml** | Container orchestration | `command: python worker.py` |
| **package.json** | npm scripts | `"start": "node server.js"` |
| **tsconfig.json** | TypeScript paths | `"@utils/*": ["src/utils/*"]` |
| **.github/workflows/*.yml** | GitHub Actions | `run: python scripts/deploy.py` |
| **pyproject.toml** | Python packaging | `[tool.poetry.scripts]` |
| **Dockerfile** | Container images | `ENTRYPOINT ["python", "app.py"]` |

---

## The $49 ROI Calculation

**Break-even: 30 minutes of developer time.**

At $100/hr, Premium pays for itself if it prevents:

- **1 production hotfix** ($800 debugging) → **$751 saved** ✅
- **1 false positive** (2 hours fixing broken tests) → **$151 saved** ✅
- **1 deleted Lambda handler** (4 hours debugging silent failures) → **$351 saved** ✅

**Annual savings: $10,000+** for a team of 5 developers.

---

## How to Upgrade

### Purchase Premium

**Contact**: [sales@thejanitor.app](mailto:sales@thejanitor.app)

**Pricing**:
- Individual: $49/year
- Team (5-10 devs): $199/year
- Enterprise (unlimited): Contact sales

### Activate Premium

```bash
# Install Premium Wisdom Packs
janitor install-premium --license-key YOUR_KEY

# Verify activation
janitor --version
# Output: The Janitor v3.8.0 (Premium Edition ✅)
```

---

## Premium Support

**Included with Premium:**

- 📧 **Priority email support** (24-hour response time)
- 💬 **Private Slack channel** (for Enterprise customers)
- 🔄 **Monthly pattern updates** (new frameworks added regularly)
- 📚 **Custom pattern development** (Enterprise tier)

---

## Next Steps

- [Learn about architecture](architecture.md)
- [Explore safety mechanisms](safety.md)
- [Contact sales](mailto:sales@thejanitor.app)
