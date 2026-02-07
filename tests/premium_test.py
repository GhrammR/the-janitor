"""Premium Tier Test File - Enterprise Edge Cases.

This file tests the 8+ enterprise-grade reference tracking patterns:
1. Type Hint Analysis (FastAPI/Pydantic)
2. String-to-Symbol Resolution (Celery/Django)
3. Magic Naming (PySide/Qt)
4. Metaprogramming (SQLAlchemy)
5. Inheritance Context (ORM awareness)
6. Pydantic v2 Alias Generator (v3.0)
7. FastAPI Dependency Overrides (v3.0)
8. pytest Fixture Detection (v3.0)
9. Metaprogramming Danger Shield (v3.0)

EXPECTED BEHAVIOR: None of these symbols should appear in Dead Symbols list.
"""

from typing import Annotated
from dataclasses import dataclass


# =============================================================================
# EDGE CASE 1: Type Hint Analysis (FastAPI/Pydantic)
# =============================================================================

def get_current_user():
    """Dependency injection function - referenced only in type hints."""
    return {"username": "test_user"}


def get_database_session():
    """Database session provider - referenced only in Depends()."""
    return "db_session"


def get_token_header():
    """Token validation - referenced in Security()."""
    return "Bearer token"


# FastAPI endpoint using dependency injection
def read_items(
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[str, Depends(get_database_session)],
    token: Annotated[str, Security(get_token_header)]
):
    """This endpoint uses dependencies that appear unused without deep analysis."""
    return {"user": user, "db": db, "token": token}


# =============================================================================
# EDGE CASE 2: String-to-Symbol Resolution (Celery/Django)
# =============================================================================

def process_video_task():
    """Celery task referenced by string signature."""
    return "Processing video..."


def send_email_notification():
    """Celery task referenced in workflow chains."""
    return "Email sent"


def calculate_analytics():
    """Task used in Celery canvas primitives."""
    return "Analytics calculated"


# Celery workflow using string-based task references
def create_workflow():
    """Workflow that references tasks by string names."""
    # These look like dead code to simple static analysis
    task1 = signature('process_video_task')
    task2 = s('send_email_notification')
    task3 = si('calculate_analytics')
    return [task1, task2, task3]


# Django model lookup by string
def get_user_model_dynamically():
    """Django pattern for dynamic model access."""
    UserModel = get_model('auth.User')
    return UserModel


# =============================================================================
# EDGE CASE 3: Magic Naming (PySide/Qt)
# =============================================================================

class QMainWindow:
    """Mock Qt base class for testing."""
    pass


class MainWindow(QMainWindow):
    """Qt application main window with auto-connected slots."""

    def on_button_clicked(self):
        """Auto-connected slot - no static references but called by Qt runtime."""
        print("Button was clicked")

    def on_slider_valueChanged(self):
        """Auto-connected to slider's valueChanged signal."""
        print("Slider value changed")

    def on_menu_action_triggered(self):
        """Auto-connected to menu action."""
        print("Menu action triggered")


# =============================================================================
# EDGE CASE 4: Metaprogramming (SQLAlchemy)
# =============================================================================

class BaseMixin:
    """SQLAlchemy mixin with metaprogramming."""

    __abstract__ = True  # This looks unused but is essential for SQLAlchemy

    @declared_attr
    def created_at(cls):
        """Dynamically generated column - appears unused."""
        return "Column(DateTime)"

    @hybrid_property
    def display_name(self):
        """Hybrid property - SQL and Python expression."""
        return f"{self.first_name} {self.last_name}"


class User(BaseMixin):
    """User model inheriting from mixin."""

    __tablename__ = 'users'  # Looks unused but required by SQLAlchemy

    def __init__(self):
        self.first_name = "John"
        self.last_name = "Doe"


# =============================================================================
# EDGE CASE 5: Inheritance Context (ORM Lifecycle Methods)
# =============================================================================

class Base:
    """Mock ORM Base class."""
    pass


class Model(Base):
    """ORM Model with context-aware lifecycle methods."""

    def save(self):
        """ORM save method - should be protected because class inherits from Base."""
        print("Saving to database...")

    def delete(self):
        """ORM delete method - protected by inheritance context."""
        print("Deleting from database...")

    def update(self):
        """ORM update method - protected."""
        print("Updating database...")


class RandomUtilityClass:
    """Not an ORM model - lifecycle methods should NOT be protected."""

    def save(self):
        """This 'save' is NOT protected - class doesn't inherit from Base."""
        print("Saving to file...")

    def delete(self):
        """This 'delete' is NOT protected - not an ORM method."""
        print("Deleting file...")


# =============================================================================
# EDGE CASE 6: Pydantic v2 Alias Generator (v3.0 - PRIORITY THREE)
# =============================================================================

class BaseModel:
    """Mock Pydantic BaseModel."""
    pass


class ConfigDict:
    """Mock Pydantic ConfigDict."""
    def __init__(self, alias_generator=None):
        self.alias_generator = alias_generator


def to_camel(string: str) -> str:
    """Mock camelCase converter."""
    return string


class UserProfileModel(BaseModel):
    """Pydantic model with alias_generator.

    Fields look unused because JSON uses camelCase but Python uses snake_case.
    """
    model_config = ConfigDict(alias_generator=to_camel)

    # These fields appear unused but are accessed via camelCase aliases
    user_name: str = "john_doe"  # Accessed as "userName" in JSON
    email_address: str = "john@example.com"  # Accessed as "emailAddress"
    phone_number: str = "555-0100"  # Accessed as "phoneNumber"
    is_active: bool = True  # Accessed as "isActive"


# =============================================================================
# EDGE CASE 7: FastAPI Dependency Overrides (v3.0 - PRIORITY THREE)
# =============================================================================

class FastAPIApp:
    """Mock FastAPI app."""
    def __init__(self):
        self.dependency_overrides = {}


app = FastAPIApp()


def get_real_database():
    """Production database connection."""
    return "postgres://prod-db"


def override_get_database():
    """Test database override - appears unused but assigned to dependency_overrides."""
    return "sqlite:///:memory:"


def mock_external_api():
    """Mock external API for testing - appears unused."""
    return {"status": "mocked"}


# Testing pattern: Override dependencies
app.dependency_overrides[get_real_database] = override_get_database
app.dependency_overrides["external_api"] = mock_external_api


# =============================================================================
# EDGE CASE 8: pytest Fixture Detection (v3.0 - PRIORITY THREE)
# =============================================================================

def pytest_fixture(func):
    """Mock pytest.fixture decorator."""
    return func


@pytest_fixture
def database_connection():
    """pytest fixture - appears unused but called implicitly by test framework."""
    return "db_connection_object"


@pytest_fixture
def mock_api_client():
    """API client fixture - used by test functions via dependency injection."""
    return "mock_api_client"


@pytest_fixture
def sample_user_data():
    """Test data fixture - appears unused."""
    return {"username": "test", "email": "test@example.com"}


def test_user_creation(database_connection, sample_user_data):
    """Test function using fixtures - fixtures appear unused without pytest awareness."""
    assert database_connection is not None
    assert sample_user_data["username"] == "test"


# =============================================================================
# EDGE CASE 9: Metaprogramming Danger Shield (v3.0 - PRIORITY TWO)
# =============================================================================

class DynamicHandler:
    """Class using metaprogramming - ALL methods should be protected."""

    def process_csv(self):
        """Method called dynamically via getattr."""
        return "CSV processed"

    def process_json(self):
        """Method called dynamically via getattr."""
        return "JSON processed"

    def process_xml(self):
        """Method called dynamically via getattr."""
        return "XML processed"

    def handle_request(self, data_type: str):
        """Uses getattr to call methods dynamically."""
        # This pattern makes static analysis impossible
        method_name = f"process_{data_type}"
        method = getattr(self, method_name)
        return method()


def dynamic_import_example(module_name: str):
    """Uses importlib for dynamic imports - ALL symbols here are protected."""
    import importlib
    module = importlib.import_module(module_name)
    return module


def eval_example(expression: str):
    """Uses eval - dangerous metaprogramming, ALL symbols protected."""
    result = eval(expression)
    return result


# =============================================================================
# Mock Functions for Type Hints (to avoid import errors)
# =============================================================================

def Depends(dependency):
    """Mock FastAPI Depends."""
    return dependency


def Security(dependency):
    """Mock FastAPI Security."""
    return dependency


def signature(task_name):
    """Mock Celery signature."""
    return f"Task: {task_name}"


def s(task_name):
    """Mock Celery signature shorthand."""
    return f"Task: {task_name}"


def si(task_name):
    """Mock Celery signature immutable."""
    return f"Task: {task_name}"


def get_model(model_path):
    """Mock Django get_model."""
    return f"Model: {model_path}"


def declared_attr(func):
    """Mock SQLAlchemy declared_attr decorator."""
    return func


def hybrid_property(func):
    """Mock SQLAlchemy hybrid_property decorator."""
    return func


# =============================================================================
# VERIFICATION SUMMARY
# =============================================================================

"""
Expected Protection Results:

EDGE CASE 1 (Type Hint Analysis):
- get_current_user: Protected (referenced in Annotated[..., Depends(...)])
- get_database_session: Protected (referenced in Depends())
- get_token_header: Protected (referenced in Security())

EDGE CASE 2 (String-to-Symbol Resolution):
- process_video_task: Protected (string reference in signature('process_video_task'))
- send_email_notification: Protected (string reference in s('send_email_notification'))
- calculate_analytics: Protected (string reference in si('calculate_analytics'))

EDGE CASE 3 (Qt Auto-Connection):
- on_button_clicked: Protected (Qt auto-connection slot pattern)
- on_slider_valueChanged: Protected (Qt auto-connection slot pattern)
- on_menu_action_triggered: Protected (Qt auto-connection slot pattern)

EDGE CASE 4 (SQLAlchemy Metaprogramming):
- __abstract__: Protected (SQLAlchemy class variable)
- created_at: Protected (@declared_attr decorator)
- display_name: Protected (@hybrid_property decorator)
- __tablename__: Protected (SQLAlchemy class variable)

EDGE CASE 5 (Inheritance Context):
- Model.save: Protected (inherits from Base)
- Model.delete: Protected (inherits from Base)
- Model.update: Protected (inherits from Base)
- RandomUtilityClass.save: NOT protected (no ORM inheritance)
- RandomUtilityClass.delete: NOT protected (no ORM inheritance)

EDGE CASE 6 (Pydantic v2 Alias Generator - v3.0):
- user_name: Protected (Pydantic field with alias_generator)
- email_address: Protected (Pydantic field with alias_generator)
- phone_number: Protected (Pydantic field with alias_generator)
- is_active: Protected (Pydantic field with alias_generator)

EDGE CASE 7 (FastAPI Dependency Overrides - v3.0):
- override_get_database: Protected (assigned to app.dependency_overrides)
- mock_external_api: Protected (assigned to app.dependency_overrides)

EDGE CASE 8 (pytest Fixtures - v3.0):
- database_connection: Protected (@pytest_fixture decorator)
- mock_api_client: Protected (@pytest_fixture decorator)
- sample_user_data: Protected (@pytest_fixture decorator)

EDGE CASE 9 (Metaprogramming Danger Shield - v3.0):
- DynamicHandler.process_csv: Protected (file uses getattr)
- DynamicHandler.process_json: Protected (file uses getattr)
- DynamicHandler.process_xml: Protected (file uses getattr)
- DynamicHandler.handle_request: Protected (file uses getattr)
- dynamic_import_example: Protected (uses importlib)
- eval_example: Protected (uses eval)

TOTAL PROTECTED: 37 enterprise patterns (v3.0)
TOTAL DEAD: 2 (RandomUtilityClass methods - correctly identified)

v3.0 ADDITIONS: +19 new protected patterns
- Pydantic v2 alias_generator: 4 patterns
- FastAPI dependency_overrides: 2 patterns
- pytest fixtures: 3 patterns
- Metaprogramming danger: 10 patterns (entire file protected)
"""
