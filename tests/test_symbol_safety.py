"""Integration test for symbol safety - verifying Constructor Shield.

CRITICAL: This test verifies that dunder methods (__init__, __new__, __call__, etc.)
are NEVER marked as dead symbols when their parent class is used.
"""
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from analyzer.parser import LanguageParser
from analyzer.extractor import EntityExtractor
from analyzer.reference_tracker import ReferenceTracker


def test_constructor_shield_basic():
    """Test that __init__ is protected when class is instantiated."""
    code = b"""
class MyClass:
    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value

# Use the class
obj = MyClass(42)
print(obj.get_value())
"""

    # Parse and extract
    parser = LanguageParser('python')
    tree = parser.parse_source(code)
    extractor = EntityExtractor('python')
    entities = extractor.extract_entities(tree, code, 'test.py')

    # Track references
    tracker = ReferenceTracker(Path('.'))
    for entity in entities:
        tracker.add_definition(entity)
    tracker.extract_references_from_file(Path('test.py'), tree, code)

    # Find dead symbols
    dead_symbols = tracker.find_dead_symbols()
    dead_names = {symbol.qualified_name for symbol in dead_symbols}

    # CRITICAL ASSERTION: __init__ must NOT be in dead symbols
    assert 'MyClass.__init__' not in dead_names, \
        f"CONSTRUCTOR SHIELD FAILURE: MyClass.__init__ marked as dead! Dead symbols: {dead_names}"

    # get_value should also be protected (it's called)
    assert 'MyClass.get_value' not in dead_names, \
        f"MyClass.get_value should not be dead (it's called)"

    print("[PASS] Constructor Shield: __init__ is IMMORTAL when class is used")


def test_constructor_shield_unused_method():
    """Test that unused methods ARE marked dead while __init__ is protected."""
    code = b"""
class MyClass:
    def __init__(self, value):
        self.value = value

    def used_method(self):
        return self.value

    def unused_method(self):
        return "never called"

# Use the class
obj = MyClass(42)
print(obj.used_method())
"""

    # Parse and extract
    parser = LanguageParser('python')
    tree = parser.parse_source(code)
    extractor = EntityExtractor('python')
    entities = extractor.extract_entities(tree, code, 'test.py')

    # Track references
    tracker = ReferenceTracker(Path('.'))
    for entity in entities:
        tracker.add_definition(entity)
    tracker.extract_references_from_file(Path('test.py'), tree, code)

    # Find dead symbols
    dead_symbols = tracker.find_dead_symbols()
    dead_names = {symbol.qualified_name for symbol in dead_symbols}

    # CRITICAL: __init__ must be protected
    assert 'MyClass.__init__' not in dead_names, \
        f"CONSTRUCTOR SHIELD FAILURE: __init__ marked as dead!"

    # used_method should be protected
    assert 'MyClass.used_method' not in dead_names, \
        f"used_method should not be dead"

    # unused_method SHOULD be dead
    assert 'MyClass.unused_method' in dead_names, \
        f"unused_method should be marked as dead"

    print("[PASS] Constructor Shield: Only unused methods are marked dead, not __init__")


def test_qualified_names():
    """Test that qualified names prevent confusion between different classes."""
    code = b"""
class ClassA:
    def __init__(self):
        self.a = 1

    def method(self):
        return self.a

class ClassB:
    def __init__(self):
        self.b = 2

    def method(self):
        return self.b

# Only use ClassA
obj = ClassA()
print(obj.method())
"""

    # Parse and extract
    parser = LanguageParser('python')
    tree = parser.parse_source(code)
    extractor = EntityExtractor('python')
    entities = extractor.extract_entities(tree, code, 'test.py')

    # Verify qualified names are generated
    qualified_names = {entity.qualified_name for entity in entities}
    assert 'ClassA.__init__' in qualified_names, "Missing qualified name for ClassA.__init__"
    assert 'ClassB.__init__' in qualified_names, "Missing qualified name for ClassB.__init__"
    assert 'ClassA.method' in qualified_names, "Missing qualified name for ClassA.method"
    assert 'ClassB.method' in qualified_names, "Missing qualified name for ClassB.method"

    # Track references
    tracker = ReferenceTracker(Path('.'))
    for entity in entities:
        tracker.add_definition(entity)
    tracker.extract_references_from_file(Path('test.py'), tree, code)

    # Find dead symbols
    dead_symbols = tracker.find_dead_symbols()
    dead_names = {symbol.qualified_name for symbol in dead_symbols}

    # ClassA and its methods should be protected
    assert 'ClassA.__init__' not in dead_names, "ClassA.__init__ should not be dead"
    assert 'ClassA.method' not in dead_names, "ClassA.method should not be dead"

    # ClassB and its methods should be dead (not used)
    assert 'ClassB' in dead_names, "ClassB should be dead"
    assert 'ClassB.__init__' in dead_names, "ClassB.__init__ should be dead (class not used)"
    assert 'ClassB.method' in dead_names, "ClassB.method should be dead"

    print("[PASS] Qualified Names: Correctly distinguish between ClassA and ClassB methods")


def test_all_dunder_methods():
    """Test that all dunder methods are protected."""
    code = b"""
class MyClass:
    def __init__(self):
        pass

    def __str__(self):
        return "MyClass"

    def __repr__(self):
        return "MyClass()"

    def __call__(self):
        return "called"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

# Use the class
obj = MyClass()
"""

    # Parse and extract
    parser = LanguageParser('python')
    tree = parser.parse_source(code)
    extractor = EntityExtractor('python')
    entities = extractor.extract_entities(tree, code, 'test.py')

    # Track references
    tracker = ReferenceTracker(Path('.'))
    for entity in entities:
        tracker.add_definition(entity)
    tracker.extract_references_from_file(Path('test.py'), tree, code)

    # Find dead symbols
    dead_symbols = tracker.find_dead_symbols()
    dead_names = {symbol.qualified_name for symbol in dead_symbols}

    # ALL dunder methods should be protected
    dunder_methods = [
        'MyClass.__init__',
        'MyClass.__str__',
        'MyClass.__repr__',
        'MyClass.__call__',
        'MyClass.__enter__',
        'MyClass.__exit__'
    ]

    for method in dunder_methods:
        assert method not in dead_names, \
            f"CONSTRUCTOR SHIELD FAILURE: {method} marked as dead!"

    print("[PASS] Constructor Shield: ALL dunder methods are IMMORTAL")


def main():
    """Run all symbol safety tests."""
    print("\n" + "="*70)
    print("SYMBOL SAFETY INTEGRATION TESTS")
    print("="*70 + "\n")

    try:
        test_constructor_shield_basic()
        test_constructor_shield_unused_method()
        test_qualified_names()
        test_all_dunder_methods()

        print("\n" + "="*70)
        print("ALL TESTS PASSED")
        print("Constructor Shield is ACTIVE and protecting dunder methods")
        print("="*70 + "\n")
        return 0

    except AssertionError as e:
        print(f"\n{'='*70}")
        print(f"TEST FAILED")
        print(f"{'='*70}")
        print(f"\nError: {e}\n")
        return 1
    except Exception as e:
        print(f"\n{'='*70}")
        print(f"UNEXPECTED ERROR")
        print(f"{'='*70}")
        print(f"\n{e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
