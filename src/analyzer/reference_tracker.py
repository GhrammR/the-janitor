"""Reference tracker for mapping symbol definitions to their usage across the codebase."""
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
import networkx as nx

from .extractor import Entity
from .parser import LanguageParser
from .wisdom_registry import WisdomRegistry
from .config_parser import ConfigParser
from .cache import AnalysisCache
from .heuristics import AdvancedHeuristics
from .js_heuristics import JSAdvancedHeuristics
from .resolver import SymbolResolver
from .js_import_tracker import JSImportTracker


@dataclass
class Reference:
    """A reference to a symbol in code."""
    symbol_name: str
    file_path: str
    line_number: int
    reference_type: str  # 'import', 'call', 'instantiation'


class InheritanceMap:
    """Tracks class inheritance relationships for method family protection.

    INHERITANCE MAPPER: Builds bidirectional class hierarchy graph.
    When a method is called on a base class, all subclass overrides are protected.
    """

    def __init__(self):
        """Initialize the inheritance map."""
        # class_name -> list of parent class names
        self.parents: Dict[str, List[str]] = {}
        # class_name -> list of child class names (reverse map)
        self.children: Dict[str, List[str]] = {}
        # (class_name, method_name) -> set of symbol_ids for all implementations
        self.method_families: Dict[Tuple[str, str], Set[str]] = {}

    def add_class(self, class_name: str, base_classes: List[str]):
        """Add a class and its inheritance relationships.

        Args:
            class_name: Name of the class
            base_classes: List of base class names
        """
        if base_classes:
            self.parents[class_name] = base_classes
            # Update reverse map (children)
            for base in base_classes:
                if base not in self.children:
                    self.children[base] = []
                self.children[base].append(class_name)

    def add_method(self, class_name: str, method_name: str, symbol_id: str):
        """Register a method as part of a method family.

        Args:
            class_name: Class containing the method
            method_name: Name of the method
            symbol_id: Unique symbol ID for this method
        """
        key = (class_name, method_name)
        if key not in self.method_families:
            self.method_families[key] = set()
        self.method_families[key].add(symbol_id)

    def get_method_family(self, class_name: str, method_name: str, visited: Set[str] = None) -> Set[str]:
        """Get all symbol IDs for a method across the inheritance hierarchy.

        CRITICAL: When BaseClass.method() is called, this returns symbol IDs for:
        - BaseClass.method
        - SubClass1.method (override)
        - SubClass2.method (override)
        - ... and all other overrides in the hierarchy

        Args:
            class_name: Class name to start search
            method_name: Method name to find
            visited: Set of already-visited class names (prevents infinite recursion)

        Returns:
            Set of symbol IDs for all implementations of this method in the hierarchy
        """
        if visited is None:
            visited = set()

        # Prevent infinite recursion
        if class_name in visited:
            return set()

        visited.add(class_name)
        family = set()

        # Get direct implementation
        key = (class_name, method_name)
        if key in self.method_families:
            family.update(self.method_families[key])

        # Get parent implementations (traverse up the hierarchy)
        if class_name in self.parents:
            for parent in self.parents[class_name]:
                family.update(self.get_method_family(parent, method_name, visited))

        # Get child implementations (traverse down the hierarchy)
        if class_name in self.children:
            for child in self.children[class_name]:
                family.update(self.get_method_family(child, method_name, visited))

        return family


class VariableTypeMap:
    """Tracks variable types within file scopes for type-aware reference resolution.

    TYPE INFERENCE ENGINE: Resolves indirect method calls like instance.method()
    by tracking variable assignments and type annotations.
    """

    def __init__(self):
        """Initialize the variable type map."""
        # file_path -> variable_name -> type_name
        self.types: Dict[str, Dict[str, str]] = {}
        # Stack for tracking nested scopes with isinstance narrowing
        # List of (file_path, variable_name, narrowed_type) tuples
        self.narrowed_scopes: List[Tuple[str, str, str]] = []

    def add_assignment(self, file_path: str, variable_name: str, type_name: str):
        """Record a variable assignment with inferred type.

        Examples:
            x = StringParser()  -> add_assignment(file, 'x', 'StringParser')
            y: Err = ...        -> add_assignment(file, 'y', 'Err')

        Args:
            file_path: File containing the assignment
            variable_name: Name of the variable
            type_name: Inferred type (class name)
        """
        if file_path not in self.types:
            self.types[file_path] = {}
        self.types[file_path][variable_name] = type_name

    def get_type(self, file_path: str, variable_name: str) -> str:
        """Get the type of a variable, checking narrowed scopes first.

        Args:
            file_path: File containing the variable
            variable_name: Name of the variable

        Returns:
            Type name if known, None otherwise
        """
        # Check narrowed scopes first (isinstance checks take precedence)
        for scope_file, scope_var, scope_type in reversed(self.narrowed_scopes):
            if scope_file == file_path and scope_var == variable_name:
                return scope_type

        # Check regular type map
        if file_path in self.types and variable_name in self.types[file_path]:
            return self.types[file_path][variable_name]

        return None

    def push_narrowed_scope(self, file_path: str, variable_name: str, narrowed_type: str):
        """Enter a scope where a variable's type is narrowed (e.g., isinstance check).

        Args:
            file_path: File path
            variable_name: Variable being narrowed
            narrowed_type: Narrowed type within this scope
        """
        self.narrowed_scopes.append((file_path, variable_name, narrowed_type))

    def pop_narrowed_scope(self):
        """Exit a narrowed type scope."""
        if self.narrowed_scopes:
            self.narrowed_scopes.pop()


class ReferenceTracker:
    """Tracks symbol definitions and references across the codebase."""

    # Directories that contain symbols that should ALWAYS be immortal
    IMMORTAL_DIRECTORIES = {
        'tests', 'examples', 'docs_src', 'sandbox', 'bin',
        'docs', 'requirements', 'scripts', 'tutorial', 'benchmarks'
    }

    # Framework base classes that provide lifecycle methods
    FRAMEWORK_BASES = {
        'unittest.TestCase': ['setUp', 'tearDown', 'setUpClass', 'tearDownClass', 'setUpModule', 'tearDownModule'],
        'TestCase': ['setUp', 'tearDown', 'setUpClass', 'tearDownClass'],
        'pytest.Class': [],  # pytest uses fixtures, not lifecycle methods
    }

    def __init__(self, project_root: Path, library_mode: bool = False):
        """Initialize reference tracker.

        Args:
            project_root: Root directory of the project
            library_mode: If True, treat all public symbols as immortal
        """
        self.project_root = Path(project_root)
        self.library_mode = library_mode
        self.definitions: Dict[str, Entity] = {}  # symbol_id -> Entity
        self.references: Dict[str, List[Reference]] = {}  # symbol_id -> [References]
        self.wisdom = WisdomRegistry()  # Load framework immortality rules
        self.package_exports: Set[str] = set()  # Track symbols exported via __init__.py
        self.inheritance_map = InheritanceMap()  # INHERITANCE MAPPER
        self.variable_types = VariableTypeMap()  # TYPE INFERENCE ENGINE
        self.config_parser = ConfigParser(project_root)  # PRIORITY ONE: Cross-language config parser
        self.config_references = {}  # Will be populated when parsing configs
        self.metaprogramming_dangerous_files: Set[str] = set()  # Files using dynamic execution
        self.cache = AnalysisCache(project_root)  # TASK 1: Cache for repeat audits
        self.heuristics = AdvancedHeuristics(self)  # SEMANTIC INTELLIGENCE: Advanced heuristic engine (Python)
        self.js_heuristics = JSAdvancedHeuristics(self)  # POLYGLOT: JavaScript/TypeScript semantic intelligence
        self.resolver = SymbolResolver(project_root)  # SCOPE-AWARE: Compiler-level import resolution
        self.js_import_tracker = JSImportTracker()  # JS SEMANTIC ENGINE: Alias-aware import tracking

    def _get_symbol_id(self, entity: Entity) -> str:
        """Get unique symbol ID for an entity using qualified name.

        Args:
            entity: Entity to get ID for

        Returns:
            Unique symbol ID (file_path::qualified_name)
        """
        # Use qualified name if available, otherwise fall back to name
        qualified_name = entity.qualified_name if entity.qualified_name else entity.name
        return f"{entity.file_path}::{qualified_name}"

    def add_definition(self, entity: Entity):
        """Add a symbol definition.

        INHERITANCE MAPPER: Populates inheritance map for classes and methods.

        Args:
            entity: Entity representing the definition
        """
        symbol_id = self._get_symbol_id(entity)
        self.definitions[symbol_id] = entity
        if symbol_id not in self.references:
            self.references[symbol_id] = []

        # INHERITANCE MAPPER: Register classes and methods
        if entity.type in ['class_definition', 'class_declaration']:
            # This is a class - register it with its base classes
            if entity.base_classes:
                self.inheritance_map.add_class(entity.name, entity.base_classes)
        elif entity.parent_class:
            # This is a method - register it as part of a method family
            self.inheritance_map.add_method(entity.parent_class, entity.name, symbol_id)

    def add_reference(self, symbol_name: str, file_path: str = "<heuristic>", line_number: int = 0,
                      reference_type: str = "heuristic", target_file: str = None, class_context: str = None):
        """Add a reference to a symbol.

        UNIVERSAL SCALPEL MODE: Supports cross-module imports and self/cls dispatch.
        HEURISTIC MODE: Can be called with just symbol_name for semantic analysis.

        CRITICAL: When a class is referenced (instantiated or called), ALL its dunder methods
        (__init__, __new__, __call__, etc.) are implicitly referenced via the Constructor Shield.

        Args:
            symbol_name: Name of the symbol being referenced
            file_path: File containing the reference (defaults to heuristic marker)
            line_number: Line number of the reference (defaults to 0)
            reference_type: Type of reference (import, call, instantiation, heuristic)
            target_file: For imports, the file where the symbol is defined
            class_context: For self/cls calls, the class name containing the method
        """
        reference = Reference(
            symbol_name=symbol_name,
            file_path=file_path,
            line_number=line_number,
            reference_type=reference_type
        )

        # Track if we found a matching class
        found_class = False
        found_match = False

        # PHASE 1: Try context-specific strategies first
        for symbol_id, entity in self.definitions.items():
            # STRATEGY 1: Cross-module import matching (target_file specified)
            if target_file:
                # Match by file path AND name (normalize paths for comparison)
                entity_path = Path(entity.file_path).resolve()
                target_path = Path(target_file).resolve()

                if entity_path == target_path:
                    if entity.name == symbol_name or entity.qualified_name == symbol_name:
                        if symbol_id not in self.references:
                            self.references[symbol_id] = []
                        self.references[symbol_id].append(reference)

                        # CONSTRUCTOR SHIELD
                        if entity.type in ['class_definition', 'class_declaration']:
                            found_class = True
                            self._activate_constructor_shield(entity, file_path, line_number)

                        return

            # STRATEGY 2: Self/cls method matching (class_context specified)
            elif class_context:
                # Match methods within the specified class
                if entity.parent_class == class_context and entity.name == symbol_name:
                    if symbol_id not in self.references:
                        self.references[symbol_id] = []
                    self.references[symbol_id].append(reference)

                    # INHERITANCE MAPPER: Protect entire method family
                    self._protect_method_family(class_context, symbol_name, file_path, line_number)
                    found_match = True
                    return

        # STRATEGY 3: Name Matching Fallback (for calls, heuristics)
        # When no specific context is available, match by simple name
        # This handles:
        # - Top-level function/class calls
        # - Heuristic-based references (e.g., from advanced heuristics)
        # - Any other references without import or class context
        if not found_match:
            for symbol_id, entity in self.definitions.items():
                # Skip if we're doing Strategy 1 (already handled above)
                if target_file:
                    continue

                # Match by simple name (handles top-level and qualified)
                if entity.name == symbol_name or entity.qualified_name == symbol_name:
                    if symbol_id not in self.references:
                        self.references[symbol_id] = []
                    self.references[symbol_id].append(reference)

                    # CONSTRUCTOR SHIELD: If this is a class being referenced,
                    # mark all its dunder methods as implicitly referenced
                    if entity.type in ['class_definition', 'class_declaration']:
                        found_class = True
                        self._activate_constructor_shield(entity, file_path, line_number)

                    # INHERITANCE MAPPER: If this is a method, protect entire method family
                    if entity.parent_class:
                        self._protect_method_family(entity.parent_class, entity.name, file_path, line_number)

                    return

        # If no definition found, create a placeholder entry
        placeholder_id = f"unknown::{symbol_name}"
        if placeholder_id not in self.references:
            self.references[placeholder_id] = []
        self.references[placeholder_id].append(reference)

    def _activate_constructor_shield(self, class_entity: Entity, ref_file: str, ref_line: int):
        """Activate Constructor Shield for a referenced class.

        When a class is referenced (imported, instantiated, called), all its dunder methods
        are implicitly referenced and should never be marked as dead.

        Args:
            class_entity: The class entity being referenced
            ref_file: File where the class is referenced
            ref_line: Line where the class is referenced
        """
        class_name = class_entity.name

        # Find all methods of this class
        for symbol_id, entity in self.definitions.items():
            # Check if this entity is a method of the referenced class
            if entity.parent_class == class_name:
                method_name = entity.name

                # IMMORTAL METHODS: dunder methods are implicitly called
                if self._is_dunder_method(method_name):
                    # Create an implicit reference for this dunder method
                    implicit_ref = Reference(
                        symbol_name=f"{class_name}.{method_name}",
                        file_path=ref_file,
                        line_number=ref_line,
                        reference_type='implicit_class_usage'
                    )

                    if symbol_id not in self.references:
                        self.references[symbol_id] = []
                    self.references[symbol_id].append(implicit_ref)

    def _protect_method_family(self, class_name: str, method_name: str, ref_file: str, ref_line: int):
        """Protect entire method family across the inheritance hierarchy.

        INHERITANCE MAPPER: When BaseClass.method() is called, protect:
        - BaseClass.method
        - SubClass1.method (override)
        - SubClass2.method (override)
        - ... and all overrides in parent/child classes

        Args:
            class_name: Class containing the method
            method_name: Method name
            ref_file: File where the method is referenced
            ref_line: Line where the method is referenced
        """
        # Get all symbol IDs for this method family
        family_ids = self.inheritance_map.get_method_family(class_name, method_name)

        # Add implicit reference to each method in the family
        for symbol_id in family_ids:
            implicit_ref = Reference(
                symbol_name=method_name,
                file_path=ref_file,
                line_number=ref_line,
                reference_type='inheritance_family'
            )

            if symbol_id not in self.references:
                self.references[symbol_id] = []
            self.references[symbol_id].append(implicit_ref)

    def apply_framework_lifecycle_protection(self):
        """Apply framework lifecycle protection to all classes after definitions are loaded.

        FRAMEWORK LIFECYCLE PROTECTION: Call this AFTER all definitions have been added.
        Protects lifecycle methods for classes inheriting from framework bases.
        """
        # Find all class definitions
        for symbol_id, entity in self.definitions.items():
            if entity.type in ['class_definition', 'class_declaration'] and entity.base_classes:
                # Check if this class inherits from any known framework base
                for base_class in entity.base_classes:
                    # Check both fully qualified and simple names
                    for framework_base, protected_methods in self.FRAMEWORK_BASES.items():
                        if base_class == framework_base or base_class.endswith(f'.{framework_base}'):
                            # This class inherits from a framework base
                            # Find and protect all lifecycle methods
                            class_name = entity.name

                            for method_id, method_entity in self.definitions.items():
                                if method_entity.parent_class == class_name and method_entity.name in protected_methods:
                                    # This is a framework lifecycle method - add implicit reference
                                    implicit_ref = Reference(
                                        symbol_name=method_entity.name,
                                        file_path=method_entity.file_path,
                                        line_number=method_entity.start_line,
                                        reference_type='framework_lifecycle'
                                    )

                                    if method_id not in self.references:
                                        self.references[method_id] = []
                                    self.references[method_id].append(implicit_ref)

    def mark_immortal(self, symbol_name: str, reason: str = "Advanced Heuristic"):
        """Mark a symbol as immortal (protected from deletion).

        Used by AdvancedHeuristics to protect symbols discovered via semantic analysis.

        Args:
            symbol_name: Name of the symbol to protect
            reason: Protection reason for attribution
        """
        # Find all entities matching this symbol name
        for symbol_id, entity in self.definitions.items():
            if entity.name == symbol_name or entity.qualified_name == symbol_name:
                # Set protection attribution
                if not entity.protected_by:
                    entity.protected_by = f"[Premium] {reason}"

    def _find_enclosing_class(self, node, source_code: bytes) -> str:
        """Find the name of the class enclosing a given node.

        Used to resolve self/cls method calls to their class context.

        Args:
            node: AST node to find class for
            source_code: Source code as bytes

        Returns:
            Class name if found, None otherwise
        """
        # Walk up the tree looking for a class_definition
        current = node
        while current:
            if current.type == 'class_definition':
                # Find the class name (usually second child after 'class' keyword)
                for child in current.children:
                    if child.type == 'identifier':
                        return source_code[child.start_byte:child.end_byte].decode('utf-8')
            current = current.parent if hasattr(current, 'parent') else None
        return None

    def _resolve_module_to_file(self, module_name: str, current_file: Path) -> str:
        """Resolve a module import to its actual file path.

        SCOPE-AWARE v3.5.0: Uses SymbolResolver for compiler-level import resolution.
        Previously: Hand-rolled heuristics that guessed paths.
        Now: Proves import paths using language semantics (Python relative/absolute, JS/TS aliases).

        Args:
            module_name: Module name (e.g., 'black.nodes', '.nodes', '..utils', './utils')
            current_file: Path of the file containing the import

        Returns:
            Absolute file path of the module, or None if not found (External import)
        """
        if not module_name:
            return None

        # UPGRADE v3.5.0: Delegate to SymbolResolver (compiler-level resolution)
        resolved_path = self.resolver.resolve_source_file(current_file, module_name)

        if resolved_path:
            # Convert to string (already absolute from resolver)
            return str(resolved_path)

        return None

    def _is_dunder_method(self, method_name: str) -> bool:
        """Check if a method is a dunder (double underscore) method.

        Dunder methods like __init__, __new__, __call__, etc. are special methods
        that are implicitly called by Python and should be protected.

        Args:
            method_name: Name of the method

        Returns:
            True if this is a dunder method
        """
        return (
            method_name.startswith('__') and
            method_name.endswith('__') and
            len(method_name) > 4  # More than just ____
        )

    def _extract_and_cache_references(self, file_path: Path, tree, source_code: bytes) -> List[Dict]:
        """Extract references from a file and cache them.

        PERFORMANCE ARCHITECT: Phase 3 cache - eliminates re-parsing on repeat audits.

        Args:
            file_path: Path to the file
            tree: Tree-sitter parse tree
            source_code: Source code as bytes

        Returns:
            List of serialized reference dicts
        """
        # OPTIMIZATION: Track only counts, not full copies
        refs_count_before = {symbol_id: len(refs) for symbol_id, refs in self.references.items()}

        # Extract references (normal parsing)
        self.extract_references_from_file(file_path, tree, source_code)

        # Collect new references added for this file (only new ones since extraction)
        new_references = []
        file_path_str = str(file_path)

        for symbol_id, refs in self.references.items():
            # Get the count before extraction
            old_count = refs_count_before.get(symbol_id, 0)

            # Only check new references (from old_count onward)
            for ref in refs[old_count:]:
                if ref.file_path == file_path_str:
                    new_references.append({
                        'symbol_name': ref.symbol_name,
                        'file_path': ref.file_path,
                        'line_number': ref.line_number,
                        'reference_type': ref.reference_type,
                        'symbol_id': symbol_id
                    })

        # Cache the extracted references
        self.cache.set_file_references(file_path, new_references)

        return new_references

    def _replay_cached_references(self, cached_references: List[Dict]):
        """Replay cached references without re-parsing.

        PERFORMANCE ARCHITECT: Phase 3 fast path - instant replay from cache.

        Args:
            cached_references: List of cached reference dicts
        """
        for ref_data in cached_references:
            symbol_id = ref_data['symbol_id']

            reference = Reference(
                symbol_name=ref_data['symbol_name'],
                file_path=ref_data['file_path'],
                line_number=ref_data['line_number'],
                reference_type=ref_data['reference_type']
            )

            if symbol_id not in self.references:
                self.references[symbol_id] = []

            self.references[symbol_id].append(reference)

    def extract_references_from_file(self, file_path: Path, tree, source_code: bytes):
        """Extract all references (imports, calls) from a file.

        Args:
            file_path: Path to the file
            tree: Tree-sitter parse tree
            source_code: Source code as bytes
        """
        parser = LanguageParser.from_file_extension(file_path)
        if not parser:
            return

        language = parser.language
        root_node = tree.root_node

        # Check if this is a package __init__.py file (for Package Export Shield)
        is_package_init = file_path.name == '__init__.py'

        if language == "python":
            self._extract_python_references(file_path, root_node, source_code, is_package_init)

            # === SEMANTIC INTELLIGENCE: Apply Advanced Heuristics ===
            # HEURISTIC 1: Pydantic Forward References (List['User'] -> User)
            self.heuristics.apply_pydantic_forward_ref_heuristic(root_node, source_code)

            # HEURISTIC 2: Lifespan/Teardown Detection (@asynccontextmanager post-yield)
            self.heuristics.apply_lifespan_teardown_heuristic(root_node, source_code)

            # HEURISTIC 3: Polymorphic ORM (__mapper_args__ -> immortal class)
            self.heuristics.apply_polymorphic_orm_heuristic(root_node, source_code)

        elif language in ["javascript", "typescript"]:
            self._extract_js_references(file_path, root_node, source_code)

            # === JS SEMANTIC ENGINE: Analyze imports for alias awareness ===
            # v3.6.0: Track import origins to distinguish `useEffect` (React) from `useEffect` (custom)
            import_map = self.js_import_tracker.analyze_imports(root_node, source_code)

            # === POLYGLOT INTELLIGENCE: Apply JavaScript/TypeScript Heuristics ===
            # HEURISTIC 1: React Hooks (useEffect/useCallback/useMemo dependencies)
            # v3.6.0: Now checks if function originates from 'react' module
            self.js_heuristics.apply_react_hook_heuristic(root_node, source_code, import_map)

            # HEURISTIC 2: Express Routes (router.get/app.post handlers)
            # v3.6.0: Now checks if object originates from 'express' module
            self.js_heuristics.apply_express_route_heuristic(root_node, source_code, import_map)

            # HEURISTIC 3: Export Protection (export default/named exports)
            # v3.4.0: Application-aware tree shaking
            # Library mode: Protects ALL exports (public API)
            # App mode: Only protects 'export default' (enables dead export detection)
            self.js_heuristics.apply_export_heuristic(root_node, source_code, self.library_mode)

    def _is_identifier_usage(self, identifier_node, parent_node, source_code: bytes) -> bool:
        """Check if an identifier node is a USAGE (reference) rather than a definition/binding.

        MAXIMUM PARANOIA MODE: Track everything except actual definition names.

        Args:
            identifier_node: The identifier node to check
            parent_node: The parent of the identifier node
            source_code: Source code as bytes

        Returns:
            True if this is a usage, False if it's a definition/binding
        """
        if parent_node is None:
            return False

        parent_type = parent_node.type

        # === CRITICAL EXCLUSIONS ONLY ===

        # EXCLUSION 1: Function/class definition names (the actual definition itself)
        if parent_type in ('function_definition', 'class_definition'):
            # Check if this identifier is the NAME of the function/class
            # (not just any identifier inside the function/class)
            for i, child in enumerate(parent_node.children):
                if child.type == 'identifier' and child == identifier_node:
                    # First identifier in function/class def is the name
                    if i <= 2:  # Usually: 'def'/'class', name, parameters/inheritance
                        return False

        # EXCLUSION 2: Parameter names (function parameter definitions)
        if parent_type in ('parameters', 'parameter', 'typed_parameter', 'default_parameter',
                          'typed_default_parameter', 'list_splat_pattern', 'dictionary_splat_pattern'):
            # Check if this is a parameter name (not a type annotation or default value)
            # Type annotations and default values ARE usages
            for i, child in enumerate(parent_node.children):
                if child.type == 'identifier' and child == identifier_node:
                    # First identifier in parameter is usually the name
                    if i == 0 or (i == 1 and parent_node.children[0].type != 'identifier'):
                        return False

        # EXCLUSION 3: Import statement names (tracked separately via dedicated import handler)
        if parent_type in ('import_from_statement', 'import_statement', 'aliased_import'):
            return False

        # EXCLUSION 4: Decorator names (tracked separately via dedicated decorator handler)
        if parent_type == 'decorator':
            return False

        # EXCLUSION 5: Left-hand side of assignment (being assigned TO, not used)
        # BUT: Right-hand side values ARE usages
        if parent_type == 'assignment':
            if parent_node.child_count >= 3:
                left_side = parent_node.children[0]
                if self._contains_node(left_side, identifier_node):
                    return False

        # === EVERYTHING ELSE IS A USAGE ===
        # This includes:
        # - Attribute access (obj.symbol)
        # - Function arguments
        # - Return values
        # - Conditional expressions
        # - List/dict comprehensions
        # - Keyword argument VALUES
        # - Type annotations
        # - Default parameter values
        # - Everything else
        return True

    def _contains_node(self, parent, target_node) -> bool:
        """Check if parent contains target_node in its tree.

        Args:
            parent: Parent node to search
            target_node: Node to find

        Returns:
            True if target_node is in parent's subtree
        """
        if parent == target_node:
            return True
        for child in parent.children:
            if self._contains_node(child, target_node):
                return True
        return False

    def _extract_all_import_names(self, node, source_code: bytes) -> List[Tuple[str, int]]:
        """Recursively extract ALL imported names from an import_from_statement node.

        MULTI-LINE IMPORT PARSER: Handles parenthesized imports like:
            from black.nodes import (
                is_import,
                is_with_or_async_with_stmt,
            )

        Args:
            node: import_from_statement node or any child node
            source_code: Source code as bytes

        Returns:
            List of (name, line_number) tuples for all imported symbols
        """
        names = []
        module_name_found = False

        # Recursive stack-based traversal
        stack = [node]
        while stack:
            current = stack.pop()

            # CRITICAL FIX: Skip ONLY the first dotted_name (which is the module name)
            # For "from black.nodes import is_import", the dotted_name is "black.nodes"
            if current.type == 'dotted_name' and not module_name_found:
                # Check if this is a direct child of import_from_statement
                if current.parent and current.parent.type == 'import_from_statement':
                    module_name_found = True
                    continue

            # Found an identifier - this is an imported name
            if current.type == 'identifier':
                # Make sure we're not capturing keywords like 'from' or 'import'
                name = source_code[current.start_byte:current.end_byte].decode('utf-8')
                if name not in ('from', 'import', 'as'):
                    line_number = current.start_point[0] + 1
                    names.append((name, line_number))
            # Found an aliased import - extract the original name (first child)
            elif current.type == 'aliased_import':
                if current.child_count > 0:
                    name_node = current.children[0]
                    name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    line_number = name_node.start_point[0] + 1
                    names.append((name, line_number))
            # Recurse into children for other node types
            else:
                for child in reversed(current.children):
                    stack.append(child)

        return names

    def _track_assignment(self, assignment_node, source_code: bytes, file_path: Path):
        """Track variable assignment for type inference.

        TYPE INFERENCE ENGINE: Detects patterns like:
            x = StringParser()  -> infer x has type StringParser
            y = ClassName(args) -> infer y has type ClassName

        Args:
            assignment_node: AST assignment node
            source_code: Source code bytes
            file_path: File path
        """
        # Assignment structure: left = right
        # children: [left_side, '=', right_side]
        if assignment_node.child_count < 3:
            return

        left_node = assignment_node.children[0]
        right_node = assignment_node.children[2]  # After '='

        # Extract variable name from left side
        variable_name = None
        if left_node.type == 'identifier':
            variable_name = source_code[left_node.start_byte:left_node.end_byte].decode('utf-8')
        elif left_node.type == 'pattern_list':
            # Multiple assignment: a, b = values (skip for now)
            return

        if not variable_name:
            return

        # Infer type from right side
        inferred_type = self._infer_type_from_expression(right_node, source_code)
        if inferred_type:
            self.variable_types.add_assignment(str(file_path), variable_name, inferred_type)

    def _track_type_annotation(self, annotation_node, source_code: bytes, file_path: Path):
        """Track type annotations for type inference.

        TYPE INFERENCE ENGINE: Detects patterns like:
            variable: ClassName = ...
            def func(param: ClassName):

        Args:
            annotation_node: AST type annotation node
            source_code: Source code bytes
            file_path: File path
        """
        # Type annotation in various contexts
        # For now, we'll handle this in _infer_type_from_expression
        pass

    def _infer_type_from_expression(self, expr_node, source_code: bytes) -> str:
        """Infer the type from an expression node.

        Args:
            expr_node: Expression node
            source_code: Source code bytes

        Returns:
            Type name if inferrable, None otherwise
        """
        if expr_node.type == 'call':
            # Pattern: ClassName() or ClassName(args)
            if expr_node.child_count > 0:
                func_node = expr_node.children[0]
                if func_node.type == 'identifier':
                    # Simple constructor call
                    type_name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                    # Only consider capitalized names (class names by convention)
                    if type_name and type_name[0].isupper():
                        return type_name
        return None

    def _handle_isinstance_narrowing(self, if_node, source_code: bytes, file_path: Path, stack: List):
        """Handle isinstance() type narrowing in if statements.

        TYPE NARROWING: Detects patterns like:
            if isinstance(var, ClassName):
                var.method()  # Here, var is known to be ClassName

        Args:
            if_node: if_statement node
            source_code: Source code bytes
            file_path: File path
            stack: Traversal stack (to process if-block with narrowed type)
        """
        # if_statement structure: if, condition, :, block
        # Find the condition (typically an isinstance call)
        condition_node = None
        if_block_node = None

        for child in if_node.children:
            if child.type == 'comparison_operator' or child.type == 'call':
                condition_node = child
            elif child.type == 'block':
                if_block_node = child
                break

        if not condition_node or not if_block_node:
            return

        # Check if condition is isinstance(var, Type)
        isinstance_info = self._extract_isinstance_info(condition_node, source_code)
        if isinstance_info:
            var_name, type_name = isinstance_info
            # Push narrowed scope before processing if-block
            self.variable_types.push_narrowed_scope(str(file_path), var_name, type_name)
            # Note: We'd need to pop this after processing the if-block
            # For now, this is a simplified implementation

    def _extract_isinstance_info(self, node, source_code: bytes) -> Tuple[str, str]:
        """Extract variable and type from isinstance() call.

        Args:
            node: AST node potentially containing isinstance
            source_code: Source code bytes

        Returns:
            (variable_name, type_name) if found, None otherwise
        """
        # Pattern: isinstance(var_name, TypeName)
        # Look for call node with 'isinstance' identifier
        if node.type == 'call':
            if node.child_count >= 2:
                func = node.children[0]
                if func.type == 'identifier':
                    func_name = source_code[func.start_byte:func.end_byte].decode('utf-8')

                    if func_name == 'isinstance':
                        # Extract arguments
                        args = node.children[1]  # argument_list

                        if args.type == 'argument_list':
                            # argument_list includes punctuation: '(', arg1, ',', arg2, ')'
                            # Filter out punctuation and find actual argument nodes
                            actual_args = [child for child in args.children
                                         if child.type not in ('(', ')', ',')]

                            if len(actual_args) >= 2:
                                var_node = actual_args[0]
                                type_node = actual_args[1]

                                var_name = None
                                if var_node.type == 'identifier':
                                    var_name = source_code[var_node.start_byte:var_node.end_byte].decode('utf-8')

                                type_name = None
                                if type_node.type == 'identifier':
                                    type_name = source_code[type_node.start_byte:type_node.end_byte].decode('utf-8')

                                if var_name and type_name:
                                    return (var_name, type_name)

        # Recursively check children
        for child in node.children:
            result = self._extract_isinstance_info(child, source_code)
            if result:
                return result

        return None

    def _extract_type_hint_references(self, node, source_code: bytes, file_path: Path):
        """ENTERPRISE EDGE CASE 1: Type Hint Analysis (FastAPI/Pydantic).

        Extract references from type hints like:
        - Annotated[str, Depends(get_token)]
        - x: Annotated[User, Depends(get_current_user)]

        This catches dependency injection patterns where functions are only
        referenced inside type annotations.

        Args:
            node: AST node (subscript for Annotated)
            source_code: Source code bytes
            file_path: File path
        """
        # Recursively search through node and all children
        stack = [node]
        while stack:
            current = stack.pop()

            # Look for Annotated[Type, Depends(...)] patterns
            if current.type == 'subscript':
                # Check if this is Annotated[...]
                if current.child_count >= 2:
                    base = current.children[0]
                    if base.type == 'identifier':
                        base_name = source_code[base.start_byte:base.end_byte].decode('utf-8')
                        if base_name == 'Annotated':
                            # Extract arguments from Annotated
                            self._extract_depends_calls(current, source_code, file_path)

            # Also check for standalone Depends() calls in type annotations
            if current.type == 'call':
                if current.child_count >= 1:
                    func = current.children[0]
                    if func.type == 'identifier':
                        func_name = source_code[func.start_byte:func.end_byte].decode('utf-8')
                        if func_name in ('Depends', 'Security', 'Inject'):
                            # Extract the dependency function
                            if current.child_count >= 2:
                                args = current.children[1]
                                if args.type == 'argument_list':
                                    for child in args.children:
                                        if child.type == 'identifier':
                                            dep_name = source_code[child.start_byte:child.end_byte].decode('utf-8')
                                            # Add reference to the dependency function
                                            self.add_reference(dep_name, str(file_path),
                                                             child.start_point[0] + 1, 'dependency_injection')

            # Recurse into children
            for child in current.children:
                stack.append(child)

    def _extract_depends_calls(self, node, source_code: bytes, file_path: Path):
        """Extract Depends() calls from within Annotated type hints.

        Args:
            node: AST node
            source_code: Source code bytes
            file_path: File path
        """
        # Recursively search for Depends(...) calls
        stack = [node]
        while stack:
            current = stack.pop()

            if current.type == 'call':
                if current.child_count >= 1:
                    func = current.children[0]
                    if func.type == 'identifier':
                        func_name = source_code[func.start_byte:func.end_byte].decode('utf-8')
                        if func_name in ('Depends', 'Security', 'Inject'):
                            # Extract the dependency function
                            if current.child_count >= 2:
                                args = current.children[1]
                                if args.type == 'argument_list':
                                    for child in args.children:
                                        if child.type == 'identifier':
                                            dep_name = source_code[child.start_byte:child.end_byte].decode('utf-8')
                                            self.add_reference(dep_name, str(file_path),
                                                             child.start_point[0] + 1, 'dependency_injection')

            # Recurse
            for child in current.children:
                stack.append(child)

    def _extract_string_symbol_references(self, node, source_code: bytes, file_path: Path):
        """ENTERPRISE EDGE CASE 2: String-to-Symbol Resolution (Celery/Django).

        Detect calls like:
        - signature('tasks.process_data')
        - task('my_task')
        - get_model('app_name.ModelName')

        If the string literal matches a known symbol, mark it as referenced.

        Args:
            node: AST node (call expression)
            source_code: Source code bytes
            file_path: File path
        """
        if node.type == 'call':
            if node.child_count >= 2:
                func = node.children[0]
                func_name = None

                # Get function name
                if func.type == 'identifier':
                    func_name = source_code[func.start_byte:func.end_byte].decode('utf-8')
                elif func.type == 'attribute':
                    # e.g., celery.signature
                    if func.child_count >= 2:
                        attr = func.children[-1]
                        if attr.type == 'identifier':
                            func_name = source_code[attr.start_byte:attr.end_byte].decode('utf-8')

                # Check if this is a string-based reference function
                if func_name in ('signature', 's', 'si', 'task', 'get_model', 'get_task'):
                    # Extract string argument
                    args = node.children[1]
                    if args.type == 'argument_list':
                        for child in args.children:
                            if child.type == 'string':
                                # Extract string content (remove quotes)
                                string_val = source_code[child.start_byte:child.end_byte].decode('utf-8')
                                string_val = string_val.strip('"\'')

                                # Try to resolve to a known symbol
                                # Handle dotted paths like 'tasks.process_data'
                                symbol_name = string_val.split('.')[-1]  # Get last part

                                # Check if this matches any known definition
                                for symbol_id, entity in self.definitions.items():
                                    if entity.name == symbol_name:
                                        # Found a match - add string reference
                                        self.add_reference(symbol_name, str(file_path),
                                                         child.start_point[0] + 1, 'string_reference')
                                        break

    def _check_qt_auto_connection(self, entity: Entity, class_name: str) -> bool:
        """ENTERPRISE EDGE CASE 3: Magic Naming (PySide/Qt).

        Qt's connectSlotsByName auto-connects methods matching:
        on_<object_name>_<signal_name>

        Args:
            entity: Method entity to check
            class_name: Class containing the method

        Returns:
            True if this is a Qt auto-connection slot
        """
        import re

        # Check if method name matches Qt slot pattern
        if not re.match(r'^on_[a-zA-Z0-9]+_[a-zA-Z0-9]+$', entity.name):
            return False

        # Check if class inherits from Qt widgets
        # Look for Qt base classes in the inheritance map
        qt_bases = {'QMainWindow', 'QWidget', 'QDialog', 'QFrame', 'QWindow'}

        # Check if class_name has any Qt ancestors
        if class_name in self.inheritance_map.parents:
            for base in self.inheritance_map.parents[class_name]:
                if base in qt_bases:
                    return True

        # Also check imports in the file to see if Qt is used
        # (Simplified check - look for Qt in file path or imports)
        file_content = Path(entity.file_path).read_text(errors='ignore')
        if 'PySide' in file_content or 'PyQt' in file_content or 'QMainWindow' in file_content:
            if any(qt_base in file_content for qt_base in qt_bases):
                return True

        return False

    def _check_sqlalchemy_metaprogramming(self, entity: Entity) -> bool:
        """ENTERPRISE EDGE CASE 4: Metaprogramming (SQLAlchemy).

        Protect:
        - Methods decorated with @declared_attr or @hybrid_property
        - Class variables named __abstract__ or __tablename__

        Args:
            entity: Entity to check

        Returns:
            True if this is SQLAlchemy metaprogramming
        """
        # Check for SQLAlchemy decorators
        if '@declared_attr' in entity.full_text or '@hybrid_property' in entity.full_text:
            return True

        # Check for special SQLAlchemy class variables
        if entity.name in ('__abstract__', '__tablename__', '__table_args__'):
            return True

        return False

    def _check_inheritance_context(self, entity: Entity, class_name: str) -> bool:
        """ENTERPRISE EDGE CASE 5: Inheritance Context.

        Only protect methods like 'save' or 'delete' if the class inherits
        from known ORM bases like 'Model', 'Base', 'db.Model'.

        Args:
            entity: Entity to check (must be a method)
            class_name: Class containing the method

        Returns:
            True if method should be protected based on inheritance
        """
        # Check if this is a method that should be context-aware
        context_sensitive_methods = {'save', 'delete', 'update', 'create', 'get', 'filter'}

        if entity.name not in context_sensitive_methods:
            return False

        # Check if class inherits from ORM bases
        orm_bases = {'Model', 'Base', 'Document', 'db.Model', 'models.Model'}

        # Check direct parents
        if class_name in self.inheritance_map.parents:
            for base in self.inheritance_map.parents[class_name]:
                if base in orm_bases or base.endswith('.Model') or base.endswith('.Base'):
                    return True

        return False

    def _check_pydantic_alias_generator(self, entity: Entity) -> bool:
        """PRIORITY THREE: Pydantic v2 Alias Generator.

        Fields in Pydantic models with alias_generator look unused because the
        incoming JSON uses camelCase while the Python model uses snake_case.

        Example:
            class UserModel(BaseModel):
                model_config = ConfigDict(alias_generator=to_camel)
                user_name: str  # Accessed as "userName" in JSON - looks unused!

        Args:
            entity: Entity to check

        Returns:
            True if this is a Pydantic field in a model with alias_generator
        """
        # Must be a class variable (not a method)
        if entity.type not in ['variable', 'assignment']:
            return False

        # Must be inside a class
        if not entity.parent_class:
            return False

        # Check if file uses Pydantic
        try:
            file_content = Path(entity.file_path).read_text(errors='ignore')
            if 'BaseModel' not in file_content and 'pydantic' not in file_content:
                return False

            # Check if the class has model_config with alias_generator
            if 'alias_generator' in file_content and 'model_config' in file_content:
                # Conservative: Protect ALL fields in files with alias_generator
                return True
        except (IOError, OSError):
            pass

        return False

    def _check_fastapi_dependency_override(self, entity: Entity) -> bool:
        """PRIORITY THREE: FastAPI Dependency Overrides.

        Functions assigned to app.dependency_overrides appear unused in main flow
        but are critical for testing patterns.

        Example:
            def override_auth():
                return {"user": "test"}

            app.dependency_overrides[get_current_user] = override_auth

        Args:
            entity: Entity to check

        Returns:
            True if function name appears in dependency_overrides assignments
        """
        # Must be a function
        if entity.type not in ['function_definition', 'function']:
            return False

        try:
            file_content = Path(entity.file_path).read_text(errors='ignore')

            # Check if file uses FastAPI dependency_overrides
            if 'dependency_overrides' not in file_content:
                return False

            # Check if this function name appears near dependency_overrides
            # Pattern: app.dependency_overrides[...] = function_name
            import re
            pattern = rf'dependency_overrides\[.*?\]\s*=\s*{re.escape(entity.name)}'
            if re.search(pattern, file_content):
                return True
        except (IOError, OSError):
            pass

        return False

    def _check_pytest_fixture(self, entity: Entity) -> bool:
        """PRIORITY THREE: pytest Fixture Detection.

        Functions decorated with @pytest.fixture are called implicitly by pytest,
        not directly by test code.

        Example:
            @pytest.fixture
            def db_connection():
                return setup_db()

            def test_query(db_connection):  # db_connection appears unused!
                assert db_connection.query(...)

        Args:
            entity: Entity to check

        Returns:
            True if function is a pytest fixture
        """
        # Must be a function
        if entity.type not in ['function_definition', 'function']:
            return False

        # Check for @pytest.fixture decorator
        if '@pytest.fixture' in entity.full_text or '@fixture' in entity.full_text:
            return True

        # Also check for @conftest patterns (pytest conftest.py)
        if 'conftest.py' in str(entity.file_path):
            # Functions in conftest.py are often fixtures
            try:
                file_content = Path(entity.file_path).read_text(errors='ignore')
                if 'pytest' in file_content or '@fixture' in file_content:
                    return True
            except (IOError, OSError):
                pass

        return False

    def _extract_python_references(self, file_path: Path, node, source_code: bytes, is_package_init: bool = False):
        """Extract Python references (imports, function calls, ANY identifier usage).

        Args:
            file_path: Path to the file
            node: Tree-sitter node
            source_code: Source code as bytes
            is_package_init: True if this file is __init__.py (for package export tracking)
        """
        # Use stack-based traversal with parent tracking and class context
        # Stack format: (current_node, parent_node, enclosing_class_name)
        stack = [(node, None, None)]
        while stack:
            current, parent, class_context = stack.pop()

            # Update class context if we're entering a class definition
            if current.type == 'class_definition':
                # Find the class name
                for child in current.children:
                    if child.type == 'identifier':
                        class_context = source_code[child.start_byte:child.end_byte].decode('utf-8')
                        break

            # TYPE INFERENCE ENGINE: Track variable assignments
            if current.type == 'assignment':
                # Pattern: variable = Constructor() or variable = expression
                self._track_assignment(current, source_code, file_path)

            # TYPE INFERENCE ENGINE: Track type annotations
            elif current.type == 'typed_parameter' or current.type == 'type':
                # Pattern: variable: Type or variable: Type = value
                self._track_type_annotation(current, source_code, file_path)
                # ENTERPRISE: Also extract type hint references from annotations
                self._extract_type_hint_references(current, source_code, file_path)

            # TYPE NARROWING: Detect isinstance() checks
            elif current.type == 'if_statement':
                self._handle_isinstance_narrowing(current, source_code, file_path, stack)

            # Extract import statements
            if current.type == 'import_from_statement':
                # from module import name1, name2
                # UNIVERSAL SCALPEL: Resolve module to file path for precise cross-module linking
                module_name = None
                for child in current.children:
                    if child.type == 'dotted_name':
                        module_name = source_code[child.start_byte:child.end_byte].decode('utf-8')
                        break

                # Resolve module path to actual file
                target_file_path = self._resolve_module_to_file(module_name, file_path) if module_name else None

                # MULTI-LINE IMPORT PARSER: Recursively extract ALL imported names
                # Handles both single-line and parenthesized multi-line imports
                imported_names = self._extract_all_import_names(current, source_code)

                for name, line_num in imported_names:
                    self.add_reference(name, str(file_path), line_num, 'import',
                                     target_file=target_file_path)
                    # Track package export
                    if is_package_init and module_name:
                        self._track_package_export(module_name, name, file_path)

            elif current.type == 'import_statement':
                # import module or import module as alias
                for child in current.children:
                    if child.type == 'dotted_name':
                        name = source_code[child.start_byte:child.end_byte].decode('utf-8')
                        self.add_reference(name, str(file_path), child.start_point[0] + 1, 'import')
                    elif child.type == 'aliased_import':
                        if child.child_count > 0:
                            name_node = child.children[0]
                            name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                            self.add_reference(name, str(file_path), name_node.start_point[0] + 1, 'import')

            # ENTERPRISE EDGE CASE 2: String-to-Symbol Resolution (Celery/Django)
            # Check for string-based task/model references
            if current.type == 'call':
                self._extract_string_symbol_references(current, source_code, file_path)

            # ENTERPRISE EDGE CASE 1: Type Hint Analysis (FastAPI/Pydantic)
            # Check for Annotated[Type, Depends(...)] patterns
            if current.type == 'subscript':
                self._extract_type_hint_references(current, source_code, file_path)

            # Extract function calls
            if current.type == 'call':
                # ENTERPRISE: Also extract type hint references from calls
                self._extract_type_hint_references(current, source_code, file_path)

                # function_name() or obj.method()
                if current.child_count > 0:
                    func_node = current.children[0]
                    if func_node.type == 'identifier':
                        name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                        self.add_reference(name, str(file_path), func_node.start_point[0] + 1, 'call')
                    elif func_node.type == 'attribute':
                        # obj.method() - extract the method name
                        # TYPE INFERENCE ENGINE: Resolve obj to its type
                        if func_node.child_count >= 2:
                            # First child is the object (e.g., 'self', 'cls', or 'obj')
                            # Last child is the attribute name
                            obj_node = func_node.children[0]
                            attr_node = func_node.children[-1]

                            if attr_node.type == 'identifier':
                                method_name = source_code[attr_node.start_byte:attr_node.end_byte].decode('utf-8')

                                # Resolve the type of the object
                                method_class_context = None
                                if obj_node.type == 'identifier':
                                    obj_name = source_code[obj_node.start_byte:obj_node.end_byte].decode('utf-8')

                                    if obj_name in ('self', 'cls'):
                                        # Use the enclosing class from our traversal
                                        method_class_context = class_context
                                    else:
                                        # TYPE INFERENCE: Look up the variable's type
                                        inferred_type = self.variable_types.get_type(str(file_path), obj_name)
                                        if inferred_type:
                                            method_class_context = inferred_type

                                self.add_reference(method_name, str(file_path), attr_node.start_point[0] + 1, 'call',
                                                 class_context=method_class_context)

            # Extract decorator references
            elif current.type == 'decorator':
                # @decorator_name or @decorator.method or @decorator(args)
                # The decorator node has children: '@', identifier/attribute/call
                for child in current.children:
                    if child.type == 'identifier':
                        # Simple decorator: @decorator_name
                        name = source_code[child.start_byte:child.end_byte].decode('utf-8')
                        self.add_reference(name, str(file_path), child.start_point[0] + 1, 'decorator')
                    elif child.type == 'attribute':
                        # Attribute decorator: @module.decorator
                        # Track the base identifier (e.g., 'module' in '@module.decorator')
                        if child.child_count > 0:
                            base_node = child.children[0]
                            if base_node.type == 'identifier':
                                name = source_code[base_node.start_byte:base_node.end_byte].decode('utf-8')
                                self.add_reference(name, str(file_path), base_node.start_point[0] + 1, 'decorator')
                    elif child.type == 'call':
                        # Call decorator: @decorator(args)
                        # Extract the function being called
                        if child.child_count > 0:
                            func_node = child.children[0]
                            if func_node.type == 'identifier':
                                name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                                self.add_reference(name, str(file_path), func_node.start_point[0] + 1, 'decorator')
                            elif func_node.type == 'attribute':
                                # @module.decorator(args)
                                if func_node.child_count > 0:
                                    base_node = func_node.children[0]
                                    if base_node.type == 'identifier':
                                        name = source_code[base_node.start_byte:base_node.end_byte].decode('utf-8')
                                        self.add_reference(name, str(file_path), base_node.start_point[0] + 1, 'decorator')

            # === COMPREHENSIVE IDENTIFIER TRACKING ===
            # Track ALL identifier usages (assignments, arguments, return values, etc.)
            elif current.type == 'identifier':
                # Check if this identifier is a USAGE (not a definition or binding)
                if self._is_identifier_usage(current, parent, source_code):
                    name = source_code[current.start_byte:current.end_byte].decode('utf-8')
                    self.add_reference(name, str(file_path), current.start_point[0] + 1, 'usage')

            # Add children to stack in reverse order with parent tracking and class context
            for child in reversed(current.children):
                stack.append((child, current, class_context))

    def _extract_js_references(self, file_path: Path, node, source_code: bytes):
        """Extract JavaScript/TypeScript references.

        Args:
            file_path: Path to the file
            node: Tree-sitter node
            source_code: Source code as bytes
        """
        stack = [(node, None)]  # (current_node, parent_node) for consistency
        while stack:
            current, parent = stack.pop()

            # Extract import statements
            if current.type == 'import_statement':
                # import { name1, name2 } from 'module'
                for child in current.children:
                    if child.type == 'import_clause':
                        for subchild in child.children:
                            if subchild.type == 'named_imports':
                                for import_spec in subchild.children:
                                    if import_spec.type == 'import_specifier':
                                        if import_spec.child_count > 0:
                                            name_node = import_spec.children[0]
                                            name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                                            self.add_reference(name, str(file_path), name_node.start_point[0] + 1, 'import')
                            elif subchild.type == 'identifier':
                                # default import
                                name = source_code[subchild.start_byte:subchild.end_byte].decode('utf-8')
                                self.add_reference(name, str(file_path), subchild.start_point[0] + 1, 'import')

            # Extract function calls
            elif current.type == 'call_expression':
                if current.child_count > 0:
                    func_node = current.children[0]
                    if func_node.type == 'identifier':
                        name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                        self.add_reference(name, str(file_path), func_node.start_point[0] + 1, 'call')
                    elif func_node.type == 'member_expression':
                        # obj.method()
                        if func_node.child_count >= 2:
                            prop_node = func_node.children[-1]
                            if prop_node.type in ('property_identifier', 'identifier'):
                                name = source_code[prop_node.start_byte:prop_node.end_byte].decode('utf-8')
                                self.add_reference(name, str(file_path), prop_node.start_point[0] + 1, 'call')

            # Extract class instantiations
            elif current.type == 'new_expression':
                if current.child_count > 1:
                    class_node = current.children[1]
                    if class_node.type == 'identifier':
                        name = source_code[class_node.start_byte:class_node.end_byte].decode('utf-8')
                        self.add_reference(name, str(file_path), class_node.start_point[0] + 1, 'instantiation')

            # Add children to stack with parent tracking
            for child in reversed(current.children):
                stack.append((child, current))

    def _build_grep_shield_cache(self) -> Dict[str, str]:
        """Build a cache of all file contents for grep shield.

        PERFORMANCE OPTIMIZATION: Read all files once and cache contents.
        This prevents re-reading files for each dead symbol check.

        VENDORED CODE FILTER: Skips vendored directories to avoid scanning
        thousands of third-party files.

        Returns:
            Dict mapping file paths to file contents
        """
        # Import VENDORED_PATTERNS from orphan_detector
        from .orphan_detector import OrphanDetector

        cache = {}
        python_files = list(self.project_root.rglob('*.py'))

        # Vendored patterns to skip (same as OrphanDetector)
        VENDORED_PATTERNS = {
            'vendor', 'extern', 'third_party', 'blib2to3', '_internal',
            'dist', 'build', 'node_modules', '.tox', '.venv', 'venv',
            '.virtualenv', 'site-packages', '__pycache__'
        }

        for file_path in python_files:
            # Skip vendored directories
            if any(pattern in file_path.parts for pattern in VENDORED_PATTERNS):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    cache[str(file_path.resolve())] = f.read()
            except (IOError, OSError):
                continue

        return cache

    def _is_dynamically_referenced(self, symbol_name: str, defining_file: str, grep_cache: Dict[str, str] = None) -> bool:
        """Check if a symbol name appears as a string in files outside its definition.

        GREP SHIELD: Catches dynamic usage via eval(), getattr(), factory patterns.
        This is the final safety net against deleting symbols used through strings.

        Args:
            symbol_name: Name of the symbol to search for
            defining_file: File where the symbol is defined (exclude from search)
            grep_cache: Optional pre-built cache of file contents (for performance)

        Returns:
            True if symbol name found as a string in other files
        """
        # If no cache provided, build it on the fly (less efficient)
        if grep_cache is None:
            grep_cache = self._build_grep_shield_cache()

        # Resolve defining file path
        try:
            defining_file_resolved = str(Path(defining_file).resolve())
        except (ValueError, OSError):
            defining_file_resolved = defining_file

        # Search through cached file contents
        for file_path, content in grep_cache.items():
            # Skip the defining file (symbol name will always appear there)
            if file_path == defining_file_resolved:
                continue

            # Check if symbol name appears anywhere in the file
            if symbol_name in content:
                return True

        return False

    def _detect_all_metaprogramming_danger(self):
        """Scan all Python files for metaprogramming patterns that make static analysis unsafe.

        PRIORITY TWO: Metaprogramming Danger Shield
        Files using dynamic execution (getattr, eval, exec, importlib) are flagged as UNSAFE.
        ALL symbols in these files are protected from deletion since they may be called dynamically.

        Patterns detected:
        - getattr() / setattr() / hasattr() / delattr()
        - eval() / exec() / compile()
        - importlib.import_module()
        - __import__()
        - type() with 3 arguments (dynamic class creation)

        This is conservative but necessary - we cannot trace dynamic execution statically.

        CACHE INTEGRATION: Check cache before scanning files. Cache hit = instant result.
        """
        # Patterns that indicate dynamic execution
        danger_patterns = {
            'getattr', 'setattr', 'hasattr', 'delattr',
            'eval', 'exec', 'compile',
            'importlib', '__import__',
            # Also check for common metaprogramming decorators
            '@property', '@staticmethod', '@classmethod',  # Safe but often used with getattr
        }

        # Scan all files in definitions
        scanned_files = set()
        for entity in self.definitions.values():
            file_path = Path(entity.file_path)
            file_path_str = str(file_path)

            if file_path_str in scanned_files:
                continue
            scanned_files.add(file_path_str)

            # CACHE CHECK: Load from cache if file is unchanged
            cached_danger = self.cache.get_metaprogramming_danger(file_path)
            if cached_danger is not None:
                # Cache hit! Use cached result
                if cached_danger:
                    self.metaprogramming_dangerous_files.add(file_path_str)
                continue

            # Cache miss - perform full analysis
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Check for danger patterns
                    # Use more precise matching to avoid false positives
                    is_dangerous = any(pattern in content for pattern in ['getattr(', 'setattr(', 'hasattr(', 'delattr(',
                                                                            'eval(', 'exec(', 'compile(',
                                                                            'importlib.', '__import__(',
                                                                            'type(', '.__dict__'])

                    # Store result in cache
                    self.cache.set_metaprogramming_danger(file_path, is_dangerous)

                    if is_dangerous:
                        self.metaprogramming_dangerous_files.add(file_path_str)

            except (IOError, OSError):
                # If we can't read the file, play it safe and mark it as dangerous
                self.metaprogramming_dangerous_files.add(file_path_str)
                # Also cache this result
                self.cache.set_metaprogramming_danger(file_path, True)

    def find_dead_symbols(self, language: str = 'python', enable_grep_shield: bool = False) -> List[Entity]:
        """Find symbols that are defined but never referenced using the 4-5 Stage Shield.

        4-STAGE SHIELD (default):
        Stage 1 (Cross-File): Is the symbol imported or called by another file?
        Stage 2 (Framework/Meta): Does it pass the WisdomRegistry.is_immortal check?
        Stage 3 (Lifecycle): Is it a dunder method of a used class?
        Stage 4 (Entry Point): Is the file a known entry point?

        5-STAGE SHIELD (with --grep-shield flag):
        Stage 5 (Grep Shield): Does the symbol name appear as a string elsewhere?
        WARNING: Grep shield can be slow on large codebases (3000+ files).

        PREMIUM SHIELDS (always enabled):
        - Config File References: AWS/Serverless handlers, Django settings, Docker commands
        - Metaprogramming Danger: Files using getattr, eval, exec
        - Advanced Framework Heuristics: Pydantic v2, FastAPI, pytest

        Args:
            language: Language being analyzed ('python', 'javascript', 'typescript')
            enable_grep_shield: Enable grep shield for dynamic usage detection (default: False)

        Returns:
            List of Entity objects for dead symbols
        """
        dead_symbols = []

        # === PRIORITY ONE: Parse Configuration Files ===
        # Scan YAML/JSON config files for infrastructure-as-code references
        # This catches serverless handlers, Django settings, Docker commands, etc.
        if not self.config_references:
            try:
                self.config_references = self.config_parser.parse_all_configs()
            except Exception as e:
                # Graceful degradation: Continue without config file protection
                # Don't crash the entire analysis if config parsing fails
                self.config_references = {}
                # Note: Logging would go here in production, but we skip console output for now

        # === PRIORITY TWO: Detect Metaprogramming Danger ===
        # Scan all files for dynamic execution patterns (getattr, eval, exec)
        if not self.metaprogramming_dangerous_files:
            try:
                self._detect_all_metaprogramming_danger()
            except Exception as e:
                # Graceful degradation: Continue without metaprogramming protection
                self.metaprogramming_dangerous_files = set()

        # Build grep shield cache if enabled (performance optimization)
        # This reads all files once instead of re-reading for each dead symbol
        grep_cache = self._build_grep_shield_cache() if enable_grep_shield else None

        for symbol_id, entity in self.definitions.items():
            references = self.references.get(symbol_id, [])

            # === STAGE 0: CONTEXTUAL IMMORTALITY (Protected Directories) ===
            # Symbols in tests, examples, etc. are automatically immortal
            file_path = Path(entity.file_path)
            # Check if any part of the path is in IMMORTAL_DIRECTORIES
            if any(part in self.IMMORTAL_DIRECTORIES for part in file_path.parts):
                entity.protected_by = f"Directory: {next(part for part in file_path.parts if part in self.IMMORTAL_DIRECTORIES)}/"
                continue

            # === STAGE 1: CROSS-FILE REFERENCES ===
            # Separate external and internal references
            external_references = [
                ref for ref in references
                if ref.file_path != entity.file_path
            ]

            internal_references = [
                ref for ref in references
                if ref.file_path == entity.file_path
            ]

            # If symbol has external references (imported or called from another file), it's ALIVE
            if external_references:
                continue

            # If symbol has internal references (used in same file), it's ALIVE
            if internal_references:
                continue

            # === STAGE 2: FRAMEWORK/META IMMORTALITY ===
            # Check WisdomRegistry for framework patterns
            is_immortal, reason, framework, tier = self.wisdom.is_immortal(
                entity.qualified_name or entity.name,
                entity.full_text,
                language
            )
            if is_immortal:
                # Store protection attribution
                if tier == 'premium':
                     entity.protected_by = f"[Premium Protection] Rule: {framework}"
                else:
                     entity.protected_by = f"Rule: {framework}"
                continue

            # === STAGE 2.5: LIBRARY MODE PUBLIC SYMBOL SHIELD ===
            # In library mode, all public symbols (not starting with _) are immortal
            if self.library_mode and self._is_public_symbol(entity):
                entity.protected_by = "Library Mode"
                continue

            # === STAGE 2.6: PACKAGE EXPORT SHIELD ===
            # Symbols exported via __init__.py are part of the package API
            symbol_full_name = f"{entity.file_path}::{entity.qualified_name or entity.name}"
            if symbol_full_name in self.package_exports:
                entity.protected_by = "Package Export"
                continue

            # === STAGE 2.7: CONFIG FILE REFERENCES (PRIORITY ONE) ===
            # Check if symbol is referenced in infrastructure-as-code configs
            # AWS Lambda handlers, Django settings, Docker commands, Airflow DAGs
            if entity.name in self.config_references:
                config_file, reason = self.config_references[entity.name][0]
                entity.protected_by = f"[Premium] Config Reference: {reason}"
                continue

            # === STAGE 2.8: METAPROGRAMMING DANGER SHIELD (PRIORITY TWO) ===
            # Files using dynamic execution (getattr, eval, exec) - unsafe to delete ANY symbols
            if str(entity.file_path) in self.metaprogramming_dangerous_files:
                entity.protected_by = "[Premium] Metaprogramming Danger (getattr/eval/exec detected)"
                continue

            # === STAGE 3: LIFECYCLE METHODS (DUNDER) ===
            # Dunder methods of used classes are protected by Constructor Shield
            # This is already handled in add_reference via _activate_constructor_shield
            # If we got here and it's a dunder method without references, its class is unused
            # So it's safe to mark as dead

            # === STAGE 4: ENTRY POINT ===
            # Legacy entry point check (for edge cases not covered by Wisdom)
            if self._is_entry_point_symbol(entity):
                entity.protected_by = "Entry Point"
                continue

            # === ENTERPRISE EDGE CASE 3: Qt Auto-Connection Slots ===
            # Protect on_*_* methods in Qt widgets
            try:
                if entity.parent_class and self._check_qt_auto_connection(entity, entity.parent_class):
                    entity.protected_by = "[Premium] Qt Auto-Connection Slot"
                    continue
            except Exception:
                pass

            # === ENTERPRISE EDGE CASE 4: SQLAlchemy Metaprogramming ===
            # Protect @declared_attr, @hybrid_property, __abstract__, __tablename__
            try:
                if self._check_sqlalchemy_metaprogramming(entity):
                    entity.protected_by = "[Premium] SQLAlchemy Metaprogramming"
                    continue
            except Exception:
                pass

            # === ENTERPRISE EDGE CASE 5: Inheritance Context ===
            # Only protect save/delete if class inherits from ORM base
            try:
                if entity.parent_class and self._check_inheritance_context(entity, entity.parent_class):
                    entity.protected_by = "[Premium] ORM Lifecycle Method"
                    continue
            except Exception:
                pass

            # === PRIORITY THREE: ADVANCED FRAMEWORK HEURISTICS ===

            # === Pydantic v2: Alias Generator Fields ===
            # Fields in models with alias_generator look unused but are accessed via aliases
            try:
                if self._check_pydantic_alias_generator(entity):
                    entity.protected_by = "[Premium] Pydantic v2 Alias Generator"
                    continue
            except Exception:
                # Graceful degradation: Skip this check if it fails
                pass

            # === FastAPI: Dependency Overrides ===
            # Functions assigned to app.dependency_overrides (common in testing)
            try:
                if self._check_fastapi_dependency_override(entity):
                    entity.protected_by = "[Premium] FastAPI Dependency Override"
                    continue
            except Exception:
                # Graceful degradation: Skip this check if it fails
                pass

            # === pytest: Fixture Detection ===
            # Functions decorated with @pytest.fixture
            try:
                if self._check_pytest_fixture(entity):
                    entity.protected_by = "[Premium] pytest Fixture"
                    continue
            except Exception:
                # Graceful degradation: Skip this check if it fails
                pass

            # === STAGE 5: GREP SHIELD (DYNAMIC USAGE DETECTION) ===
            # Final safety net: Check if symbol name appears as a string elsewhere
            # Catches dynamic usage via eval(), getattr(), factory patterns
            # Only runs if --grep-shield flag is enabled (can be slow on large codebases)
            if enable_grep_shield and self._is_dynamically_referenced(entity.name, entity.file_path, grep_cache):
                entity.protected_by = "Found in global string search (Potential Dynamic Usage)"
                continue

            # Symbol passed all shields and has NO references - it's DEAD
            dead_symbols.append(entity)

        return dead_symbols

    def _track_package_export(self, module_name: str, symbol_name: str, init_file_path: Path):
        """Track a symbol as a package export (imported into __init__.py).

        Args:
            module_name: Module being imported from (e.g., '.module', 'package.module')
            symbol_name: Symbol being imported
            init_file_path: Path to the __init__.py file
        """
        # Resolve module to file path
        # Handle relative imports (e.g., '.module', '..module')
        if module_name.startswith('.'):
            # Relative import - resolve based on __init__.py location
            init_dir = init_file_path.parent

            # Count leading dots to determine how many levels up
            level = 0
            for char in module_name:
                if char == '.':
                    level += 1
                else:
                    break

            # Remove leading dots to get module name
            module_part = module_name[level:]

            # Go up 'level-1' directories (level 1 means same directory)
            target_dir = init_dir
            for _ in range(level - 1):
                target_dir = target_dir.parent

            # Construct potential file path
            if module_part:
                # from .module import Symbol
                module_file = target_dir / f"{module_part}.py"
            else:
                # from . import Symbol (import from same directory's __init__.py)
                module_file = target_dir / "__init__.py"
        else:
            # Absolute import - try to resolve from project root
            # This is more complex and may not work reliably
            # For now, we'll skip absolute imports in package export tracking
            return

        # Track as package export: file_path::symbol_name
        if module_file.exists():
            export_id = f"{module_file}::{symbol_name}"
            self.package_exports.add(export_id)

    def _is_public_symbol(self, entity: Entity) -> bool:
        """Check if a symbol is public (part of the library's API).

        Public symbols are:
        - Top-level functions/classes that don't start with underscore
        - Methods of public classes that don't start with underscore
        - NOT nested inside other functions

        Args:
            entity: Entity to check

        Returns:
            True if the symbol is public
        """
        # Get the simple name (last part after dot)
        simple_name = entity.name

        # If it starts with underscore, it's private
        if simple_name.startswith('_'):
            return False

        # If it's nested (parent_class exists and it's not a class method), skip
        # We only want top-level entities or class methods
        # Parent_class being set means it's a method, which is fine
        # But we need to check if it's a nested function (which we can't easily detect here)
        # For now, we'll treat all non-underscore entities as public

        return True

    def _is_entry_point_symbol(self, entity: Entity) -> bool:
        """Check if a symbol is an entry point (should not be marked as dead).

        Entry points include:
        - Functions decorated with @app.command() (Typer)
        - Functions named 'main'
        - Symbols explicitly called in __main__ blocks

        Args:
            entity: Entity to check

        Returns:
            True if the symbol is an entry point
        """
        # Check for 'main' function
        if entity.name == 'main':
            return True

        # Check for typer decorators in the full text
        if '@app.command' in entity.full_text or '@app.callback' in entity.full_text:
            return True

        # IMPORTANT: Don't treat all symbols in __main__ files as entry points
        # Only if they're actually referenced in the __main__ block
        # This will be caught by the normal reference tracking

        return False

    def get_symbol_references(self, entity: Entity) -> List[Reference]:
        """Get all references to a symbol.

        Args:
            entity: Entity to get references for

        Returns:
            List of Reference objects
        """
        symbol_id = self._get_symbol_id(entity)
        return self.references.get(symbol_id, [])

    def get_licensing_status(self) -> dict:
        """Get the licensing tier status from WisdomRegistry.

        Returns:
            Dictionary with licensing information
        """
        return self.wisdom.get_licensing_status()
