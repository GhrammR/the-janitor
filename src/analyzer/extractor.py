"""Entity and import extraction from parsed syntax trees."""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from tree_sitter import Tree, Node


@dataclass
class Entity:
    """Represents a code entity (function or class)."""
    name: str
    type: str  # function_definition, class_definition, etc.
    full_text: str  # ENTIRE node text for embedding
    start_line: int
    end_line: int
    file_path: str
    qualified_name: str = None  # Fully qualified name (e.g., ClassName.method_name)
    parent_class: str = None  # Parent class name if this is a method
    base_classes: List[str] = None  # Base classes if this is a class (e.g., ['BaseClass', 'Mixin'])
    protected_by: str = ""  # Rule or directory that protected this symbol
    decorators: List[str] = None  # v4.2.0: Decorator names (e.g., ['@property', '@staticmethod'])


@dataclass
class Import:
    """Represents an import statement."""
    module: str  # The module being imported (e.g., 'os.path', './utils')
    names: List[str]  # Specific names imported (empty for 'import x')
    is_relative: bool  # True for relative imports ('./', '../')
    line_number: int
    file_path: str


class EntityExtractor:
    """Extract functions, classes, and imports from syntax trees."""

    # Node types to extract as entities per language
    NODE_TYPES = {
        'python': ['function_definition', 'class_definition', 'decorated_definition'],
        'typescript': ['function_declaration', 'class_declaration', 'method_definition'],
        'javascript': ['function_declaration', 'class_declaration', 'method_definition'],
    }

    # Import node types per language
    IMPORT_TYPES = {
        'python': ['import_statement', 'import_from_statement'],
        'typescript': ['import_statement', 'call_expression'],
        'javascript': ['import_statement', 'call_expression'],
    }

    def __init__(self, language: str):
        """Initialize extractor for given language.

        Args:
            language: One of 'python', 'typescript', 'javascript'
        """
        self.language = language
        self.entity_node_types = self.NODE_TYPES.get(language, [])
        self.import_node_types = self.IMPORT_TYPES.get(language, [])

    def extract_entities(self, tree: Tree, source_code: bytes, file_path: str) -> List[Entity]:
        """Extract functions/classes with FULL text and qualified names.

        CRITICAL: Captures ENTIRE node text (def keyword → end of body) via
        source_code[node.start_byte:node.end_byte].

        Builds qualified names for methods: ClassName.method_name

        Args:
            tree: Parsed tree-sitter Tree
            source_code: Original source code bytes
            file_path: Path to source file

        Returns:
            List of Entity objects with complete function/class text and qualified names
        """
        entities = []
        root = tree.root_node

        # Use context-aware traversal to track parent classes
        self._extract_with_context(root, source_code, file_path, None, entities)

        return entities

    def _extract_with_context(self, node: Node, source_code: bytes, file_path: str,
                              parent_class: Optional[str], entities: List[Entity]):
        """Recursively extract entities with parent class context.

        Args:
            node: Current node to process
            source_code: Source code bytes
            file_path: File path
            parent_class: Name of parent class if inside a class
            entities: List to append entities to
        """
        # Check if this node is an entity we want to extract
        if node.type in self.entity_node_types:
            # Special handling for decorated_definition (Python decorators)
            if node.type == 'decorated_definition':
                # Find the inner function_definition or class_definition
                inner_def = None
                for child in node.children:
                    if child.type in ['function_definition', 'class_definition']:
                        inner_def = child
                        break

                if inner_def:
                    # Extract the entire decorated_definition (includes decorators)
                    full_text = source_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
                    name = self._extract_name(inner_def)

                    if name:
                        # Build qualified name
                        if parent_class and inner_def.type in ['function_definition', 'method_definition']:
                            qualified_name = f"{parent_class}.{name}"
                        else:
                            qualified_name = name

                        # Extract base classes if this is a class definition
                        base_classes = None
                        if inner_def.type in ['class_definition', 'class_declaration']:
                            base_classes = self._extract_base_classes(inner_def, source_code)

                        # v4.2.0: Extract decorators for metadata preservation
                        decorators = self._extract_decorators(node, source_code)

                        # Use inner_def type for entity type
                        entities.append(Entity(
                            name=name,
                            type=inner_def.type,
                            full_text=full_text,  # Full text includes decorators!
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                            file_path=str(file_path),
                            qualified_name=qualified_name,
                            parent_class=parent_class,
                            base_classes=base_classes,
                            decorators=decorators
                        ))

                        # If this is a class, set it as parent for nested entities
                        if inner_def.type == 'class_definition' or inner_def.type == 'class_declaration':
                            parent_class = name

                        # Process ONLY the inner definition's children (for nested classes/methods)
                        # Skip the inner definition itself since we already processed it
                        for child in inner_def.children:
                            self._extract_with_context(child, source_code, file_path, parent_class, entities)

                # DON'T recurse into decorated_definition children here
                # We already handled the inner_def above
                return
            else:
                # Regular function_definition or class_definition
                full_text = source_code[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
                name = self._extract_name(node)

                if name:
                    # Build qualified name
                    if parent_class and node.type in ['function_definition', 'method_definition']:
                        # This is a method inside a class
                        qualified_name = f"{parent_class}.{name}"
                        current_parent = parent_class
                    else:
                        # This is a top-level function or class
                        qualified_name = name
                        current_parent = None

                    # Extract base classes if this is a class definition
                    base_classes = None
                    if node.type in ['class_definition', 'class_declaration']:
                        base_classes = self._extract_base_classes(node, source_code)

                    # v4.2.0: No decorators for non-decorated entities
                    decorators = None

                    entities.append(Entity(
                        name=name,
                        type=node.type,
                        full_text=full_text,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        file_path=str(file_path),
                        qualified_name=qualified_name,
                        parent_class=parent_class,
                        base_classes=base_classes,
                        decorators=decorators
                    ))

                    # If this is a class, set it as parent for nested entities
                    if node.type == 'class_definition' or node.type == 'class_declaration':
                        parent_class = name

                # Recursively process children with updated context
                for child in node.children:
                    self._extract_with_context(child, source_code, file_path, parent_class, entities)
        else:
            # Not an entity node, just recurse
            for child in node.children:
                self._extract_with_context(child, source_code, file_path, parent_class, entities)

    def extract_imports(self, tree: Tree, source_code: bytes, file_path: str) -> List[Import]:
        """Extract import statements to build dependency graph.

        Args:
            tree: Parsed tree-sitter Tree
            source_code: Original source code bytes
            file_path: Path to source file

        Returns:
            List of Import objects
        """
        imports = []
        root = tree.root_node

        for node in self._traverse(root):
            if node.type in self.import_node_types:
                import_info = self._extract_import_info(node, source_code)
                if import_info:
                    import_info.file_path = str(file_path)
                    imports.append(import_info)

        return imports

    def _traverse(self, node: Node):
        """Iteratively traverse tree using a stack and yield all nodes.

        Args:
            node: Root node to start traversal

        Yields:
            All nodes in tree
        """
        stack = [node]
        while stack:
            current = stack.pop()
            yield current
            # Add children in reverse order to maintain left-to-right traversal
            stack.extend(reversed(current.children))

    def _extract_name(self, node: Node) -> Optional[str]:
        """Extract name from function/class definition node.

        Args:
            node: Function or class definition node

        Returns:
            Name string, or None if not found
        """
        # Look for identifier child (name of function/class)
        for child in node.children:
            if child.type == 'identifier':
                return child.text.decode('utf-8', errors='ignore')
        return None

    def _extract_base_classes(self, node: Node, source_code: bytes) -> List[str]:
        """Extract base classes from class definition node.

        INHERITANCE MAPPER: Parses class Child(Base1, Base2) to extract ['Base1', 'Base2'].

        Args:
            node: Class definition node
            source_code: Original source code bytes

        Returns:
            List of base class names
        """
        base_classes = []

        # For Python: class_definition has argument_list child with base classes
        # For JS/TS: class_declaration has class_heritage child
        for child in node.children:
            if self.language == 'python':
                # Python: class Foo(Base1, Base2):
                # Structure: class_definition -> argument_list -> identifier/attribute
                if child.type == 'argument_list':
                    for arg_child in child.children:
                        if arg_child.type == 'identifier':
                            base_name = arg_child.text.decode('utf-8', errors='ignore')
                            base_classes.append(base_name)
                        elif arg_child.type == 'attribute':
                            # Handle qualified names like module.BaseClass
                            base_name = source_code[arg_child.start_byte:arg_child.end_byte].decode('utf-8', errors='ignore')
                            base_classes.append(base_name)
            elif self.language in ('javascript', 'typescript'):
                # JS/TS: class Foo extends Bar
                if child.type == 'class_heritage':
                    for heritage_child in child.children:
                        if heritage_child.type == 'identifier':
                            base_name = heritage_child.text.decode('utf-8', errors='ignore')
                            base_classes.append(base_name)

        return base_classes

    def _extract_decorators(self, node: Node, source_code: bytes) -> List[str]:
        """Extract decorator names from decorated_definition node.

        v4.2.0: METADATA PRESERVATION - Extracts @property, @staticmethod, @lru_cache, etc.

        Args:
            node: decorated_definition node (parent of function/class)
            source_code: Original source code bytes

        Returns:
            List of decorator strings (e.g., ['@property', '@staticmethod'])
        """
        decorators = []

        # Only Python supports decorators via decorated_definition
        if self.language == 'python' and node.type == 'decorated_definition':
            # decorated_definition children: [decorator, decorator, ..., function_definition]
            for child in node.children:
                if child.type == 'decorator':
                    # Extract full decorator text (e.g., '@lru_cache(maxsize=128)')
                    decorator_text = source_code[child.start_byte:child.end_byte].decode('utf-8', errors='ignore')
                    decorators.append(decorator_text.strip())

        return decorators

    def _extract_import_info(self, node: Node, source_code: bytes) -> Optional[Import]:
        """Extract import information from import node.

        Args:
            node: Import statement node
            source_code: Original source code bytes

        Returns:
            Import object, or None if extraction failed
        """
        if self.language == 'python':
            return self._extract_python_import(node, source_code)
        elif self.language in ('javascript', 'typescript'):
            return self._extract_js_import(node, source_code)
        return None

    def _extract_python_import(self, node: Node, source_code: bytes) -> Optional[Import]:
        """Extract Python import (import x, from x import y).

        Args:
            node: Python import node
            source_code: Original source code bytes

        Returns:
            Import object
        """
        module = None
        names = []
        is_relative = False

        if node.type == 'import_statement':
            # import os, sys
            # In import_statement, children are dotted_name or aliased_import
            # There is no 'module_name' field typically, just names to be imported.
            for child in node.children:
                if child.type == 'dotted_name' or child.type == 'identifier':
                    # For "import x", x is the module
                    module = child.text.decode('utf-8', errors='ignore')
                elif child.type == 'aliased_import':
                     if child.child_count > 0:
                        module = child.children[0].text.decode('utf-8', errors='ignore')

        elif node.type == 'import_from_statement':
            # from os.path import join OR from . import name
            
            # 1. Extract Module (using field name for robustness)
            module_node = node.child_by_field_name('module_name')
            if module_node:
                module_text = module_node.text.decode('utf-8', errors='ignore')
                module = module_text
                is_relative = module_text.startswith('.')
            
            # 2. Extract Names (imported symbols/modules)
            name_nodes = node.children_by_field_name('name')
            for child in name_nodes:
                if child.type == 'aliased_import':
                    # Extract original name from alias
                    original_name = child.child_by_field_name('name')
                    if original_name:
                        names.append(original_name.text.decode('utf-8', errors='ignore'))
                else:
                    # dotted_name or identifier
                    names.append(child.text.decode('utf-8', errors='ignore'))

        # NEW: Check for potential dynamic imports (strings only)
        # We handle this case by returning an Import even if it's not a standard import statement
        # This relies on the loop in extract_imports iterating ALL nodes.
        elif node.type == 'string':
             text = node.text.decode('utf-8', errors='ignore').strip('\'"')
             # Heuristic: Only consider strings that look like filenames (no spaces, no newlines)
             # and have reasonable length (e.g., > 2 chars)
             if 2 < len(text) < 50 and all(c.isalnum() or c in '._-' for c in text):
                 module = text
                 # Assume relative for dynamic imports to allow sibling resolution (e.g. 'schema' -> ./schema.py)
                 is_relative = True

        if not module:
            return None

        return Import(
            module=module,
            names=names,
            is_relative=is_relative,
            line_number=node.start_point[0] + 1,
            file_path=""  # Will be set by caller
        )

    def _extract_js_import(self, node: Node, source_code: bytes) -> Optional[Import]:
        """Extract JavaScript/TypeScript import.
        
        Handles:
        - import ... from "module"
        - import "module"
        - require("module")

        Args:
            node: JS/TS import node
            source_code: Original source code bytes

        Returns:
            Import object
        """
        module = None
        is_relative = False

        # Case 1: ES6 Import (import_statement)
        # Structure: (import_statement (import_clause (named_imports ...)) source: (string))
        # Or: (import_statement source: (string))
        if node.type == 'import_statement':
            # Look for the source string
            for child in node.children:
                if child.type == 'string':
                     module_text = child.text.decode('utf-8', errors='ignore').strip('\'"')
                     module = module_text
                     is_relative = module_text.startswith('./') or module_text.startswith('../')
                     break

        # Case 2: CommonJS Require (call_expression)
        # This usually appears inside variable_declarator, expression_statement, etc.
        # But extractor only visits nodes in IMPORT_TYPES list?
        # WAIT: 'import_statement' is in IMPORT_TYPES, but 'call_expression' is NOT.
        # We need to add 'call_expression' to IMPORT_TYPES for JS/TS in __init__? 
        # Or we rely on the fact that we might traverse and find call_expressions?
        # The 'extract_imports' method iterates only nodes in 'self.import_node_types'.
        # I MUST UPDATE IMPORT_TYPES dict in 'EntityExtractor' class definition first!
        # But wait, 'require' is a function call. It can be anywhere.
        # Ideally we should look for 'call_expression' where function name is 'require'.
        
        elif node.type == 'call_expression':
            # ensure function name is 'require'
            function_node = node.child_by_field_name('function')
            if function_node and function_node.text.decode('utf-8', errors='ignore') == 'require':
                args_node = node.child_by_field_name('arguments')
                if args_node and args_node.child_count > 0:
                     # Arguments is a list ( ... ). First child is usually '('. 
                     # We need the first argument which should be a string.
                     for arg in args_node.children:
                         if arg.type == 'string':
                             module_text = arg.text.decode('utf-8', errors='ignore').strip('\'"')
                             module = module_text
                             is_relative = module_text.startswith('./') or module_text.startswith('../')
                             break

        if not module:
            return None

        return Import(
            module=module,
            names=[],
            is_relative=is_relative,
            line_number=node.start_point[0] + 1,
            file_path=""  # Will be set by caller
        )
