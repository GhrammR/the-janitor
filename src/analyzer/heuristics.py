import tree_sitter
from tree_sitter import Language
import tree_sitter_python as tspython
from typing import List, Set, Optional

class AdvancedHeuristics:
    """
    Implements advanced semantic analysis heuristics for 'The Janitor' ReferenceTracker.
    Operates on Tree-sitter AST nodes to detect implicit usage patterns in 
    modern Python frameworks (Pydantic, FastAPI, SQLAlchemy).
    """

    def __init__(self, reference_tracker):
        """
        :param reference_tracker: Instance of ReferenceTracker. 
                                  Must expose .add_reference(name: str) 
                                  and .mark_immortal(name: str).
        """
        self.tracker = reference_tracker

    def apply_pydantic_forward_ref_heuristic(self, root_node: tree_sitter.Node, source_code: bytes) -> None:
        """
        Heuristic 1: PydanticForwardRefHeuristic
        Scans type annotations for string literals (e.g., x: List['User']).
        Extracts the inner string content and marks it as a reference.
        """
        # Manual tree traversal to find string literals in type contexts
        self._find_forward_refs(root_node, source_code)

    def _find_forward_refs(self, node: tree_sitter.Node, source_code: bytes):
        """Recursively find string literals in type annotation contexts."""
        # Check if this is a type node containing a string
        if node.type == 'type':
            for child in node.children:
                if child.type == 'string':
                    # Extract text, e.g., "'User'" or '"User"'
                    raw_text = child.text.decode('utf-8')
                    # Strip quotes to get the class name
                    class_name = raw_text.strip("'\"")

                    if class_name and class_name.isidentifier():
                        self.tracker.add_reference(class_name)
                        return

        # Recurse into children
        for child in node.children:
            self._find_forward_refs(child, source_code)

    def apply_lifespan_teardown_heuristic(self, root_node: tree_sitter.Node, source_code: bytes) -> None:
        """
        Heuristic 2: LifespanTeardownHeuristic
        Identifies @asynccontextmanager functions. Marks symbols used lexically
        after the 'yield' keyword as IMMORTAL (critical for teardown logic).
        """
        # Manual traversal to find @asynccontextmanager decorated functions
        self._find_asynccontextmanager_functions(root_node, source_code)

    def _find_asynccontextmanager_functions(self, node: tree_sitter.Node, source_code: bytes):
        """Recursively find functions decorated with @asynccontextmanager."""
        if node.type == 'decorated_definition':
            # Check if decorated with @asynccontextmanager
            has_asynccontextmanager = False
            func_body = None

            for child in node.children:
                if child.type == 'decorator':
                    # Check decorator content
                    for dec_child in child.children:
                        if dec_child.type == 'identifier':
                            dec_name = dec_child.text.decode('utf-8')
                            if dec_name == 'asynccontextmanager':
                                has_asynccontextmanager = True
                elif child.type == 'function_definition':
                    # Find the function body
                    for func_child in child.children:
                        if func_child.type == 'block':
                            func_body = func_child
                            break

            if has_asynccontextmanager and func_body:
                # Locate the yield statement within the function body
                yield_node = self._find_yield_node(func_body)
                if yield_node:
                    # Traverse everything lexically after the yield statement
                    start_scanning = False
                    for child in func_body.children:
                        if child.id == yield_node.id:
                            start_scanning = True
                            continue

                        if start_scanning:
                            self._mark_identifiers_in_subtree_immortal(child, source_code)

        # Recurse into children
        for child in node.children:
            self._find_asynccontextmanager_functions(child, source_code)

    def apply_polymorphic_orm_heuristic(self, root_node: tree_sitter.Node, source_code: bytes) -> None:
        """
        Heuristic 3: PolymorphicORMHeuristic
        Scans for classes defining '__mapper_args__'.
        Marks the class itself as IMMORTAL, as it is dynamically instantiated
        by the SQLAlchemy ORM registry based on polymorphic discriminators.
        """
        # Manual traversal to find classes with __mapper_args__
        self._find_orm_polymorphic_classes(root_node, source_code)

    def _find_orm_polymorphic_classes(self, node: tree_sitter.Node, source_code: bytes):
        """Recursively find classes with __mapper_args__."""
        if node.type == 'class_definition':
            class_name = None
            has_mapper_args = False

            for child in node.children:
                if child.type == 'identifier' and class_name is None:
                    # First identifier is the class name
                    class_name = child.text.decode('utf-8')
                elif child.type == 'block':
                    # Check class body for __mapper_args__
                    has_mapper_args = self._has_mapper_args(child, source_code)

            if class_name and has_mapper_args:
                self.tracker.mark_immortal(class_name, "Polymorphic ORM (__mapper_args__)")

        # Recurse into children
        for child in node.children:
            self._find_orm_polymorphic_classes(child, source_code)

    def _has_mapper_args(self, block_node: tree_sitter.Node, source_code: bytes) -> bool:
        """Check if a class block contains __mapper_args__ assignment."""
        for child in block_node.children:
            if child.type == 'expression_statement':
                for expr_child in child.children:
                    if expr_child.type == 'assignment':
                        # Check if left side is __mapper_args__
                        for assign_child in expr_child.children:
                            if assign_child.type == 'identifier':
                                name = assign_child.text.decode('utf-8')
                                if name == '__mapper_args__':
                                    return True
            # Recurse into nested blocks
            if self._has_mapper_args(child, source_code):
                return True
        return False

    # --- Internal Helpers ---

    def _find_yield_node(self, block_node: tree_sitter.Node) -> Optional[tree_sitter.Node]:
        """Recursively searches for the first yield statement in a block."""
        if block_node.type == 'yield_statement':
            return block_node
        
        for child in block_node.children:
            found = self._find_yield_node(child)
            if found:
                return found
        return None

    def _mark_identifiers_in_subtree_immortal(self, node: tree_sitter.Node, source_code: bytes) -> None:
        """Recursively finds identifiers in a subtree and marks them immortal."""
        if node.type == 'identifier':
            name = node.text.decode('utf-8')
            self.tracker.mark_immortal(name)
        
        for child in node.children:
            self._mark_identifiers_in_subtree_immortal(child, source_code)