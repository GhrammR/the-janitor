import tree_sitter
from typing import List, Set, Optional

class JSAdvancedHeuristics:
    """
    Implements advanced semantic analysis heuristics for JavaScript/TypeScript.
    Operates on Tree-sitter AST nodes to detect implicit usage patterns in 
    React, Express, and module exports.
    """

    def __init__(self, reference_tracker):
        """
        :param reference_tracker: Instance of ReferenceTracker. 
                                  Must expose .add_reference(name: str) 
                                  and .mark_immortal(name: str).
        """
        self.tracker = reference_tracker

    def apply_react_hook_heuristic(self, root_node: tree_sitter.Node, source_code: bytes, import_map: dict = None) -> None:
        """
        Heuristic 1: ReactHookProtection
        Scans useEffect, useCallback, useMemo.
        Any identifier inside the dependency array (2nd argument) is marked as a reference.

        v3.6.0: Now checks if the function originates from 'react' module (alias-aware).
        """
        if import_map is None:
            import_map = {}
        self._find_react_hooks(root_node, source_code, import_map)

    def _find_react_hooks(self, node: tree_sitter.Node, source_code: bytes, import_map: dict):
        """Recursively find React hooks and analyze dependency arrays.

        v3.6.0: Checks import origin to verify this is actually a React hook.
        """
        if node.type == 'call_expression':
            func_node = node.child_by_field_name('function')
            if func_node:
                func_name = func_node.text.decode('utf-8')

                # v3.6.0: SEMANTIC CHECK - Verify this is actually a React hook
                # Check if func_name is in import_map and originates from 'react'
                is_react_hook = False

                if func_name in import_map:
                    import_info = import_map[func_name]
                    # Check if it's from 'react' module
                    if import_info.source_module == 'react':
                        # Check if original name is a React hook (handles aliasing)
                        if import_info.original_name in {'useEffect', 'useCallback', 'useMemo'}:
                            is_react_hook = True
                elif func_name in {'useEffect', 'useCallback', 'useMemo'}:
                    # Fallback: If not in import_map, assume it's React (for untracked imports)
                    # This maintains backward compatibility
                    is_react_hook = True

                if is_react_hook:
                    args_node = node.child_by_field_name('arguments')
                    if args_node:
                        # React hooks: (callback, dependency_array)
                        # We look for the second argument, which should be an array
                        args = []
                        for child in args_node.children:
                            # Filter out parentheses and commas to get actual arguments
                            if child.type not in {',', '(', ')'}:
                                args.append(child)

                        if len(args) >= 2:
                            dep_array = args[1]
                            if dep_array.type == 'array':
                                self._scan_dependency_array(dep_array, source_code)

        # Recurse
        for child in node.children:
            self._find_react_hooks(child, source_code, import_map)

    def _scan_dependency_array(self, array_node: tree_sitter.Node, source_code: bytes):
        """Scans a React dependency array for identifiers."""
        for child in array_node.children:
            if child.type == 'identifier':
                name = child.text.decode('utf-8')
                self.tracker.add_reference(name)
            elif child.type not in {'[', ']', ','}:
                # Handle complex dependencies like obj.prop (recurse to find identifiers)
                self._scan_subtree_for_refs(child, source_code)

    def _scan_subtree_for_refs(self, node: tree_sitter.Node, source_code: bytes):
        """Helper to find identifiers in complex expressions."""
        if node.type == 'identifier':
            name = node.text.decode('utf-8')
            self.tracker.add_reference(name)
        for child in node.children:
            self._scan_subtree_for_refs(child, source_code)

    def apply_express_route_heuristic(self, root_node: tree_sitter.Node, source_code: bytes, import_map: dict = None) -> None:
        """
        Heuristic 2: ExpressMiddlewareProtection
        Scans for router.get(), app.post(), etc.
        Marks callback functions (identifiers passed as args) as IMMORTAL.

        v3.6.0: Now checks if the object originates from 'express' module (alias-aware).
        """
        if import_map is None:
            import_map = {}
        self._find_express_routes(root_node, source_code, import_map)

    def _find_express_routes(self, node: tree_sitter.Node, source_code: bytes, import_map: dict):
        """Recursively find Express route definitions.

        v3.6.0: Checks import origin to verify this is actually an Express app/router.
        """
        if node.type == 'call_expression':
            func_node = node.child_by_field_name('function')
            if func_node and func_node.type == 'member_expression':
                # Check for app.get, router.post, etc.
                property_node = func_node.child_by_field_name('property')
                object_node = func_node.child_by_field_name('object')

                if property_node and object_node:
                    method_name = property_node.text.decode('utf-8')
                    object_name = object_node.text.decode('utf-8')

                    if method_name in {'get', 'post', 'put', 'delete', 'patch', 'use', 'all'}:
                        # v3.6.0: SEMANTIC CHECK - Verify this is actually Express
                        is_express = False

                        if object_name in import_map:
                            import_info = import_map[object_name]
                            # Check if it's from 'express' module
                            if import_info.source_module == 'express':
                                is_express = True
                        elif object_name in {'app', 'router'}:
                            # Fallback: If not in import_map, assume it's Express (backward compatibility)
                            is_express = True

                        if is_express:
                            self._mark_express_callbacks(node, source_code)

        # Recurse
        for child in node.children:
            self._find_express_routes(child, source_code, import_map)

    def _mark_express_callbacks(self, call_node: tree_sitter.Node, source_code: bytes):
        """Marks arguments of Express routes as immortal if they are identifiers."""
        args_node = call_node.child_by_field_name('arguments')
        if not args_node:
            return

        # Iterate through arguments. 
        # Usually arg 0 is the path (string), subsequent args are middlewares/handlers.
        # We mark all identifier arguments as immortal.
        for child in args_node.children:
            if child.type == 'identifier':
                name = child.text.decode('utf-8')
                self.tracker.mark_immortal(name, "Express Route Handler")

    def apply_export_heuristic(self, root_node: tree_sitter.Node, source_code: bytes, library_mode: bool = False) -> None:
        """
        Heuristic 3: ExportProtection
        Marks exported symbols as IMMORTAL based on the mode.
        
        :param library_mode: If True, all exports (named and default) are immortal.
                             If False, only 'export default' is immortal.
        """
        self._find_exports(root_node, source_code, library_mode)

    def _find_exports(self, node: tree_sitter.Node, source_code: bytes, library_mode: bool):
        """Recursively find export statements and apply protection rules."""
        
        if node.type == 'export_statement':
            # Determine if this is a default export
            is_default = False
            for child in node.children:
                if child.text.decode('utf-8') == 'default':
                    is_default = True
                    break
            
            if is_default:
                # Always protect default exports (Application Entry Point or Library Default)
                for child in node.children:
                    if child.type == 'identifier':
                        # export default x;
                        self.tracker.mark_immortal(child.text.decode('utf-8'), "Export Default")
                    elif child.type in {'function_declaration', 'class_declaration'}:
                        # export default function x() {}
                        name_node = child.child_by_field_name('name')
                        if name_node:
                            self.tracker.mark_immortal(name_node.text.decode('utf-8'), "Export Default")
            
            elif library_mode:
                # Only protect named exports if we are in Library Mode.
                # In Application Mode, named exports are subject to tree-shaking (reference counting).
                for child in node.children:
                    if child.type == 'export_clause':
                        # export { x, y }
                        self._process_export_clause(child, source_code)
                    elif child.type == 'lexical_declaration':
                        # export const x = ...
                        self._process_declaration(child, source_code)
                    elif child.type in {'function_declaration', 'class_declaration'}:
                        # export function x() ...
                        name_node = child.child_by_field_name('name')
                        if name_node:
                            self.tracker.mark_immortal(name_node.text.decode('utf-8'), "Export Declaration")

        # Recurse
        for child in node.children:
            self._find_exports(child, source_code, library_mode)

    def _process_export_clause(self, clause_node: tree_sitter.Node, source_code: bytes):
        """Handle export { A, B as C }."""
        for child in clause_node.children:
            if child.type == 'export_specifier':
                # Check for 'name' field (the local name)
                name_node = child.child_by_field_name('name')
                if name_node:
                    self.tracker.mark_immortal(name_node.text.decode('utf-8'), "Named Export")
                else:
                    # Sometimes simple specifiers are just identifiers in children
                    for spec_child in child.children:
                        if spec_child.type == 'identifier':
                            # If there's an 'as', we want the first identifier (local)
                            # But usually child_by_field_name('name') handles this.
                            # Fallback for simple { A }
                            self.tracker.mark_immortal(spec_child.text.decode('utf-8'), "Named Export")
                            break

    def _process_declaration(self, decl_node: tree_sitter.Node, source_code: bytes):
        """Handle export const x = 1, let y = 2."""
        for child in decl_node.children:
            if child.type == 'variable_declarator':
                name_node = child.child_by_field_name('name')
                if name_node and name_node.type == 'identifier':
                    self.tracker.mark_immortal(name_node.text.decode('utf-8'), "Exported Variable")
                elif name_node and name_node.type in {'array_pattern', 'object_pattern'}:
                    # Destructuring export: export const { a, b } = obj
                    self._mark_destructured_immortal(name_node, source_code)

    def _mark_destructured_immortal(self, pattern_node: tree_sitter.Node, source_code: bytes):
        """Recursively mark identifiers in destructuring patterns as immortal."""
        if pattern_node.type == 'identifier':
            self.tracker.mark_immortal(pattern_node.text.decode('utf-8'), "Exported Destructured")
        
        for child in pattern_node.children:
            # Skip punctuation and property keys in object patterns (shorthand property_identifier is tricky)
            if child.type == 'shorthand_property_identifier':
                self.tracker.mark_immortal(child.text.decode('utf-8'), "Exported Destructured")
            elif child.type not in {':', '{', '}', '[', ']', ','}:
                self._mark_destructured_immortal(child, source_code)