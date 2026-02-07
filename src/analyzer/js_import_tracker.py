from dataclasses import dataclass
from typing import Dict, Optional, Union, List

@dataclass
class ImportInfo:
    source_module: str
    original_name: Optional[str] = None
    is_namespace: bool = False

class JSImportTracker:
    def analyze_imports(self, root_node, source_code: Union[str, bytes]) -> Dict[str, ImportInfo]:
        """
        Analyzes a Tree-sitter root node to map local variables to their import sources.
        """
        if isinstance(source_code, str):
            source_code = source_code.encode('utf-8')

        imports: Dict[str, ImportInfo] = {}

        def get_text(node) -> str:
            return source_code[node.start_byte : node.end_byte].decode('utf-8')

        def strip_quotes(text: str) -> str:
            return text.strip('"\'`')

        # Stack for traversal
        stack = [root_node]

        while stack:
            node = stack.pop()

            # 1. Handle ESM Import Statements
            if node.type == 'import_statement':
                source_node = node.child_by_field_name('source')
                if not source_node:
                    continue
                
                module_name = strip_quotes(get_text(source_node))
                import_clause = node.child_by_field_name('clause')
                
                if import_clause:
                    # Iterate over children of the clause to handle cases like:
                    # import x, { y } from 'mod' (Default + Named)
                    # import * as ns from 'mod' (Namespace)
                    # import x from 'mod' (Default)
                    
                    # In tree-sitter-javascript, import_clause wraps the specific import types
                    # We iterate its named children to catch identifiers (default) or specific structures
                    for child in import_clause.named_children:
                        
                        # Case: Default Import (e.g., import x from 'mod')
                        # The child is a direct identifier inside the clause
                        if child.type == 'identifier':
                            local_name = get_text(child)
                            imports[local_name] = ImportInfo(
                                source_module=module_name,
                                original_name='default',
                                is_namespace=False
                            )

                        # Case: Namespace Import (e.g., import * as ns from 'mod')
                        elif child.type == 'namespace_import':
                            # structure: * as identifier
                            for ns_child in child.named_children:
                                if ns_child.type == 'identifier':
                                    local_name = get_text(ns_child)
                                    imports[local_name] = ImportInfo(
                                        source_module=module_name,
                                        original_name=None,
                                        is_namespace=True
                                    )

                        # Case: Named Imports (e.g., import { x, y as z } from 'mod')
                        elif child.type == 'named_imports':
                            for specifier in child.named_children:
                                if specifier.type == 'import_specifier':
                                    # Check for aliasing: import { name as alias }
                                    name_node = specifier.child_by_field_name('name')
                                    alias_node = specifier.child_by_field_name('alias')
                                    
                                    original = get_text(name_node)
                                    
                                    if alias_node:
                                        local_name = get_text(alias_node)
                                        imports[local_name] = ImportInfo(
                                            source_module=module_name,
                                            original_name=original,
                                            is_namespace=False
                                        )
                                    else:
                                        # No alias, local name equals original name
                                        imports[original] = ImportInfo(
                                            source_module=module_name,
                                            original_name=original,
                                            is_namespace=False
                                        )

            # 2. Handle CommonJS Require (const x = require('mod'))
            # Look for variable declarations
            elif node.type in ('lexical_declaration', 'variable_declaration'):
                for declarator in node.named_children:
                    if declarator.type == 'variable_declarator':
                        name_node = declarator.child_by_field_name('name')
                        value_node = declarator.child_by_field_name('value')

                        # Ensure we have a name and a value, and the value is a function call
                        if (name_node and value_node and 
                            value_node.type == 'call_expression'):
                            
                            function_node = value_node.child_by_field_name('function')
                            args_node = value_node.child_by_field_name('arguments')

                            # Check if function is 'require'
                            if (function_node and get_text(function_node) == 'require' and 
                                args_node and args_node.named_child_count > 0):
                                
                                first_arg = args_node.named_children[0]
                                if first_arg.type == 'string':
                                    module_name = strip_quotes(get_text(first_arg))
                                    
                                    # Handle simple identifier assignment: const x = require(...)
                                    if name_node.type == 'identifier':
                                        local_name = get_text(name_node)
                                        imports[local_name] = ImportInfo(
                                            source_module=module_name,
                                            original_name=None, # CommonJS export object
                                            is_namespace=False
                                        )

            # Continue traversal
            # We push named children to the stack to traverse nested scopes (e.g. require inside functions)
            # We reverse to process in order, though order doesn't strictly matter for this map
            stack.extend(reversed(node.named_children))

        return imports