from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser, Node, Query, QueryCursor

class JSSymbolRemover:
    """
    Removes specified JS/TS symbols (functions, classes, variables) from source files
    using Tree-sitter for precise AST-based deletion.
    """

    def __init__(self):
        # Initialize languages using tree-sitter v0.25+ structure
        # CRITICAL: Wrap PyCapsule with Language() for v0.25+ API
        # The .language() functions return PyCapsule (opaque C pointers),
        # which must be wrapped with Language() to use query() and other methods.
        self.js_lang = Language(tree_sitter_javascript.language())
        self.ts_lang = Language(tree_sitter_typescript.language_typescript())
        self.tsx_lang = Language(tree_sitter_typescript.language_tsx())

        self.parsers = {
            "js": Parser(self.js_lang),
            "ts": Parser(self.ts_lang),
            "tsx": Parser(self.tsx_lang),
        }

        # Query to find identifiers that might define symbols
        # We find the identifier, then traverse up to find the declaration statement
        self.query_str = """
        (identifier) @id
        (property_identifier) @id
        """

    def remove_symbols_batch(
        self, file_symbols: Dict[Path, List], file_contents: Dict[Path, str]
    ) -> Dict[Path, Tuple[str, int]]:
        """
        Batch processes files to remove specified symbols.

        Args:
            file_symbols: Mapping of file path to list of symbols to remove.
                         Each symbol can be a string (symbol name) or an Entity object.
            file_contents: Mapping of file path to raw content string.

        Returns:
            Dict mapping Path to (modified_source_code, number_of_removals).
        """
        results = {}

        for file_path, symbols_to_remove in file_symbols.items():
            if not symbols_to_remove or file_path not in file_contents:
                continue

            content = file_contents[file_path]
            parser_type = self._get_parser_type(file_path)
            
            if not parser_type:
                results[file_path] = (content, 0)
                continue

            # Extract symbol names from Entity objects or use strings directly
            symbol_names = []
            for sym in symbols_to_remove:
                if hasattr(sym, 'name'):
                    # It's an Entity object
                    symbol_names.append(sym.name)
                else:
                    # It's a string
                    symbol_names.append(str(sym))

            modified_content, count = self._process_file(
                content, symbol_names, self.parsers[parser_type], parser_type
            )
            results[file_path] = (modified_content, count)

        return results

    def _get_parser_type(self, path: Path) -> Optional[str]:
        ext = path.suffix.lower()
        if ext in {".js", ".mjs", ".cjs", ".jsx"}:
            return "js"
        elif ext in {".ts", ".mts", ".cts"}:
            return "ts"
        elif ext == ".tsx":
            return "tsx"
        return None

    def _process_file(
        self, source_code: str, symbols: List[str], parser: Parser, parser_type: str
    ) -> Tuple[str, int]:
        source_bytes = source_code.encode("utf8")
        tree = parser.parse(source_bytes)
        root = tree.root_node
        
        # Select appropriate language for query
        lang = (
            self.tsx_lang if parser_type == "tsx" 
            else self.ts_lang if parser_type == "ts" 
            else self.js_lang
        )
        
        # tree-sitter v0.25+ API: Use Query constructor and QueryCursor
        # Note: lang.query() is deprecated, use Query(lang, query_str) instead
        query = Query(lang, self.query_str)
        cursor = QueryCursor(query=query)
        # captures() returns dict[str, list[Node]] where keys are capture names
        captures = cursor.captures(root)
        
        target_symbols = set(symbols)
        ranges_to_remove: List[Tuple[int, int]] = []

        # 1. Identify nodes to remove
        # captures is a dict mapping capture names to lists of nodes
        for capture_name, nodes in captures.items():
            for node in nodes:
                node_text = node.text.decode("utf8")
                if node_text in target_symbols:
                    removal_range = self._find_definition_range(node, root)
                    if removal_range:
                        ranges_to_remove.append(removal_range)

        if not ranges_to_remove:
            return source_code, 0

        # 2. Merge overlapping ranges (Logic: Union of intervals)
        # Sort by start byte ascending to merge
        ranges_to_remove.sort(key=lambda x: x[0])
        
        merged_ranges = []
        if ranges_to_remove:
            current_start, current_end = ranges_to_remove[0]
            for next_start, next_end in ranges_to_remove[1:]:
                if next_start < current_end:  # Overlap or adjacent
                    current_end = max(current_end, next_end)
                else:
                    merged_ranges.append((current_start, current_end))
                    current_start, current_end = next_start, next_end
            merged_ranges.append((current_start, current_end))

        # 3. Extend ranges to clean up trailing newlines
        final_ranges = []
        for start, end in merged_ranges:
            start, end = self._extend_range_for_newline(source_bytes, start, end)
            final_ranges.append((start, end))

        # 4. Apply deletions in DESCENDING order to preserve offsets
        final_ranges.sort(key=lambda x: x[0], reverse=True)
        
        modified_bytes = bytearray(source_bytes)
        removed_count = len(final_ranges)

        for start, end in final_ranges:
            # Slice out the bytes
            del modified_bytes[start:end]

        return modified_bytes.decode("utf8"), removed_count

    def _find_definition_range(self, identifier_node: Node, root: Node) -> Optional[Tuple[int, int]]:
        """
        Traverses up from an identifier to find the removable statement/declaration.
        Handles exports and multiple variable declarators.
        """
        current = identifier_node
        
        # Parent types that represent a full declaration statement
        declaration_types = {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "method_definition",
            "lexical_declaration", # let, const
            "variable_declaration", # var
            "interface_declaration",
            "type_alias_declaration",
            "enum_declaration"
        }

        # Traverse up to find the declaration
        target_node = None
        while current and current.parent:
            parent = current.parent
            p_type = parent.type
            
            # Case: Function, Class, Method, Type, Interface
            if p_type in declaration_types:
                target_node = parent
                break
            
            # Case: Variable Declarator (e.g., const x = 1)
            # We need to check if it's inside a list (const x=1, y=2)
            if p_type == "variable_declarator":
                grandparent = parent.parent
                if grandparent and grandparent.type in {"lexical_declaration", "variable_declaration"}:
                    # If it's the only declarator, remove the whole statement
                    if grandparent.named_child_count == 1:
                        target_node = grandparent
                    else:
                        # Multiple declarators: removing just one is risky with simple byte slicing 
                        # due to commas. For this specific implementation, we remove just the declarator
                        # but we must be careful with commas. 
                        # Production-Grade Fallback: Target the specific declarator.
                        # Cleanup of commas is hard without re-parsing, but we will return the declarator range.
                        target_node = parent
                break
            
            # Stop if we hit block or program boundaries to prevent deleting too much
            if p_type in {"program", "statement_block", "class_body"}:
                break
                
            current = parent

        if not target_node:
            return None

        # Check if the declaration is exported
        if target_node.parent and target_node.parent.type == "export_statement":
            target_node = target_node.parent

        return (target_node.start_byte, target_node.end_byte)

    def _extend_range_for_newline(self, source_bytes: bytes, start: int, end: int) -> Tuple[int, int]:
        """
        Adjusts the end index to consume a trailing newline if present,
        ensuring we don't leave empty lines behind.
        """
        length = len(source_bytes)
        
        # Check bytes immediately following the node
        current = end
        
        # Consume optional carriage return
        if current < length and source_bytes[current] == 13: # \r
            current += 1
            
        # Consume newline
        if current < length and source_bytes[current] == 10: # \n
            current += 1
            return (start, current)
            
        return (start, end)