"""Symbol remover for surgically removing dead functions/classes from files."""
from pathlib import Path
from typing import List, Set
import libcst as cst
from libcst import matchers as m

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzer.extractor import Entity


class SymbolRemovalTransformer(cst.CSTTransformer):
    """LibCST transformer to remove specific functions/classes."""

    def __init__(self, symbols_to_remove: Set[str]):
        """Initialize transformer.

        Args:
            symbols_to_remove: Set of symbol names to remove
        """
        self.symbols_to_remove = symbols_to_remove
        self.removed_count = 0

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.RemovalSentinel | cst.FunctionDef:
        """Remove function if it's in the removal set.

        Args:
            original_node: Original function node
            updated_node: Updated function node

        Returns:
            RemovalSentinel to remove the node, or the node itself to keep it
        """
        func_name = updated_node.name.value
        if func_name in self.symbols_to_remove:
            self.removed_count += 1
            return cst.RemovalSentinel.REMOVE
        return updated_node

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.RemovalSentinel | cst.ClassDef:
        """Remove class if it's in the removal set.

        Args:
            original_node: Original class node
            updated_node: Updated class node

        Returns:
            RemovalSentinel to remove the node, or the node itself to keep it
        """
        class_name = updated_node.name.value
        if class_name in self.symbols_to_remove:
            self.removed_count += 1
            return cst.RemovalSentinel.REMOVE
        return updated_node


class SymbolRemover:
    """Removes dead symbols from source files while preserving structure."""

    def __init__(self):
        """Initialize symbol remover."""
        pass

    def remove_symbols_from_file(
        self, file_path: Path, symbols: List[Entity], source_code: str = None
    ) -> tuple[str, int]:
        """Remove specific symbols from a Python file.

        Args:
            file_path: Path to the file
            symbols: List of Entity objects to remove
            source_code: Optional source code (if None, reads from file_path)

        Returns:
            Tuple of (modified_code, removed_count)

        Raises:
            ValueError: If file is not a Python file
            IOError: If file cannot be read
        """
        if file_path.suffix != '.py':
            raise ValueError(f"Only Python files supported, got: {file_path}")

        # Read the file (if source_code not provided)
        if source_code is None:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

        # Parse with LibCST
        try:
            module = cst.parse_module(source_code)
        except cst.ParserSyntaxError as e:
            raise ValueError(f"Failed to parse {file_path}: {e}")

        # Create set of symbol names to remove
        symbols_to_remove = {entity.name for entity in symbols}

        # Transform the code
        transformer = SymbolRemovalTransformer(symbols_to_remove)
        modified_module = module.visit(transformer)

        # Generate modified code
        modified_code = modified_module.code

        return modified_code, transformer.removed_count

    def remove_symbols_batch(
        self, symbols_by_file: dict[Path, List[Entity]], file_contents: dict[Path, str] = None
    ) -> dict[Path, tuple[str, int]]:
        """Remove symbols from multiple files.

        Args:
            symbols_by_file: Dictionary mapping file paths to lists of symbols to remove
            file_contents: Optional dictionary mapping file paths to source code

        Returns:
            Dictionary mapping file paths to (modified_code, removed_count) tuples
        """
        results = {}

        for file_path, symbols in symbols_by_file.items():
            try:
                # Get source code from file_contents if provided
                source_code = file_contents.get(file_path) if file_contents else None

                modified_code, removed_count = self.remove_symbols_from_file(
                    file_path, symbols, source_code=source_code
                )
                results[file_path] = (modified_code, removed_count)
            except (ValueError, IOError) as e:
                # Log error but continue with other files
                print(f"Error removing symbols from {file_path}: {e}")
                continue

        return results
