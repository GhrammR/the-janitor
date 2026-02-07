from pathlib import Path
from functools import lru_cache
from typing import Optional, Dict, List, Any, Union
import os

class SymbolResolver:
    """
    Compiler-level symbol resolution engine.
    Resolves import strings to absolute file paths on disk based on language semantics.
    """

    def __init__(self, project_root: Path, tsconfig_paths: Dict[str, List[str]] = None):
        self.root = project_root.resolve()
        # Normalize tsconfig paths: {"@app/*": ["src/*"]} -> {"@app": "src"}
        self.ts_aliases = {}
        if tsconfig_paths:
            for alias, targets in tsconfig_paths.items():
                clean_alias = alias.replace("/*", "")
                # We take the first target for simplicity in this implementation
                if targets:
                    clean_target = targets[0].replace("/*", "")
                    self.ts_aliases[clean_alias] = clean_target

    def resolve_source_file(self, current_file: Path, import_string: str) -> Optional[Path]:
        """
        Determines the absolute file path of an imported module.
        
        Args:
            current_file: The absolute path of the file containing the import.
            import_string: The string used in the import statement (e.g., './utils', 'django.db').
        """
        if not import_string:
            return None

        # Determine language context based on current file extension
        ext = current_file.suffix.lower()
        
        if ext in {'.py', '.pyi'}:
            return self._resolve_python_import(current_file, import_string)
        elif ext in {'.js', '.jsx', '.ts', '.tsx'}:
            return self._resolve_js_import(current_file, import_string)
        
        return None

    def resolve_symbol_source(self, current_file: Path, symbol_name: str, import_node: Any = None) -> Optional[Path]:
        """
        Resolves the file defining a specific symbol.
        
        In many cases, this delegates to resolve_source_file. However, for Python
        'from x import y', 'y' might be a submodule (file) or a variable in 'x' (file).
        """
        # Heuristic: If we have an import node (AST), we can extract the module string.
        # Assuming import_node has a 'module' attribute or similar for this exercise.
        # If import_node is None, we assume import_string was passed elsewhere or we infer.
        
        # This is a simplified interface implementation. In a real compiler, 
        # we would parse the import_node to get the module path.
        # Here we assume the caller uses resolve_source_file for the module, 
        # but we handle the specific Python ambiguity of "import x.y".
        
        # If this is purely a symbol lookup inside a known file, we return the file itself
        # unless logic dictates it's a re-export (which requires AST parsing not available here).
        
        # For the purpose of this task, we treat the symbol resolution as finding the 
        # file where the symbol *module* lives.
        
        return self.resolve_source_file(current_file, symbol_name)

    # -------------------------------------------------------------------------
    # Python Resolution Logic
    # -------------------------------------------------------------------------

    def _resolve_python_import(self, current_file: Path, import_string: str) -> Optional[Path]:
        """
        Handles Python absolute and relative imports.
        """
        # Handle Relative Imports (starting with .)
        if import_string.startswith('.'):
            return self._resolve_python_relative(current_file, import_string)
        
        # Handle Absolute Imports
        return self._resolve_python_absolute(import_string)

    def _resolve_python_relative(self, current_file: Path, import_string: str) -> Optional[Path]:
        dots = 0
        for char in import_string:
            if char == '.':
                dots += 1
            else:
                break
        
        module_part = import_string[dots:]
        
        # Calculate base directory
        # 1 dot = current dir, 2 dots = parent, etc.
        # current_file is /a/b/c.py. 
        # from . import x -> base is /a/b
        base_dir = current_file.parent
        for _ in range(dots - 1):
            base_dir = base_dir.parent

        if not module_part:
            # Case: "from . import x" -> import_string is "." (handled by caller usually passing module)
            # If import_string is just dots, it resolves to the __init__.py of that dir
            return self._check_python_path(base_dir)

        # Convert dot notation to path
        rel_path = module_part.replace('.', '/')
        candidate = base_dir / rel_path
        return self._check_python_path(candidate)

    def _resolve_python_absolute(self, import_string: str) -> Optional[Path]:
        # Convert dot notation to path
        rel_path = import_string.replace('.', '/')
        candidate = self.root / rel_path
        return self._check_python_path(candidate)

    def _check_python_path(self, path_no_ext: Path) -> Optional[Path]:
        # 1. Check as file
        file_py = path_no_ext.with_suffix('.py')
        if file_py.exists():
            return file_py
        
        # 2. Check as package
        init_py = path_no_ext / '__init__.py'
        if init_py.exists():
            return init_py
            
        return None

    # -------------------------------------------------------------------------
    # JS/TS Resolution Logic
    # -------------------------------------------------------------------------

    def _resolve_js_import(self, current_file: Path, import_string: str) -> Optional[Path]:
        """
        Handles JS/TS relative paths, aliases, and node_module resolution style.
        """
        # 1. Relative Imports
        if import_string.startswith('.'):
            candidate = (current_file.parent / import_string).resolve()
            return self._probe_js_path(candidate)

        # 2. Path Aliases (tsconfig)
        # Check if import matches a defined alias
        for alias, target in self.ts_aliases.items():
            if import_string.startswith(alias):
                # Replace alias with target path
                remainder = import_string[len(alias):]
                if remainder.startswith('/'):
                    remainder = remainder[1:]
                
                candidate = self.root / target / remainder
                return self._probe_js_path(candidate)

        # 3. Absolute / Node Modules (simplified)
        # In a monorepo or src-root setup, imports might be relative to baseUrl
        candidate = self.root / import_string
        return self._probe_js_path(candidate)

    def _probe_js_path(self, path: Path) -> Optional[Path]:
        """
        Probes for file existence using JS resolution rules:
        1. Exact match
        2. Extensions (.ts, .tsx, .js, .jsx)
        3. Directory index files
        """
        extensions = ['.ts', '.tsx', '.d.ts', '.js', '.jsx', '.json']

        # Case A: Path refers to a file (try extensions)
        for ext in [''] + extensions:
            # If path has extension, '' covers it. If not, we append.
            if ext == '' and path.suffix == '':
                continue # Skip empty extension if file has no suffix, proceed to append extensions
            
            candidate = path.with_suffix(path.suffix + ext) if ext else path
            if candidate.is_file():
                return candidate

        # Case B: Path refers to a directory (look for index)
        if path.is_dir():
            for ext in extensions:
                index_file = path / f"index{ext}"
                if index_file.is_file():
                    return index_file

        return None