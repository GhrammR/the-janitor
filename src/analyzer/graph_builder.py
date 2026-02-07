"""Dependency graph builder using NetworkX.

TURBO UPGRADE: Cache-aware graph building for instant dependency resolution.
"""
from pathlib import Path
from typing import List, Optional, Set
import networkx as nx
from .parser import LanguageParser
from .extractor import EntityExtractor, Import
from .cache import AnalysisCache


class DependencyGraphBuilder:
    """Build directed dependency graph for project files."""

    def __init__(self, project_root: str | Path = "."):
        """Initialize graph builder.

        Args:
            project_root: Root directory of project to analyze
        """
        self.project_root = Path(project_root).resolve()
        self.graph = nx.DiGraph()
        # TURBO: Initialize cache for low-latency lookups
        self.cache = AnalysisCache(self.project_root)

    def build_graph(self, file_patterns: Optional[List[str]] = None) -> nx.DiGraph:
        """Build dependency graph for entire project.

        Creates directed graph where edge (A, B) means "file A imports file B".

        TURBO: Uses cached dependencies to avoid re-parsing unchanged files.

        Args:
            file_patterns: Optional list of file patterns to include (e.g., ['*.py'])
                          If None, uses default patterns for supported languages

        Returns:
            NetworkX DiGraph with file dependencies
        """
        if file_patterns is None:
            file_patterns = ['**/*.py', '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx']

        # Discover all source files
        all_files = self._discover_files(file_patterns)

        # Process files (using cache where possible)
        for file_path in all_files:
            self._process_file(file_path)

        return self.graph

    def _discover_files(self, patterns: List[str]) -> Set[Path]:
        """Discover all source files matching patterns.

        Args:
            patterns: Glob patterns to match

        Returns:
            Set of Path objects for all matching files
        """
        files = set()
        for pattern in patterns:
            files.update(self.project_root.glob(pattern))

        # Filter out vendored, test environments, and build artifacts
        excluded_dirs = {
            'venv', '.venv', 'env', '.virtualenv',
            'vendor', 'extern', 'third_party', 'blib2to3', '_internal',
            '.tox',
            'site-packages',
            'dist', 'build', '__pycache__',
            'node_modules',
            '.git', '.janitor_trash', '.janitor_cache'
        }

        filtered_files = set()
        for file_path in files:
            if not any(excluded in file_path.parts for excluded in excluded_dirs):
                filtered_files.add(file_path)

        return filtered_files

    def _process_file(self, file_path: Path):
        """Process a single file: parse, extract imports, add to graph.

        TURBO: Checks SQLite cache before parsing.

        Args:
            file_path: Path to file to process
        """
        str_file_path = str(file_path)

        # Add file as node (even if it has no imports)
        self.graph.add_node(str_file_path, path=file_path)

        # 1. FAST PATH: Check Cache
        # If file hasn't changed, load edges from SQLite and skip parsing
        cached_dependencies = self.cache.get_file_dependencies(file_path)
        if cached_dependencies is not None:
            for target in cached_dependencies:
                self.graph.add_edge(str_file_path, target)
            return

        # 2. SLOW PATH: Parse and Resolve
        parser = LanguageParser.from_file_extension(file_path)
        if not parser:
            # No dependencies for unknown file types - cache empty list
            self.cache.set_file_dependencies(file_path, [])
            return

        tree = parser.parse_file(file_path)
        if not tree:
            self.cache.set_file_dependencies(file_path, [])
            return

        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
        except (IOError, OSError):
            self.cache.set_file_dependencies(file_path, [])
            return

        extractor = EntityExtractor(parser.language)
        imports = extractor.extract_imports(tree, source_code, str_file_path)

        # Resolve imports and collect edges for caching
        resolved_edges = []

        for imp in imports:
            target_paths = self._resolve_import(imp, file_path, parser.language)
            for target_path in target_paths:
                if target_path and target_path.exists():
                    str_target = str(target_path)

                    # Add to graph
                    self.graph.add_edge(str_file_path, str_target)

                    # Add to list for caching
                    resolved_edges.append(str_target)

        # 3. Update Cache
        # Store the resolved dependencies so we don't have to parse/resolve next time
        self.cache.set_file_dependencies(file_path, resolved_edges)

    def _resolve_import(self, imp: Import, current_file: Path, language: str) -> List[Path]:
        """Resolve import statement to actual file path(s).

        Args:
            imp: Import object
            current_file: Current file path
            language: Language (python, javascript, typescript)

        Returns:
            List of resolved file paths
        """
        if language == 'python':
            return self._resolve_python_import(imp, current_file)
        elif language in ('javascript', 'typescript'):
            result = self._resolve_js_import(imp, current_file)
            return [result] if result else []
        return []

    def _resolve_python_import(self, imp: Import, current_file: Path) -> List[Path]:
        """Resolve Python import to file path(s).

        Args:
            imp: Import object
            current_file: Current file path

        Returns:
            List of resolved Python file paths
        """
        resolved_paths = []

        if imp.is_relative:
            # Relative import (from .module import ...)
            stripped_module = imp.module.lstrip('.')
            level = len(imp.module) - len(stripped_module)
            if level == 0:
                level = 1

            base_dir = current_file.parent
            try:
                for _ in range(level - 1):
                    base_dir = base_dir.parent
            except ValueError:
                return []

            if not stripped_module:
                # from . import x, y, z
                if imp.names:
                    found_any_file = False
                    for name in imp.names:
                        resolved = self._check_python_path_variants(base_dir / name)
                        if resolved:
                            resolved_paths.append(resolved)
                            found_any_file = True
                    if not found_any_file:
                        init_file = base_dir / '__init__.py'
                        if init_file.exists():
                            resolved_paths.append(init_file)
                else:
                    init_file = base_dir / '__init__.py'
                    if init_file.exists():
                        resolved_paths.append(init_file)
            else:
                # from .module import ...
                parts = stripped_module.split('.')
                current_path = base_dir
                for part in parts:
                    current_path = current_path / part

                resolved = self._check_python_path_variants(current_path)
                if resolved:
                    resolved_paths.append(resolved)

        else:
            # Absolute import (from module import ...)
            module_parts = imp.module.split('.')
            search_roots = [self.project_root]
            src_dir = self.project_root / 'src'
            if src_dir.is_dir():
                search_roots.append(src_dir)

            for root in search_roots:
                first_part = module_parts[0]
                if not (root / first_part).exists() and not (root / f"{first_part}.py").exists():
                    continue

                current_path = root
                for part in module_parts:
                    current_path = current_path / part

                resolved = self._check_python_path_variants(current_path)
                if resolved:
                    resolved_paths.append(resolved)
                    break

        return resolved_paths

    def _check_python_path_variants(self, base_path: Path) -> Optional[Path]:
        """Check if path exists as a .py file or a package directory.

        Args:
            base_path: Base path to check

        Returns:
            Resolved path or None
        """
        as_file = base_path.with_suffix('.py')
        if as_file.is_file():
            return as_file

        as_package = base_path / '__init__.py'
        if as_package.is_file():
            return as_package

        return None

    def _resolve_js_import(self, imp: Import, current_file: Path) -> Optional[Path]:
        """Resolve JavaScript/TypeScript import to file path.

        Args:
            imp: Import object
            current_file: Current file path

        Returns:
            Resolved file path or None
        """
        extensions = ['.ts', '.tsx', '.js', '.jsx']

        if imp.is_relative:
            current_dir = current_file.parent
            import_path = (current_dir / imp.module).resolve()

            for ext in extensions:
                as_file = import_path.with_suffix(ext)
                if as_file.exists():
                    return as_file

            if import_path.is_dir():
                for ext in extensions:
                    as_index = import_path / f'index{ext}'
                    if as_index.exists():
                        return as_index
        else:
            import_path = self.project_root / imp.module

            for ext in extensions:
                as_file = import_path.with_suffix(ext)
                if as_file.exists():
                    return as_file

            if import_path.is_dir():
                for ext in extensions:
                    as_index = import_path / f'index{ext}'
                    if as_index.exists():
                        return as_index

        return None
