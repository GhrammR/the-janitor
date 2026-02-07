Here is the optimized code.

### 1. `graph_builder.py`

```python
"""Dependency graph builder using NetworkX."""
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
        # Initialize cache for low-latency lookups
        self.cache = AnalysisCache(self.project_root)

    def build_graph(self, file_patterns: Optional[List[str]] = None) -> nx.DiGraph:
        """Build dependency graph for entire project.

        Creates directed graph where edge (A, B) means "file A imports file B".

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
            '.git', '.janitor_trash'
        }

        filtered_files = set()
        for file_path in files:
            if not any(excluded in file_path.parts for excluded in excluded_dirs):
                filtered_files.add(file_path)

        return filtered_files

    def _process_file(self, file_path: Path):
        """Process a single file: parse, extract imports, add to graph.

        PERFORMANCE UPDATE: Checks SQLite cache before parsing.

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
            return

        tree = parser.parse_file(file_path)
        if not tree:
            return

        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
        except (IOError, OSError):
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
        """Resolve import statement to actual file path(s)."""
        if language == 'python':
            return self._resolve_python_import(imp, current_file)
        elif language in ('javascript', 'typescript'):
            result = self._resolve_js_import(imp, current_file)
            return [result] if result else []
        return []

    def _resolve_python_import(self, imp: Import, current_file: Path) -> List[Path]:
        """Resolve Python import to file path(s)."""
        resolved_paths = []

        if imp.is_relative:
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
                parts = stripped_module.split('.')
                current_path = base_dir
                for part in parts:
                    current_path = current_path / part
                
                resolved = self._check_python_path_variants(current_path)
                if resolved:
                    resolved_paths.append(resolved)

        else:
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
        """Check if path exists as a .py file or a package directory."""
        as_file = base_path.with_suffix('.py')
        if as_file.is_file():
            return as_file
        
        as_package = base_path / '__init__.py'
        if as_package.is_file():
            return as_package
            
        return None

    def _resolve_js_import(self, imp: Import, current_file: Path) -> Optional[Path]:
        """Resolve JavaScript/TypeScript import to file path."""
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
```

### 2. `cache.py`

```python
"""Analysis Cache for Repeat Audits.

PERFORMANCE ENGINEER TASK 2: THE SPEED RUN
Implement `.janitor_cache` to bring repeat audits under 2 seconds.

Cache Strategy:
- Store 'Metaprogramming Danger' status per file
- Store 'Symbol Definitions' per file
- Store 'File Dependencies' (Edges) per file
- Use file mtime + size as cache key
- If file unchanged, skip AST extraction and reference linking

Cache Format: SQLite database for performance and simplicity
Location: .janitor_cache/ in project root
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import hashlib


class AnalysisCache:
    """Cache for symbol definitions, dependencies, and metaprogramming danger status."""

    def __init__(self, project_root: Path):
        """Initialize cache database.

        Args:
            project_root: Root directory of the project being analyzed
        """
        self.project_root = Path(project_root)
        self.cache_dir = self.project_root / '.janitor_cache'
        self.cache_file = self.cache_dir / 'analysis.db'

        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(exist_ok=True)

        # Initialize database
        self.conn = sqlite3.connect(str(self.cache_file))
        self._init_database()

    def _init_database(self):
        """Create cache tables if they don't exist."""
        cursor = self.conn.cursor()

        # Table for file metadata (cache keys)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_metadata (
                file_path TEXT PRIMARY KEY,
                mtime REAL NOT NULL,
                size INTEGER NOT NULL,
                cache_key TEXT NOT NULL
            )
        ''')

        # Table for metaprogramming danger status
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metaprogramming_danger (
                file_path TEXT PRIMARY KEY,
                is_dangerous INTEGER NOT NULL,
                cache_key TEXT NOT NULL,
                FOREIGN KEY (file_path) REFERENCES file_metadata(file_path)
            )
        ''')

        # Table for symbol definitions (serialized as JSON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS symbol_definitions (
                file_path TEXT NOT NULL,
                symbol_data TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                PRIMARY KEY (file_path),
                FOREIGN KEY (file_path) REFERENCES file_metadata(file_path)
            )
        ''')

        # Table for extracted file_references (PERFORMANCE ARCHITECT: Phase 3 cache)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_references (
                file_path TEXT NOT NULL,
                reference_data TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                PRIMARY KEY (file_path),
                FOREIGN KEY (file_path) REFERENCES file_metadata(file_path)
            )
        ''')

        # Table for file dependencies (Graph Edges)
        # Stores list of target file paths that this file imports
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_dependencies (
                file_path TEXT NOT NULL,
                dependencies TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                PRIMARY KEY (file_path),
                FOREIGN KEY (file_path) REFERENCES file_metadata(file_path)
            )
        ''')

        # Table for dead symbols analysis result (LOW-LATENCY: O(1) cached result)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_result (
                project_hash TEXT PRIMARY KEY,
                dead_symbols TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')

        # Index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_cache_key
            ON file_metadata(cache_key)
        ''')

        self.conn.commit()

    def _get_cache_key(self, file_path: Path) -> Optional[Tuple[float, int, str]]:
        """Generate cache key from file mtime and SHA256 hash of content.

        Args:
            file_path: Path to file

        Returns:
            Tuple of (mtime, size, hash) or None if file doesn't exist
        """
        try:
            stat = file_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size

            # SHA256 hash of file content for accurate cache validation
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)

            cache_key = f"{mtime}:{sha256_hash.hexdigest()}"

            return (mtime, size, cache_key)
        except (OSError, FileNotFoundError):
            return None

    def is_file_cached(self, file_path: Path) -> bool:
        """Check if file analysis is cached and still valid.

        PERFORMANCE OPTIMIZATION: Only check mtime + size (fast check).
        """
        try:
            stat = file_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size
        except (OSError, FileNotFoundError):
            return False

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT mtime, size FROM file_metadata
            WHERE file_path = ?
        ''', (str(file_path),))

        result = cursor.fetchone()
        if not result:
            return False

        cached_mtime, cached_size = result
        return cached_mtime == mtime and cached_size == size

    def get_file_dependencies(self, file_path: Path) -> Optional[List[str]]:
        """Get cached file dependencies (edges).

        Args:
            file_path: Path to file

        Returns:
            List of target file paths (strings), or None if not cached
        """
        if not self.is_file_cached(file_path):
            return None

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT dependencies FROM file_dependencies
            WHERE file_path = ?
        ''', (str(file_path),))

        result = cursor.fetchone()
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None

        return None

    def set_file_dependencies(self, file_path: Path, dependencies: List[str]):
        """Cache file dependencies (edges).

        Args:
            file_path: Path to file
            dependencies: List of target file paths (strings)
        """
        cache_key_data = self._get_cache_key(file_path)
        if not cache_key_data:
            return

        mtime, size, cache_key = cache_key_data

        cursor = self.conn.cursor()

        # Update file metadata
        cursor.execute('''
            INSERT OR REPLACE INTO file_metadata (file_path, mtime, size, cache_key)
            VALUES (?, ?, ?, ?)
        ''', (str(file_path), mtime, size, cache_key))

        # Update dependencies
        deps_data = json.dumps(dependencies)
        cursor.execute('''
            INSERT OR REPLACE INTO file_dependencies (file_path, dependencies, cache_key)
            VALUES (?, ?, ?)
        ''', (str(file_path), deps_data, cache_key))

        self.conn.commit()

    def get_metaprogramming_danger(self, file_path: Path) -> Optional[bool]:
        """Get cached metaprogramming danger status."""
        if not self.is_file_cached(file_path):
            return None

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT is_dangerous FROM metaprogramming_danger
            WHERE file_path = ?
        ''', (str(file_path),))

        result = cursor.fetchone()
        if result:
            return bool(result[0])

        return None

    def set_metaprogramming_danger(self, file_path: Path, is_dangerous: bool):
        """Cache metaprogramming danger status for a file."""
        cache_key_data = self._get_cache_key(file_path)
        if not cache_key_data:
            return

        mtime, size, cache_key = cache_key_data

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO file_metadata (file_path, mtime, size, cache_key)
            VALUES (?, ?, ?, ?)
        ''', (str(file_path), mtime, size, cache_key))

        cursor.execute('''
            INSERT OR REPLACE INTO metaprogramming_danger (file_path, is_dangerous, cache_key)
            VALUES (?, ?, ?)
        ''', (str(file_path), 1 if is_dangerous else 0, cache_key))

        self.conn.commit()

    def get_symbol_definitions(self, file_path: Path) -> Optional[List[Dict]]:
        """Get cached symbol definitions for a file."""
        if not self.is_file_cached(file_path):
            return None

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT symbol_data FROM symbol_definitions
            WHERE file_path = ?
        ''', (str(file_path),))

        result = cursor.fetchone()
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None

        return None

    def set_symbol_definitions(self, file_path: Path, symbols: List[Dict]):
        """Cache symbol definitions for a file."""
        cache_key_data = self._get_cache_key(file_path)
        if not cache_key_data:
            return

        mtime, size, cache_key = cache_key_data

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO file_metadata (file_path, mtime, size, cache_key)
            VALUES (?, ?, ?, ?)
        ''', (str(file_path), mtime, size, cache_key))

        symbol_data = json.dumps(symbols)
        cursor.execute('''
            INSERT OR REPLACE INTO symbol_definitions (file_path, symbol_data, cache_key)
            VALUES (?, ?, ?)
        ''', (str(file_path), symbol_data, cache_key))

        self.conn.commit()

    def get_file_references(self, file_path: Path) -> Optional[List[Dict]]:
        """Get cached file_references for a file."""
        if not self.is_file_cached(file_path):
            return None

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT reference_data FROM file_references
            WHERE file_path = ?
        ''', (str(file_path),))

        result = cursor.fetchone()
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None

        return None

    def set_file_references(self, file_path: Path, file_references: List[Dict]):
        """Cache extracted file_references for a file."""
        cache_key_data = self._get_cache_key(file_path)
        if not cache_key_data:
            return

        mtime, size, cache_key = cache_key_data

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO file_metadata (file_path, mtime, size, cache_key)
            VALUES (?, ?, ?, ?)
        ''', (str(file_path), mtime, size, cache_key))

        reference_data = json.dumps(file_references)
        cursor.execute('''
            INSERT OR REPLACE INTO file_references (file_path, reference_data, cache_key)
            VALUES (?, ?, ?)
        ''', (str(file_path), reference_data, cache_key))

        self.conn.commit()

    def invalidate_file(self, file_path: Path):
        """Invalidate cache for a specific file."""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM metaprogramming_danger WHERE file_path = ?', (str(file_path),))
        cursor.execute('DELETE FROM symbol_definitions WHERE file_path = ?', (str(file_path),))
        cursor.execute('DELETE FROM file_references WHERE file_path = ?', (str(file_path),))
        cursor.execute('DELETE FROM file_dependencies WHERE file_path = ?', (str(file_path),))
        cursor.execute('DELETE FROM file_metadata WHERE file_path = ?', (str(file_path),))
        self.conn.commit()

    def clear_cache(self):
        """Clear all cached data."""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM metaprogramming_danger')
        cursor.execute('DELETE FROM symbol_definitions')
        cursor.execute('DELETE FROM file_references')
        cursor.execute('DELETE FROM file_dependencies')
        cursor.execute('DELETE FROM file_metadata')
        self.conn.commit()

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM file_metadata')
        total_files = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM metaprogramming_danger')
        danger_cached = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM symbol_definitions')
        symbols_cached = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM file_references')
        file_references_cached = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM file_dependencies')
        dependencies_cached = cursor.fetchone()[0]

        return {
            'total_files': total_files,
            'metaprogramming_danger_cached': danger_cached,
            'symbol_definitions_cached': symbols_cached,
            'file_references_cached': file_references_cached,
            'dependencies_cached': dependencies_cached
        }

    def get_project_hash(self, file_paths: List[Path]) -> str:
        """Generate a hash representing the current state of all project files."""
        import hashlib
        file_states = []
        for file_path in sorted(file_paths):
            try:
                stat = file_path.stat()
                file_states.append(f"{file_path}:{stat.st_mtime}:{stat.st_size}")
            except (OSError, FileNotFoundError):
                pass
        project_state = "|".join(file_states)
        return hashlib.sha256(project_state.encode()).hexdigest()

    def get_cached_analysis_result(self, project_hash: str) -> Optional[List[Dict]]:
        """Get cached dead symbols analysis result."""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT dead_symbols FROM analysis_result
            WHERE project_hash = ?
        ''', (project_hash,))
        result = cursor.fetchone()
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None
        return None

    def set_cached_analysis_result(self, project_hash: str, dead_symbols: List):
        """Cache the dead symbols analysis result."""
        import time
        symbol_dicts = [
            {
                'name': s.name,
                'type': s.type,
                'file_path': s.file_path,
                'start_line': s.start_line,
                'end_line': s.end_line,
                'qualified_name': s.qualified_name,
                'parent_class': s.parent_class,
                'protected_by': s.protected_by
            }
            for s in dead_symbols
        ]
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO analysis_result (project_hash, dead_symbols, timestamp)
            VALUES (?, ?, ?)
        ''', (project_hash, json.dumps(symbol_dicts), time.time()))
        self.conn.commit()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
```