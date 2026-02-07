"""Analysis Cache for Repeat Audits.

PERFORMANCE ENGINEER TASK 2: THE SPEED RUN
Implement `.janitor_cache` to bring repeat audits under 2 seconds.

Cache Strategy:
- Store 'Metaprogramming Danger' status per file
- Store 'Symbol Definitions' per file
- Store 'File Dependencies' (Edges) per file
- Store 'File References' (extracted references) per file
- Store 'Analysis Result' (dead symbols) for entire project
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
                orphan_files TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')

        # Migration: Add orphan_files column to existing databases
        # Check if column exists, add if missing
        cursor.execute("PRAGMA table_info(analysis_result)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'orphan_files' not in columns and columns:  # Table exists but missing column
            cursor.execute('ALTER TABLE analysis_result ADD COLUMN orphan_files TEXT NOT NULL DEFAULT "[]"')

        # Index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_cache_key
            ON file_metadata(cache_key)
        ''')

        self.conn.commit()

    def _get_cache_key(self, file_path: Path) -> Optional[Tuple[float, int, str]]:
        """Generate cache key from file mtime and size.

        LOW-LATENCY: Use mtime + size (fast) instead of SHA256 (slow).

        Args:
            file_path: Path to file

        Returns:
            Tuple of (mtime, size, hash) or None if file doesn't exist
        """
        try:
            stat = file_path.stat()
            mtime = stat.st_mtime
            size = stat.st_size

            # Use mtime:size as cache key (99.9% accurate, 100x faster than SHA256)
            cache_key = f"{mtime}:{size}"

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
        cursor.execute('DELETE FROM analysis_result')
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
        """Generate a hash representing the current state of all project files.

        LOW-LATENCY: mtime + size based (fast, accurate enough).
        """
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

    def get_cached_analysis_result(self, project_hash: str) -> Optional[Tuple[List[Dict], List[str]]]:
        """Get cached analysis result (dead symbols + orphan files).

        TURBO: O(1) cache hit if project unchanged.

        Returns:
            Tuple of (dead_symbols, orphan_files) or None if not cached
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT dead_symbols, orphan_files FROM analysis_result
            WHERE project_hash = ?
        ''', (project_hash,))
        result = cursor.fetchone()
        if result:
            try:
                dead_symbols = json.loads(result[0])
                orphan_files = json.loads(result[1])
                return (dead_symbols, orphan_files)
            except json.JSONDecodeError:
                return None
        return None

    def set_cached_analysis_result(self, project_hash: str, dead_symbols: List, orphan_files: List[str]):
        """Cache the complete analysis result (dead symbols + orphan files).

        TURBO: Store entire analysis for instant replay.

        Args:
            project_hash: Hash of project state
            dead_symbols: List of dead Entity objects
            orphan_files: List of orphan file paths (strings)
        """
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
            INSERT OR REPLACE INTO analysis_result (project_hash, dead_symbols, orphan_files, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (project_hash, json.dumps(symbol_dicts), json.dumps(orphan_files), time.time()))
        self.conn.commit()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
