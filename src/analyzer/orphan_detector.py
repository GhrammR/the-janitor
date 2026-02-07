"""Orphan file detection - files with no incoming dependencies."""
from pathlib import Path
from typing import List, Set, Optional
import networkx as nx
import json
import configparser
import re
try:
    import tomllib
except ImportError:
    # Fallback for python < 3.11 if needed
    tomllib = None


class OrphanDetector:
    """Detect orphan files (files with zero incoming edges, excluding entry points)."""

    # Entry point filename patterns (for documentation - actual logic in _is_entry_point)
    ENTRY_POINT_PATTERNS = [
        '__init__.py',  # Python package structure
        '__main__.py',  # Python module entry points (python -m package)
        'main.py',
        'app.py',
        'index.ts',
        'index.tsx',
        'index.js',
        'index.jsx',
        'cli.py',
        'run.py',
    ]

    # Vendored/frozen code patterns (3rd-party libraries copied into your project)
    VENDORED_PATTERNS = {
        'vendor',
        'extern',
        'third_party',
        'blib2to3',
        '_internal',
        'dist',
        'build',
        'node_modules',
        '.tox',  # Tox test environments
        '.venv', 'venv', '.virtualenv',  # Virtual environments
        'site-packages',  # Python packages
        '__pycache__'  # Python cache
    }

    # DIRECTORY SHIELD: Directories containing files that should never be flagged as dead
    # These contain tutorial examples, documentation, scripts that are essential but not imported
    IMMORTAL_DIRECTORIES = {
        'tests', 'test',
        'examples', 'example',
        'docs', 'docs_src', 'documentation',
        'scripts', 'script',
        'requirements',
        'tutorial', 'tutorials',
        'benchmarks', 'benchmark',
        'sandbox',
        'bin'
    }

    def __init__(self, project_root: str | Path = "."):
        """Initialize orphan detector.

        Args:
            project_root: Root directory of project
        """
        self.project_root = Path(project_root).resolve()
        self.metadata_entry_points = self._parse_metadata_entry_points()

    def _parse_metadata_entry_points(self) -> Set[str]:
        """Parse project metadata to find entry points.
        
        Reads pyproject.toml, setup.cfg, and package.json to identify 
        entry point modules or script paths.
        """
        entry_points = set()

        # 1. pyproject.toml ([project.scripts], [project.entry-points], [tool.flit.metadata.scripts])
        pyproject = self.project_root / "pyproject.toml"
        if pyproject.exists() and tomllib:
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                    
                    # Standard project scripts
                    scripts = data.get("project", {}).get("scripts", {})
                    for val in scripts.values():
                        entry_points.update(self._resolve_metadata_value(val))
                    
                    # Custom entry points
                    eps = data.get("project", {}).get("entry-points", {})
                    for group in eps.values():
                        for val in group.values():
                            entry_points.update(self._resolve_metadata_value(val))
                            
                    # Flit specific
                    flit = data.get("tool", {}).get("flit", {}).get("metadata", {}).get("scripts", {})
                    for val in flit.values():
                        entry_points.update(self._resolve_metadata_value(val))
            except Exception:
                pass

        # 2. setup.cfg ([options.entry_points])
        setup_cfg = self.project_root / "setup.cfg"
        if setup_cfg.exists():
            try:
                config = configparser.ConfigParser()
                config.read(setup_cfg)
                # entry_points are usually in a dedicated section or sub-sections
                for section in config.sections():
                    if 'entry_points' in section.lower():
                        for key in config[section]:
                            val = config[section][key]
                            entry_points.update(self._resolve_metadata_value(val))
            except Exception:
                pass

        # 3. package.json ("bin", "browser", "module", "exports" fields)
        package_json = self.project_root / "package.json"
        if package_json.exists():
            try:
                with open(package_json, "r") as f:
                    data = json.load(f)
                    
                    # bin (string or dict)
                    bin_data = data.get("bin", {})
                    if isinstance(bin_data, str):
                        entry_points.add(str((self.project_root / bin_data).resolve()))
                    elif isinstance(bin_data, dict):
                        for path_str in bin_data.values():
                            entry_points.add(str((self.project_root / path_str).resolve()))

                    # browser (string or dict)
                    browser = data.get("browser")
                    if isinstance(browser, str):
                        entry_points.add(str((self.project_root / browser).resolve()))
                    elif isinstance(browser, dict):
                         # browser field can map module names to files or false.
                         # Keys can also be file paths (e.g. shim mapping).
                         for key, val in browser.items():
                             # Treat key as path if it looks like one
                             if isinstance(key, str) and (key.startswith('./') or '/' in key):
                                 entry_points.add(str((self.project_root / key).resolve()))
                             
                             if isinstance(val, str): 
                                 entry_points.add(str((self.project_root / val).resolve()))
                                 
                    # module (string)
                    module = data.get("module")
                    if isinstance(module, str):
                        entry_points.add(str((self.project_root / module).resolve()))
                        
                    # exports (string, dict, list, nested)
                    exports = data.get("exports")
                    if exports:
                        # Recursive helper to find strings in exports
                        def extract_paths(obj):
                            if isinstance(obj, str):
                                # It's a path if it starts with ./ or is just a filename
                                # Note: exports keys are paths, values are paths or conditions
                                if obj.startswith('./') or '/' in obj:
                                    entry_points.add(str((self.project_root / obj).resolve()))
                            elif isinstance(obj, dict):
                                for val in obj.values():
                                    extract_paths(val)
                            elif isinstance(obj, list):
                                for val in obj:
                                    extract_paths(val)
                        extract_paths(exports)
            except Exception:
                pass

        return entry_points

    def _resolve_metadata_value(self, val: str) -> List[str]:
        """Resolve a metadata script value (e.g. 'pkg.mod:func') to file paths."""
        resolved = []
        # Multi-line values in setup.cfg or weird formats
        lines = val.strip().split('\n')
        for line in lines:
            if '=' in line: # key = val format in setup.cfg
                line = line.split('=')[1].strip()
            
            # Extract module part from pkg.mod:func
            module_part = line.split(':')[0].strip()
            if not module_part:
                continue
                
            # Try to resolve module to file path
            # Strategy: replace '.' with '/' and check basic variants
            paths_to_check = [
                self.project_root / (module_part.replace('.', '/') + ".py"),
                self.project_root / "src" / (module_part.replace('.', '/') + ".py"),
                self.project_root / module_part.replace('.', '/') / "__init__.py",
                self.project_root / "src" / module_part.replace('.', '/') / "__init__.py"
            ]
            
            for p in paths_to_check:
                if p.exists():
                    resolved.append(str(p.resolve()))
                    
        return resolved

    def detect_orphans(self, graph: nx.DiGraph) -> List[str]:
        """Find files with zero incoming edges (excluding entry points).

        Args:
            graph: NetworkX DiGraph with file dependencies

        Returns:
            List of orphan file paths
        """
        orphans = []

        for node in graph.nodes():
            # Check in-degree (number of files importing this file)
            in_degree = graph.in_degree(node)

            if in_degree == 0:
                # No files import this one - check if it's protected

                # VENDORED CODE FILTER: Skip vendored directories (.tox, venv, etc.)
                path = Path(node)
                if any(pattern in path.parts for pattern in self.VENDORED_PATTERNS):
                    continue

                # DIRECTORY SHIELD: Skip immortal files (tests, docs, examples, etc.)
                if self.is_immortal(node):
                    continue
                # Check if it's an entry point
                if not self._is_entry_point(node):
                    orphans.append(node)

        return orphans

    def _is_entry_point(self, file_path: str) -> bool:
        """Check if file is an entry point.

        Entry points are files that should never be marked as orphans:
        1. __init__.py files (necessary for Python package structure)
        2. __main__.py files (Python module entry points)
        3. Files in project root (direct children)
        4. src/main.py explicitly
        5. Files containing typer app definitions
        6. Files containing if __name__ == "__main__"
        7. Files in protected directories (tests/, examples/, docs/, benchmarks/)

        Args:
            file_path: Path to check

        Returns:
            True if file is an entry point, False otherwise
        """
        path = Path(file_path)

        # NEVER mark __init__.py as orphan - they're necessary for package structure
        if path.name == '__init__.py':
            return True

        # NEVER mark __main__.py as orphan - they're Python module entry points
        # Used for: python -m package_name
        if path.name == '__main__.py':
            return True

        # === GLOBAL DIRECTORY PROTECTION ===
        # Protect files in test/example/doc directories - they are executed by runners, not imported
        protected_dirs = ['tests', 'test', 'examples', 'example', 'docs', 'doc', 'benchmarks', 'benchmark', 'docs_src', 'scripts', 'action', 'actions', 'profiling', 'tools', 'blib2to3', 'sandbox', 'bin']
        try:
            rel_path = path.relative_to(self.project_root)
            # Check if any parent directory matches protected dirs
            for part in rel_path.parts:
                if part.lower() in protected_dirs:
                    return True
        except ValueError:
            pass

        # Explicitly protect src/main.py
        try:
            rel_path = path.relative_to(self.project_root)
            if str(rel_path).replace('\\', '/') == 'src/main.py':
                return True
        except ValueError:
            pass

        # Check if file is in the project root (direct child)
        try:
            path.relative_to(self.project_root)
            if path.parent == self.project_root:
                # Files directly in project root are often entry points
                return True
        except ValueError:
            pass

        # Metadata Entry Points (Immortality)
        if str(path.resolve()) in self.metadata_entry_points:
            return True

        # Check for Python entry point patterns (typer app, __main__ block)
        if path.suffix == '.py':
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Check for typer app
                    if 'typer.Typer(' in content or 'typer.Typer =' in content:
                        return True
                    # Check for __main__ block
                    if 'if __name__ == "__main__"' in content:
                        return True
            except (IOError, OSError, UnicodeDecodeError):
                pass

        return False

    def is_vendored(self, file_path: str | Path) -> bool:
        """Check if file is in a vendored/frozen code directory.

        Vendored code is 3rd-party libraries copied into your project
        (e.g., vendor/, third_party/, node_modules/, blib2to3/).

        Args:
            file_path: Path to check

        Returns:
            True if file is vendored, False otherwise
        """
        path = Path(file_path)

        try:
            rel_path = path.relative_to(self.project_root)
            # Check if any parent directory matches vendored patterns
            for part in rel_path.parts:
                if part.lower() in self.VENDORED_PATTERNS:
                    return True
        except ValueError:
            pass

        return False

    def is_immortal(self, file_path: str | Path) -> bool:
        """Check if file is in an immortal directory (tests, docs, examples, etc.).

        DIRECTORY SHIELD: Files in these directories are essential but not imported.
        They contain tutorial examples, documentation, test fixtures, scripts.

        Args:
            file_path: Path to check

        Returns:
            True if file is in an immortal directory, False otherwise
        """
        path = Path(file_path)

        try:
            rel_path = path.relative_to(self.project_root)
            # Check if any parent directory matches immortal patterns
            for part in rel_path.parts:
                if part.lower() in self.IMMORTAL_DIRECTORIES:
                    return True
        except ValueError:
            pass

        return False

    def is_referenced_in_docs(self, file_path: str | Path, search_extensions: Set[str] = None) -> bool:
        """GREP SHIELD: Check if filename appears as a string in documentation/config files.

        Many documentation files are referenced as strings in Markdown or mkdocs.yml.
        This catches indirect references that dependency analysis misses.

        OPTIMIZED: Only searches key config files and docs directories (not entire project).

        Args:
            file_path: File to check for string references
            search_extensions: File types to search in (default: .md, .yml, .yaml, .rst, .txt)

        Returns:
            True if filename found in any documentation/config file
        """
        if search_extensions is None:
            search_extensions = {'.md', '.yml', '.yaml', '.rst', '.txt', '.toml', '.json'}

        path = Path(file_path)
        # Search for filename without extension (e.g., "tutorial_01" from "tutorial_01.py")
        filename_stem = path.stem

        # Don't grep for very common names (too many false positives)
        if filename_stem in ('main', 'app', 'index', 'test', 'conftest', 'setup', 'config'):
            return False

        # OPTIMIZATION: Only search specific directories and root-level config files
        search_paths = [
            self.project_root / 'docs',
            self.project_root / 'docs_src',
            self.project_root / 'documentation',
            self.project_root / 'README.md',
            self.project_root / 'mkdocs.yml',
            self.project_root / 'readthedocs.yml',
            self.project_root / '.readthedocs.yml',
            self.project_root / 'pyproject.toml',
        ]

        # Search targeted locations only
        for search_path in search_paths:
            if not search_path.exists():
                continue

            try:
                if search_path.is_file():
                    # Search single file
                    with open(search_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if filename_stem.lower() in content.lower():
                            return True
                elif search_path.is_dir():
                    # Search directory (limited depth)
                    for doc_file in search_path.rglob('*'):
                        if doc_file.suffix in search_extensions and doc_file.is_file():
                            try:
                                with open(doc_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if filename_stem.lower() in content.lower():
                                        return True
                            except (IOError, OSError):
                                continue
            except Exception:
                continue

        return False

    def get_orphan_stats(self, graph: nx.DiGraph) -> dict:
        """Get statistics about orphan files.

        Args:
            graph: NetworkX DiGraph with file dependencies

        Returns:
            Dictionary with orphan statistics
        """
        orphans = self.detect_orphans(graph)
        total_files = graph.number_of_nodes()

        # Group by extension
        by_extension = {}
        for orphan in orphans:
            ext = Path(orphan).suffix
            by_extension[ext] = by_extension.get(ext, 0) + 1

        return {
            'total_files': total_files,
            'orphan_count': len(orphans),
            'orphan_percentage': (len(orphans) / total_files * 100) if total_files > 0 else 0,
            'by_extension': by_extension,
            'orphans': orphans
        }
