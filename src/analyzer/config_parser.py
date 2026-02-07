"""Cross-Language Configuration Parser.

PRIORITY ONE: Infrastructure-as-Code and Config File Analysis
This module scans configuration files (YAML, JSON, Python) to detect
references to Python/JavaScript symbols that appear unused but are
critical for deployment, orchestration, or runtime configuration.

JUSTIFICATION FOR $49 PRICE POINT:
This is where Premium Tier separates from free tools. We understand
that modern applications are not just Python files - they're distributed
systems defined across YAML (Serverless, K8s), JSON (AWS SAM), and
configuration modules (Django settings).

Supported Patterns:
- AWS Lambda/Serverless: handler definitions in serverless.yml
- AWS SAM: Handler specifications in template.yaml
- Django: INSTALLED_APPS, MIDDLEWARE strings in settings.py
- Docker Compose: command/entrypoint specifications
- Airflow: DAG task references
"""

from pathlib import Path
from typing import Set, Dict, List, Tuple
import re
import json


class ConfigParser:
    """Parse configuration files to extract symbol references."""

    def __init__(self, project_root: Path):
        """Initialize config parser.

        Args:
            project_root: Root directory of the project
        """
        self.project_root = Path(project_root)
        self.config_references: Dict[str, List[Tuple[str, str]]] = {}  # symbol_name -> [(file, reason)]

    def parse_all_configs(self) -> Dict[str, List[Tuple[str, str]]]:
        """Parse all configuration files in the project.

        Returns:
            Dict mapping symbol names to list of (config_file, reason) tuples
        """
        # AWS/Serverless configurations
        self._parse_serverless_yml()
        self._parse_sam_template()

        # Django settings
        self._parse_django_settings()

        # Docker configurations
        self._parse_docker_compose()

        # Airflow DAGs (if present)
        self._parse_airflow_dags()

        # JavaScript/TypeScript configurations (TASK 2)
        self._parse_package_json()
        self._parse_tsconfig_json()

        return self.config_references

    def _parse_serverless_yml(self):
        """Parse serverless.yml for Lambda handler definitions.

        Pattern: handler: module.function_name
        Example: handler: handlers.process_image
        """
        serverless_file = self.project_root / 'serverless.yml'
        if not serverless_file.exists():
            return

        try:
            content = serverless_file.read_text(encoding='utf-8')

            # Pattern: handler: module.function_name
            # Example: handler: handlers.process_image
            handler_pattern = r'handler:\s*([a-zA-Z0-9_\.]+)'
            matches = re.findall(handler_pattern, content)

            for handler_path in matches:
                # Extract function name from dotted path
                # 'handlers.process_image' -> 'process_image'
                parts = handler_path.split('.')
                if len(parts) >= 2:
                    function_name = parts[-1]
                    self._add_reference(function_name, 'serverless.yml',
                                      f'Lambda Handler: {handler_path}')
        except (IOError, OSError):
            pass

    def _parse_sam_template(self):
        """Parse AWS SAM template.yaml for Lambda handlers.

        Pattern: Handler: module.function_name
        Example: Handler: app.lambda_handler
        """
        for template_file in ['template.yaml', 'template.yml']:
            sam_file = self.project_root / template_file
            if not sam_file.exists():
                continue

            try:
                content = sam_file.read_text(encoding='utf-8')

                # Pattern: Handler: module.function_name
                handler_pattern = r'Handler:\s*([a-zA-Z0-9_\.]+)'
                matches = re.findall(handler_pattern, content)

                for handler_path in matches:
                    parts = handler_path.split('.')
                    if len(parts) >= 2:
                        function_name = parts[-1]
                        self._add_reference(function_name, template_file,
                                          f'SAM Handler: {handler_path}')
            except (IOError, OSError):
                pass

    def _parse_django_settings(self):
        """Parse Django settings.py for app and middleware references.

        Patterns:
        - INSTALLED_APPS = ['myapp.users', ...]
        - MIDDLEWARE = ['middleware.auth.AuthMiddleware', ...]
        """
        # Common Django settings locations
        settings_paths = [
            self.project_root / 'settings.py',
            self.project_root / 'config' / 'settings.py',
            self.project_root / 'project' / 'settings.py',
        ]

        # Also search for settings directories
        for settings_dir in self.project_root.rglob('settings'):
            if settings_dir.is_dir():
                settings_paths.append(settings_dir / '__init__.py')
                settings_paths.append(settings_dir / 'base.py')

        for settings_file in settings_paths:
            if not settings_file.exists():
                continue

            try:
                content = settings_file.read_text(encoding='utf-8')

                # Extract INSTALLED_APPS strings
                # Pattern: 'myapp.users' or "myapp.users"
                installed_apps_match = re.search(
                    r'INSTALLED_APPS\s*=\s*\[(.*?)\]',
                    content,
                    re.DOTALL
                )
                if installed_apps_match:
                    apps_block = installed_apps_match.group(1)
                    # Extract quoted strings
                    app_strings = re.findall(r'["\']([a-zA-Z0-9_\.]+)["\']', apps_block)
                    for app_path in app_strings:
                        # 'myapp.users' -> protect 'users' module
                        parts = app_path.split('.')
                        for part in parts:
                            self._add_reference(part, str(settings_file.relative_to(self.project_root)),
                                              f'Django INSTALLED_APPS: {app_path}')

                # Extract MIDDLEWARE strings
                middleware_match = re.search(
                    r'MIDDLEWARE\s*=\s*\[(.*?)\]',
                    content,
                    re.DOTALL
                )
                if middleware_match:
                    middleware_block = middleware_match.group(1)
                    middleware_strings = re.findall(r'["\']([a-zA-Z0-9_\.]+)["\']', middleware_block)
                    for middleware_path in middleware_strings:
                        # 'middleware.auth.AuthMiddleware' -> protect 'AuthMiddleware'
                        parts = middleware_path.split('.')
                        if len(parts) >= 2:
                            class_name = parts[-1]
                            self._add_reference(class_name, str(settings_file.relative_to(self.project_root)),
                                              f'Django MIDDLEWARE: {middleware_path}')

            except (IOError, OSError):
                pass

    def _parse_docker_compose(self):
        """Parse docker-compose.yml for command/entrypoint references.

        Pattern: command: python -m myapp.worker
        Example: entrypoint: ["python", "manage.py", "runserver"]
        """
        compose_files = ['docker-compose.yml', 'docker-compose.yaml']

        for compose_file in compose_files:
            docker_file = self.project_root / compose_file
            if not docker_file.exists():
                continue

            try:
                content = docker_file.read_text(encoding='utf-8')

                # Pattern: python -m module.name
                module_pattern = r'python\s+-m\s+([a-zA-Z0-9_\.]+)'
                matches = re.findall(module_pattern, content)
                for module_path in matches:
                    parts = module_path.split('.')
                    for part in parts:
                        self._add_reference(part, compose_file,
                                          f'Docker command: python -m {module_path}')

                # Pattern: python script.py (both string and array formats)
                # String format: python script.py
                # Array format: ["python", "script.py"]
                script_pattern = r'python\s+([a-zA-Z0-9_]+\.py)'
                matches = re.findall(script_pattern, content)
                for script_name in matches:
                    # 'manage.py' -> 'manage'
                    module_name = script_name.replace('.py', '')
                    self._add_reference(module_name, compose_file,
                                      f'Docker script: {script_name}')

                # Array format: ["python", "script.py"] or ['python', 'script.py']
                array_script_pattern = r'[\"\']python[\"\'],\s*[\"\']([a-zA-Z0-9_]+\.py)[\"\']'
                array_matches = re.findall(array_script_pattern, content)
                for script_name in array_matches:
                    module_name = script_name.replace('.py', '')
                    self._add_reference(module_name, compose_file,
                                      f'Docker script: {script_name}')

            except (IOError, OSError):
                pass

    def _parse_airflow_dags(self):
        """Parse Airflow DAG files for task IDs and operator references.

        Pattern: PythonOperator(task_id='process_data', python_callable=my_function)
        """
        # Look for dags directory
        dags_dirs = list(self.project_root.rglob('dags'))

        for dags_dir in dags_dirs:
            if not dags_dir.is_dir():
                continue

            # Scan all Python files in dags directory
            for dag_file in dags_dir.glob('*.py'):
                try:
                    content = dag_file.read_text(encoding='utf-8')

                    # Pattern: python_callable=function_name
                    callable_pattern = r'python_callable\s*=\s*([a-zA-Z0-9_]+)'
                    matches = re.findall(callable_pattern, content)
                    for function_name in matches:
                        self._add_reference(function_name, str(dag_file.relative_to(self.project_root)),
                                          f'Airflow python_callable: {function_name}')

                    # Pattern: task_id='...'
                    task_id_pattern = r'task_id\s*=\s*["\']([a-zA-Z0-9_]+)["\']'
                    matches = re.findall(task_id_pattern, content)
                    for task_id in matches:
                        self._add_reference(task_id, str(dag_file.relative_to(self.project_root)),
                                          f'Airflow task_id: {task_id}')

                except (IOError, OSError):
                    pass

    def _parse_package_json(self):
        """Parse package.json for script and bin references.

        TASK 2: JS/TS CONFIG PARSING (COMPLETING THE UNIVERSE)

        Patterns detected:
        - scripts: {
            "start": "node server.js",
            "test": "jest",
            "build": "webpack"
          }
        - bin: {
            "my-cli": "./bin/cli.js"
          }
        - bin: "./bin/cli.js" (string format)

        Protects entry point files that appear unused but are critical.
        """
        package_json = self.project_root / 'package.json'
        if not package_json.exists():
            return

        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Parse scripts section
            scripts = data.get('scripts', {})
            for script_name, command in scripts.items():
                # Extract file references from commands
                # Patterns: "node server.js", "ts-node src/index.ts", "./bin/cli.js"
                js_file_pattern = r'([a-zA-Z0-9_/\-]+\.(?:js|ts|jsx|tsx|mjs|cjs))'
                matches = re.findall(js_file_pattern, command)
                for file_path in matches:
                    # Extract filename without extension
                    file_name = Path(file_path).stem
                    self._add_reference(file_name, 'package.json',
                                      f'npm script "{script_name}": {file_path}')

            # Parse bin section (CLI entry points)
            bin_config = data.get('bin', {})
            if isinstance(bin_config, dict):
                # bin: { "cli-name": "./path/to/file.js" }
                for cli_name, file_path in bin_config.items():
                    file_name = Path(file_path).stem
                    self._add_reference(file_name, 'package.json',
                                      f'bin entry point "{cli_name}": {file_path}')
            elif isinstance(bin_config, str):
                # bin: "./path/to/file.js"
                file_name = Path(bin_config).stem
                self._add_reference(file_name, 'package.json',
                                  f'bin entry point: {bin_config}')

            # Parse main entry point
            main_entry = data.get('main')
            if main_entry:
                file_name = Path(main_entry).stem
                self._add_reference(file_name, 'package.json',
                                  f'main entry point: {main_entry}')

            # Parse module entry point (ES modules)
            module_entry = data.get('module')
            if module_entry:
                file_name = Path(module_entry).stem
                self._add_reference(file_name, 'package.json',
                                  f'module entry point: {module_entry}')

        except (IOError, OSError, json.JSONDecodeError):
            pass

    def _parse_tsconfig_json(self):
        """Parse tsconfig.json for path mappings and references.

        TASK 2: JS/TS CONFIG PARSING (COMPLETING THE UNIVERSE)

        Patterns detected:
        - compilerOptions.paths: {
            "@utils/*": ["src/utils/*"],
            "@services/*": ["src/services/*"]
          }
        - compilerOptions.outDir: "dist"
        - include: ["src/**/*"]
        - files: ["src/index.ts"]

        Protects TypeScript configuration and mapped modules.
        """
        tsconfig_json = self.project_root / 'tsconfig.json'
        if not tsconfig_json.exists():
            return

        try:
            with open(tsconfig_json, 'r', encoding='utf-8') as f:
                # Remove comments (JSON5-style comments in tsconfig)
                content = f.read()
                # Remove single-line comments
                content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
                # Remove multi-line comments
                content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

                data = json.loads(content)

            # Parse compilerOptions.paths
            compiler_options = data.get('compilerOptions', {})
            paths = compiler_options.get('paths', {})

            for alias, path_list in paths.items():
                # Extract path mappings like "@utils/*": ["src/utils/*"]
                for path_pattern in path_list:
                    # Remove wildcard and extract directory
                    clean_path = path_pattern.replace('*', '').rstrip('/')
                    if clean_path:
                        # Extract last directory name as module reference
                        dir_name = Path(clean_path).name
                        if dir_name:
                            self._add_reference(dir_name, 'tsconfig.json',
                                              f'path mapping "{alias}": {path_pattern}')

            # Parse files array (explicit file inclusions)
            files = data.get('files', [])
            for file_path in files:
                file_name = Path(file_path).stem
                self._add_reference(file_name, 'tsconfig.json',
                                  f'explicit file: {file_path}')

            # Parse include patterns
            include = data.get('include', [])
            for pattern in include:
                # Extract specific files (not wildcard patterns)
                if '*' not in pattern:
                    file_name = Path(pattern).stem
                    if file_name:
                        self._add_reference(file_name, 'tsconfig.json',
                                          f'include pattern: {pattern}')

        except (IOError, OSError, json.JSONDecodeError):
            pass

    def _add_reference(self, symbol_name: str, config_file: str, reason: str):
        """Add a config file reference to a symbol.

        Args:
            symbol_name: Name of the symbol (function, class, module)
            config_file: Configuration file that references it
            reason: Human-readable reason for the reference
        """
        if symbol_name not in self.config_references:
            self.config_references[symbol_name] = []

        self.config_references[symbol_name].append((config_file, reason))
