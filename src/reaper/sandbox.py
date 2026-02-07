"""Test sandbox for validating deletions with test suite."""
import subprocess
import re
import sys
from pathlib import Path
from typing import List, Optional
from collections import deque
from rich.panel import Panel
from rich.markup import escape

# Add parent directory to path for utils imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.safe_console import SafeConsole
from utils.logger import sanitize_for_terminal

from .safe_delete import SafeDeleter


class TestSandbox:
    """Run tests to validate that deletions don't break the codebase."""

    def __init__(self, project_root: str | Path = "."):
        """Initialize test sandbox.

        Args:
            project_root: Project root directory
        """
        self.project_root = Path(project_root).resolve()
        self.pytest_path = self.project_root / "venv" / "Scripts" / "pytest.exe"

    import re
    from typing import Set

    def delete_with_tests(
        self,
        files: List[str | Path],
        reason: str = "orphan",
        safe_deleter: Optional[SafeDeleter] = None,
        test_command: Optional[str] = None,
        allowed_failures: Optional[Set[str]] = None
    ) -> dict:
        """Delete files and run tests, auto-restore if NEW tests fail.

        Args:
            files: List of file paths to delete
            reason: Reason for deletion
            safe_deleter: SafeDeleter instance
            test_command: Custom test command
            allowed_failures: Set of test IDs that are allowed to fail (baseline)

        Returns:
            Dictionary with results
        """
        if safe_deleter is None:
            safe_deleter = SafeDeleter()
        
        if allowed_failures is None:
            allowed_failures = set()

        deletion_ids = []

        # Phase 1: Delete files
        for file_path in files:
            try:
                deletion_id = safe_deleter.delete(file_path, reason)
                deletion_ids.append(deletion_id)
            except (FileNotFoundError, IOError) as e:
                print(f"Warning: Failed to delete {file_path}: {e}")
                deletion_ids.append(None)

        # Phase 2: Run tests
        test_result = self._run_tests(test_command)

        # Determine success ("Fingerprinting")
        current_failures = self._parse_failures(test_result["stdout"] + test_result["stderr"])

        # Check for NEW failures (failures in current that are NOT in allowed)
        new_failures = current_failures - allowed_failures

        # CRITICAL: Pytest exit code 2 = Collection Error (imports failed, syntax errors, etc.)
        # This is a HARD FAILURE even if fingerprint is empty (regex might have missed it)
        exit_code = test_result.get("exit_code", 0)
        is_collection_error = (exit_code == 2 and "pytest" in test_result.get("command", ""))

        success = False
        if not new_failures and not is_collection_error:
            # No new failures introduced!
            # Even if exit_code != 0, as long as we haven't broken anything NEW, it's a pass.
            success = True
        elif is_collection_error:
            # Collection error detected - add synthetic failure to ensure restoration
            new_failures.add("COLLECTION_ERROR: pytest exit code 2")
        
        if not success:
            # NEW failures detected - RESTORE EVERYTHING
            try:
                safe_deleter.restore_all(deletion_ids)
                
                # Format failure list for display
                failure_msg = "\n".join([f"- {f}" for f in list(new_failures)[:10]])
                if len(new_failures) > 10:
                    failure_msg += f"\n... and {len(new_failures) - 10} more"
                    
                return {
                    "success": False,
                    "deleted_count": 0,
                    "restored_count": len([d for d in deletion_ids if d is not None]),
                    "test_output": f"REGRESSION DETECTED: New failing tests:\n{failure_msg}\n\n" + test_result.get("test_output", test_result["stderr"]),
                    "test_command": test_result["command"],
                    "failure_count": len(current_failures),
                    "new_failures": list(new_failures)
                }
            except IOError as e:
                return {
                    "success": False,
                    "deleted_count": len([d for d in deletion_ids if d is not None]),
                    "restored_count": 0,
                    "test_output": f"CRITICAL: Restoration failed: {e}\n\n{test_result['stderr']}",
                    "restoration_error": str(e)
                }
        else:
            # Tests passed/contained - deletions are safe
            return {
                "success": True,
                "deleted_count": len([d for d in deletion_ids if d is not None]),
                "restored_count": 0,
                "deletion_ids": deletion_ids,
                "test_output": test_result["stdout"]
            }

    def run_baseline_test(self, test_command: Optional[str] = None) -> dict:
        """Run tests on untouched repo to establish baseline."""
        result = self._run_tests(test_command)
        failures = self._parse_failures(result["stdout"] + result["stderr"])
        return {
            "exit_code": result["exit_code"],
            "failure_count": len(failures),
            "failures": failures,
            "test_output": result.get("test_output", result["stderr"]),
            "status": result.get("status", "UNKNOWN")
        }

    def _parse_failures(self, output: str) -> Set[str]:
        """Extract IDs of failing tests from output (Polyglot)."""
        failed_tests = set()

        # 1. Python / Pytest Pattern (Test-level failures)
        # Matches: FAILED tests/test_file.py::test_name
        python_fails = re.findall(r'(?:FAILED|ERROR) ([^\s]+::[^\s]+)', output)
        failed_tests.update(python_fails)

        # 2. Python / Pytest Pattern (File-level collection errors)
        # Matches: ERROR src/black/linegen.py (no :: separator)
        # CRITICAL: Collection errors don't have :: so need separate regex
        python_collection_errors = re.findall(r'(?:FAILED|ERROR) ([^\s]+\.py)(?:\s|$)', output)
        failed_tests.update(python_collection_errors)

        # 3. JavaScript / Mocha / Jest Pattern
        # Matches: "1) test name", "✖ test name", "● test name"
        # Axios uses Mocha, which typically outputs: "  1) test name"
        # re.MULTILINE allows ^ to match the start of a line
        js_fails = re.findall(r'^\s*(?:\d+\)|✖|●)\s+(.+?)$', output, re.MULTILINE)

        for f in js_fails:
            # Clean up trailing colons or noise often found in JS logs
            clean_name = f.strip().rstrip(':')
            failed_tests.add(clean_name)

        return failed_tests

    def _detect_test_command(self) -> str:
        """Detect appropriate test command based on project files."""
        # 1. Node.js / NPM
        if (self.project_root / "package.json").exists():
            return "npm test"
        
        # 2. Python / Pytest
        # Check for venv pytest first
        if self.pytest_path.exists():
            return str(self.pytest_path)
        
        # Fallback to system pytest
        return "pytest"

    def _run_tests(self, custom_command: Optional[str] = None) -> dict:
        """Run test command and return results with a scrolling 5-line buffer.

        Uses a deque to maintain a sliding window of output inside a console status spinner.
        This prevents terminal flooding while still showing activity.

        Args:
            custom_command: Custom test command (defaults to auto-detect)

        Returns:
            Dictionary with exit_code, stdout, stderr, command, status
        """
        from collections import deque

        command = custom_command if custom_command else self._detect_test_command()

        # Determine environment
        use_shell = "npm" in command and subprocess.os.name == 'nt'

        # Use SafeConsole for Windows Unicode compatibility
        console = SafeConsole(force_terminal=True)

        # Buffer for the scrolling window (last 5 lines)
        output_buffer = deque(maxlen=5)
        full_output = []

        try:
            # Start subprocess
            process = subprocess.Popen(
                command if use_shell else command.split(),
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Merge stderr into stdout
                text=True,
                shell=use_shell,
                encoding='utf-8',
                errors='replace',
                bufsize=1 # Line buffered
            )

            # Use console.status for the spinner and scrolling buffer
            with console.status(f"[bold blue]Initializing test suite: {escape(command)}...[/bold blue]") as status:

                # Read output line by line
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break

                    # Store full output for parsing later
                    full_output.append(line)

                    # Sanitize for display
                    line_stripped = line.rstrip()
                    if line_stripped:
                        # Step 1: Sanitize Unicode characters for Windows
                        sanitized_line = sanitize_for_terminal(line_stripped)
                        # Step 2: Escape Rich markup
                        escaped_line = escape(sanitized_line)

                        # Add to scrolling buffer
                        output_buffer.append(escaped_line)

                        # Update the status text with the buffer content
                        buffer_text = "\n".join(output_buffer)
                        status.update(f"[bold blue]Running tests...[/bold blue]\n[dim]{buffer_text}[/dim]")

            process.wait()
            returncode = process.returncode
            combined_output = "".join(full_output)

            # Check for "No tests collected" (Pytest Exit Code 5)
            status_code = "RAN"
            if returncode == 5 and "pytest" in command:
                status_code = "NO_TESTS_FOUND"
            elif returncode == -1: # Timeout or error
                status_code = "ERROR"

            return {
                "exit_code": returncode,
                "stdout": combined_output,
                "stderr": "", # Merged into stdout
                "command": command,
                "test_output": combined_output,
                "status": status_code
            }

        except subprocess.TimeoutExpired:
            console.print("\n[bold red]Test timeout after 5 minutes[/bold red]")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Test timeout after 5 minutes",
                "command": command,
                "test_output": "Test timeout after 5 minutes",
                "status": "TIMEOUT"
            }
        except FileNotFoundError:
            error_msg = f"Test command not found: {command}"
            console.print(f"\n[bold red]{escape(error_msg)}[/bold red]")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": error_msg,
                "command": command,
                "test_output": error_msg,
                "status": "MISSING_COMMAND"
            }
