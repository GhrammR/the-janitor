"""Windows-safe Console wrapper for Rich library.

Wraps Rich's Console to automatically sanitize Unicode characters
on Windows terminals that don't support UTF-8.
"""
from rich.console import Console
from rich.status import Status
from typing import Any
from .logger import sanitize_for_terminal, is_utf8_capable


class SafeConsole(Console):
    """Console wrapper that sanitizes Unicode output for Windows compatibility.

    Inherits from Rich's Console and overrides print() to automatically
    replace Unicode icons with ASCII equivalents on non-UTF-8 terminals.
    """

    def __init__(self, *args, **kwargs):
        """Initialize SafeConsole with UTF-8 capability detection.

        All arguments are passed through to Rich's Console.
        """
        # Check if we need to sanitize
        self._needs_sanitization = not is_utf8_capable()

        # Force legacy_windows mode if needed to prevent Unicode spinner issues
        if self._needs_sanitization:
            kwargs['legacy_windows'] = True

        # Initialize parent Console
        super().__init__(*args, **kwargs)

    def print(self, *objects: Any, **kwargs) -> None:
        """Print with automatic Unicode sanitization.

        Args:
            *objects: Objects to print (same as Rich Console.print)
            **kwargs: Keyword arguments (same as Rich Console.print)
        """
        if self._needs_sanitization:
            # Sanitize all string objects
            sanitized_objects = []
            for obj in objects:
                if isinstance(obj, str):
                    sanitized_objects.append(sanitize_for_terminal(obj))
                else:
                    sanitized_objects.append(obj)

            # Call parent with sanitized objects
            super().print(*sanitized_objects, **kwargs)
        else:
            # UTF-8 capable terminal - pass through unchanged
            super().print(*objects, **kwargs)

    def status(self, *args, **kwargs):
        """Create a status context with ASCII-safe spinner on Windows.

        Args:
            *args: Positional arguments (same as Rich Console.status)
            **kwargs: Keyword arguments (same as Rich Console.status)
        """
        if self._needs_sanitization:
            # Use ASCII-safe spinner for Windows legacy console
            kwargs['spinner'] = 'line'  # Simple ASCII spinner: - \ | /

        return super().status(*args, **kwargs)
