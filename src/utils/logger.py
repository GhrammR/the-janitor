"""Windows-safe output handling with Unicode fallback for terminal compatibility.

Detects terminal encoding and provides ASCII alternatives for Unicode icons
to prevent crashes on Windows terminals that don't support UTF-8.
"""
import sys
import locale
from typing import Callable


# Unicode to ASCII icon mapping for Windows compatibility
ICON_MAP = {
    # Status icons
    '✓': '[OK]',
    '✔': '[OK]',
    '✅': '[OK]',
    '✗': '[FAIL]',
    '✘': '[FAIL]',
    '❌': '[FAIL]',
    '⚠': '[WARN]',
    '⚠️': '[WARN]',
    '⚡': '[!]',
    '🔥': '[!]',
    '🚨': '[ALERT]',

    # Progress/action icons
    '→': '->',
    '←': '<-',
    '↑': '^',
    '↓': 'v',
    '⇒': '=>',
    '⇐': '<=',

    # Structural icons
    '│': '|',
    '─': '-',
    '┌': '+',
    '┐': '+',
    '└': '+',
    '┘': '+',
    '├': '+',
    '┤': '+',
    '┬': '+',
    '┴': '+',
    '┼': '+',

    # Symbols
    '…': '...',
    '•': '*',
    '◦': 'o',
    '▪': '*',
    '▸': '>',
    '◂': '<',
    '⚙': '[*]',
    '🧹': '[janitor]',
    '📦': '[pkg]',
    '📁': '[dir]',
    '📄': '[file]',
    '🔍': '[search]',
    '⚙️': '[config]',
    '🚀': '[launch]',
    '💾': '[save]',
    '🔧': '[tool]',
    '📊': '[stats]',

    # Additional Unicode arrows that might appear in code
    '⟶': '->',
    '⟹': '=>',
    '⟷': '<->',
}


def detect_terminal_encoding() -> str:
    """Detect the terminal's encoding capability.

    Returns:
        str: Terminal encoding ('utf-8', 'cp1252', 'ascii', etc.)
    """
    # Try stdout encoding first
    if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding:
        encoding = sys.stdout.encoding.lower()
        return encoding

    # Fallback to locale
    try:
        encoding = locale.getpreferredencoding().lower()
        return encoding
    except Exception:
        pass

    # Ultimate fallback
    return 'ascii'


def is_utf8_capable() -> bool:
    """Check if the terminal can handle UTF-8 Unicode characters.

    Returns:
        bool: True if terminal supports UTF-8, False otherwise
    """
    encoding = detect_terminal_encoding()

    # UTF-8 variants that support Unicode
    utf8_encodings = ['utf-8', 'utf8', 'utf_8']

    return encoding in utf8_encodings


def sanitize_for_terminal(text: str) -> str:
    """Replace Unicode icons with ASCII equivalents if terminal doesn't support UTF-8.

    Args:
        text: Text potentially containing Unicode icons

    Returns:
        str: Sanitized text safe for current terminal
    """
    if is_utf8_capable():
        return text

    # Replace all known problematic Unicode characters
    sanitized = text
    for unicode_char, ascii_replacement in ICON_MAP.items():
        sanitized = sanitized.replace(unicode_char, ascii_replacement)

    return sanitized


def create_safe_print() -> Callable:
    """Create a print function that automatically sanitizes output.

    Returns:
        Callable: Safe print function
    """
    def safe_print(*args, **kwargs):
        """Print with automatic Unicode sanitization."""
        # Sanitize all string arguments
        sanitized_args = []
        for arg in args:
            if isinstance(arg, str):
                sanitized_args.append(sanitize_for_terminal(arg))
            else:
                sanitized_args.append(arg)

        print(*sanitized_args, **kwargs)

    return safe_print


# Module-level flag for encoding status
UTF8_CAPABLE = is_utf8_capable()
TERMINAL_ENCODING = detect_terminal_encoding()


# Export safe print function
safe_print = create_safe_print()


def log_encoding_status():
    """Log the detected terminal encoding status (for debugging)."""
    status = "UTF-8 capable" if UTF8_CAPABLE else f"Non-UTF-8 ({TERMINAL_ENCODING})"
    safe_print(f"[Terminal encoding: {status}]")
