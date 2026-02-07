"""Tree-sitter parser for multi-language code analysis."""
from pathlib import Path
from typing import Optional
from tree_sitter import Language, Parser, Tree
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript


class LanguageParser:
    """Multi-language parser using tree-sitter v0.22+ API."""

    SUPPORTED_LANGUAGES = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
    }

    def __init__(self, language: str):
        """Initialize parser for given language (python, typescript, javascript).

        Args:
            language: One of 'python', 'typescript', 'javascript'

        Raises:
            ValueError: If language is not supported
        """
        self.language = language
        self.parser = self._create_parser()

    def _create_parser(self) -> Parser:
        """Factory method using tree-sitter v0.25+ API.

        CRITICAL: Uses Parser(Language(capsule)) syntax with latest tree-sitter.

        Returns:
            Configured Parser instance

        Raises:
            ValueError: If language is not supported
        """
        if self.language == 'python':
            lang = Language(tspython.language())
        elif self.language == 'javascript':
            lang = Language(tsjavascript.language())
        elif self.language == 'typescript':
            # TypeScript language binding
            lang = Language(tstypescript.language_typescript())
        else:
            raise ValueError(f"Unsupported language: {self.language}")

        # v0.25+ API: Pass language to Parser constructor
        return Parser(lang)

    def parse_file(self, file_path: str | Path) -> Optional[Tree]:
        """Parse file and return tree-sitter Tree.

        Args:
            file_path: Path to source file to parse

        Returns:
            Parsed Tree object, or None if parsing failed
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return None

        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
            return self.parser.parse(source_code)
        except (UnicodeDecodeError, IOError):
            # Skip binary files or unreadable files
            return None

    @classmethod
    def from_file_extension(cls, file_path: str | Path) -> Optional['LanguageParser']:
        """Create parser based on file extension.

        Args:
            file_path: Path to determine language from

        Returns:
            LanguageParser instance, or None if extension not supported
        """
        file_path = Path(file_path)
        extension = file_path.suffix.lower()

        language = cls.SUPPORTED_LANGUAGES.get(extension)
        if language:
            return cls(language)
        return None
