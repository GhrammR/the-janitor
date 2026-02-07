"""Universal Wisdom Registry for framework-aware symbol immortality detection."""
import json
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class WisdomRule:
    """A normalized wisdom rule."""
    pattern: str
    match_type: str  # 'exact', 'prefix', 'suffix', 'decorator', 'syntax'
    framework: str
    tier: str = "community"  # 'community' or 'premium'
    reason: str = ""


class WisdomRegistry:
    """Loads and normalizes all framework immortality rules from rules/ directory.

    Supports Open Core licensing model:
    - Community rules: rules/community/ (MIT licensed)
    - Premium rules: rules/premium/ (Proprietary)
    """

    def __init__(self, rules_dir: Path = None):
        """Initialize the wisdom registry.

        Args:
            rules_dir: Path to rules directory (defaults to project_root/rules)
        """
        if rules_dir is None:
            # Default to project_root/rules
            rules_dir = Path(__file__).parent.parent.parent / "rules"

        self.rules_dir = Path(rules_dir)
        self.python_rules: List[WisdomRule] = []
        self.js_rules: List[WisdomRule] = []

        # Track licensing tiers
        self.community_rules_count = 0
        self.premium_rules_count = 0
        self.has_premium = False

        # Cached lookup tables for fast matching
        self._py_exact: Set[str] = set()
        self._py_prefix: Set[str] = set()
        self._py_suffix: Set[str] = set()
        self._py_decorator: Set[str] = set()
        self._py_syntax: Set[str] = set()

        self._js_exact: Set[str] = set()
        self._js_suffix: Set[str] = set()
        self._js_syntax: Set[str] = set()

        self._load_all_rules()

    def _load_all_rules(self):
        """Load JSON files from both community/ and premium/ directories."""
        if not self.rules_dir.exists():
            print(f"[WisdomRegistry] Warning: Rules directory not found: {self.rules_dir}")
            return

        # Load community rules (always present)
        community_dir = self.rules_dir / "community"
        if community_dir.exists():
            initial_count = len(self.python_rules) + len(self.js_rules)
            self._load_rules_from_directory(community_dir, tier="community")
            self.community_rules_count = len(self.python_rules) + len(self.js_rules) - initial_count

        # Load premium rules (optional)
        premium_dir = self.rules_dir / "premium"
        if premium_dir.exists():
            initial_count = len(self.python_rules) + len(self.js_rules)
            self._load_rules_from_directory(premium_dir, tier="premium")
            self.premium_rules_count = len(self.python_rules) + len(self.js_rules) - initial_count
            self.has_premium = self.premium_rules_count > 0

        # Build lookup tables
        self._build_lookup_tables()

    def _load_rules_from_directory(self, directory: Path, tier: str):
        """Load all JSON files from a specific directory.

        Args:
            directory: Path to directory containing JSON rule files
            tier: Licensing tier ('community' or 'premium')
        """
        for json_file in directory.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # DO NOT CRASH if file is malformed (e.g. is a list instead of a dict)
                if not isinstance(data, dict):
                    print(f"[WisdomRegistry] WARNING: Rule file {json_file.name} is malformed (expected dict, got {type(data).__name__}). Skipping.")
                    continue

                # Determine file type and load accordingly
                filename = json_file.stem.lower()

                if 'immortality_rules' in data:
                    # List-based Python framework rules
                    self._load_immortality_rules(data, filename, tier)
                elif 'suffix_matches' in data or 'exact_matches' in data:
                    # Meta patterns (Python)
                    self._load_meta_patterns(data, filename, tier)
                else:
                    # Framework-keyed rules (JS/TS)
                    self._load_framework_keyed_rules(data, filename, tier)

            except json.JSONDecodeError as e:
                print(f"[WisdomRegistry] Error decoding JSON in {json_file.name}: {e}")
            except Exception as e:
                print(f"[WisdomRegistry] Error loading {json_file.name}: {e}")

    def _load_immortality_rules(self, data: dict, source: str, tier: str):
        """Load list-based immortality rules (Python frameworks)."""
        for rule in data.get('immortality_rules', []):
            framework = rule.get('framework', 'Unknown')

            # Decorator patterns
            for pattern in rule.get('patterns', []):
                if pattern.startswith('@'):
                    self.python_rules.append(WisdomRule(
                        pattern=pattern,
                        match_type='decorator',
                        framework=framework,
                        tier=tier,
                        reason=f"{framework} framework pattern"
                    ))
                else:
                    # Syntax marker
                    self.python_rules.append(WisdomRule(
                        pattern=pattern,
                        match_type='syntax',
                        framework=framework,
                        tier=tier,
                        reason=f"{framework} syntax marker"
                    ))

    def _load_meta_patterns(self, data: dict, source: str, tier: str):
        """Load category-based meta patterns (Python)."""
        # Suffix matches
        for suffix in data.get('suffix_matches', []):
            self.python_rules.append(WisdomRule(
                pattern=suffix,
                match_type='suffix',
                framework='Meta',
                tier=tier,
                reason="Meta pattern suffix match"
            ))

        # Prefix matches
        for prefix in data.get('prefix_matches', []):
            self.python_rules.append(WisdomRule(
                pattern=prefix,
                match_type='prefix',
                framework='Meta',
                tier=tier,
                reason="Meta pattern prefix match"
            ))

        # Exact matches
        for exact in data.get('exact_matches', []):
            self.python_rules.append(WisdomRule(
                pattern=exact,
                match_type='exact',
                framework='Meta',
                tier=tier,
                reason="Meta pattern exact match"
            ))

        # Syntax markers
        for syntax in data.get('syntax_markers', []):
            self.python_rules.append(WisdomRule(
                pattern=syntax,
                match_type='syntax',
                framework='Meta',
                tier=tier,
                reason="Python syntax marker"
            ))

    def _load_framework_keyed_rules(self, data: dict, source: str, tier: str):
        """Load framework-keyed rules (JS/TS frameworks)."""
        for framework, rules in data.items():
            if not isinstance(rules, dict):
                continue

            # Syntax markers
            for syntax in rules.get('syntax_markers', []):
                self.js_rules.append(WisdomRule(
                    pattern=syntax,
                    match_type='syntax',
                    framework=framework,
                    tier=tier,
                    reason=f"{framework} syntax marker"
                ))

    def _build_lookup_tables(self):
        """Build fast lookup tables from rules."""
        # Reset tables
        self._py_exact = {}
        self._py_prefix = {}
        self._py_suffix = {}
        self._py_decorator = {}
        self._py_syntax = {}

        self._js_exact = {}
        self._js_suffix = {}
        self._js_syntax = {}

        # Python lookup tables
        for rule in self.python_rules:
            if rule.match_type == 'exact':
                self._py_exact[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'prefix':
                self._py_prefix[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'suffix':
                self._py_suffix[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'decorator':
                self._py_decorator[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'syntax':
                self._py_syntax[rule.pattern] = (rule.framework, rule.tier)

        # JS lookup tables
        for rule in self.js_rules:
            if rule.match_type == 'exact':
                self._js_exact[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'suffix':
                self._js_suffix[rule.pattern] = (rule.framework, rule.tier)
            elif rule.match_type == 'syntax':
                self._js_syntax[rule.pattern] = (rule.framework, rule.tier)

    def is_immortal(self, symbol_name: str, full_text: str, language: str = 'python') -> tuple[bool, str, str, str]:
        """Check if a symbol is immortal (protected from deletion).

        Args:
            symbol_name: Name of the symbol (e.g., 'audit', 'UsedClass.__init__')
            full_text: Full text of the symbol definition (includes decorators)
            language: Language ('python', 'javascript', 'typescript')

        Returns:
            Tuple of (is_immortal, reason, framework, tier)
        """
        if language == 'python':
            return self._check_python_immortality(symbol_name, full_text)
        elif language in ['javascript', 'typescript']:
            return self._check_js_immortality(symbol_name, full_text)
        else:
            return False, "", "", ""

    def _check_python_immortality(self, symbol_name: str, full_text: str) -> tuple[bool, str, str, str]:
        """Check Python symbol immortality."""
        # Stage 1: Exact match
        if symbol_name in self._py_exact:
            framework, tier = self._py_exact[symbol_name]
            return True, f"Exact match: {symbol_name}", framework, tier

        # Stage 2: Prefix match (for visitor patterns, etc.)
        for prefix, (framework, tier) in self._py_prefix.items():
            # Check both full name and simple name (after last dot)
            if symbol_name.startswith(prefix):
                return True, f"Prefix match: {prefix}", framework, tier
            # For qualified names like "ClassName.method_name", check the method_name part
            if '.' in symbol_name:
                simple_name = symbol_name.split('.')[-1]
                if simple_name.startswith(prefix):
                    return True, f"Prefix match: {prefix}", framework, tier

        # Stage 3: Decorator patterns
        for decorator, (framework, tier) in self._py_decorator.items():
            if decorator in full_text:
                return True, f"Decorator: {decorator}", framework, tier

        # Stage 4: Suffix match (for decorator-like patterns)
        for suffix, (framework, tier) in self._py_suffix.items():
            # Check if any decorator in full_text ends with this suffix
            lines = full_text.split('\n')
            for line in lines:
                if line.strip().startswith('@') and line.strip().endswith(suffix) or suffix in line:
                    return True, f"Suffix match: {suffix}", framework, tier

        # Stage 5: Syntax markers
        for syntax, (framework, tier) in self._py_syntax.items():
            if syntax in full_text:
                return True, f"Syntax marker: {syntax}", framework, tier

        # Stage 6: Dunder methods are implicitly protected
        if symbol_name.startswith('__') and symbol_name.endswith('__') and len(symbol_name) > 4:
            return True, "Dunder method", "Python", "community"

        # Stage 7: Properties and class methods
        if '@property' in full_text or '@staticmethod' in full_text or '@classmethod' in full_text:
            return True, "Property/class method", "Python", "community"

        return False, "", "", ""

    def _check_js_immortality(self, symbol_name: str, full_text: str) -> tuple[bool, str, str, str]:
        """Check JavaScript/TypeScript symbol immortality."""
        # Exact match
        if symbol_name in self._js_exact:
            framework, tier = self._js_exact[symbol_name]
            return True, f"Exact match: {symbol_name}", framework, tier

        # Suffix match
        for suffix, (framework, tier) in self._js_suffix.items():
            if symbol_name.endswith(suffix):
                return True, f"Suffix match: {suffix}", framework, tier

        # Syntax markers
        for syntax, (framework, tier) in self._js_syntax.items():
            if syntax in full_text:
                return True, f"Syntax marker: {syntax}", framework, tier

        # Export statements
        if 'export default' in full_text or 'export {' in full_text or 'module.exports' in full_text:
            return True, "Export statement", "JavaScript", "community"

        return False, "", "", ""

    def get_licensing_status(self) -> dict:
        """Get the current licensing tier status.

        Returns:
            Dictionary with licensing information
        """
        total_rules = self.community_rules_count + self.premium_rules_count
        return {
            "tier": "premium" if self.has_premium else "community",
            "community_rules": self.community_rules_count,
            "premium_rules": self.premium_rules_count,
            "total_rules": total_rules,
            "has_premium": self.has_premium
        }
