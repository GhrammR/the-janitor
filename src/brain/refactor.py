"""LLM-powered code refactoring for merging similar functions."""
from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from .llm import LLMClient
import sys
import ast
import re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.analyzer.extractor import Entity


@dataclass
class RefactorPlan:
    """Refactoring plan for merging similar functions."""
    entity1: Entity
    entity2: Entity
    similarity: float
    merged_code: Optional[str]
    is_identical: bool
    estimated_lines_saved: int


class ASTStructuralAnalyzer:
    """AST-based structural analysis for control-flow verification."""

    @staticmethod
    def count_control_flow_nodes(code: str) -> Dict[str, int]:
        """Count control-flow nodes in Python code.

        HYBRID VERIFICATION: Prevents merging functions that are textually similar
        but structurally different (different logic).

        Args:
            code: Python source code

        Returns:
            Dictionary with counts of if, for, while, return statements
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If code doesn't parse, return zeros (will fail structural check)
            return {"if": 0, "for": 0, "while": 0, "return": 0}

        counts = {"if": 0, "for": 0, "while": 0, "return": 0}

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                counts["if"] += 1
            elif isinstance(node, ast.For):
                counts["for"] += 1
            elif isinstance(node, ast.While):
                counts["while"] += 1
            elif isinstance(node, ast.Return):
                counts["return"] += 1

        return counts

    @staticmethod
    def structural_divergence(counts1: Dict[str, int], counts2: Dict[str, int]) -> float:
        """Calculate structural divergence between two control-flow profiles.

        Args:
            counts1: Control-flow counts for function 1
            counts2: Control-flow counts for function 2

        Returns:
            Divergence percentage (0.0 = identical, 1.0 = 100% different)
        """
        total_nodes1 = sum(counts1.values())
        total_nodes2 = sum(counts2.values())

        # Edge case: both functions have zero control-flow nodes (pure expressions)
        if total_nodes1 == 0 and total_nodes2 == 0:
            return 0.0

        # Edge case: one has control flow, one doesn't
        if total_nodes1 == 0 or total_nodes2 == 0:
            return 1.0

        # Calculate absolute difference for each node type
        total_diff = 0
        for key in counts1.keys():
            total_diff += abs(counts1[key] - counts2[key])

        # Normalize by the average total nodes
        avg_nodes = (total_nodes1 + total_nodes2) / 2
        divergence = total_diff / avg_nodes

        return divergence

    @staticmethod
    def are_structurally_compatible(entity1: Entity, entity2: Entity, threshold: float = 0.20) -> bool:
        """Check if two entities are structurally compatible for merging.

        CRITICAL: This is the AST PRE-FILTER that prevents semantic blindness.
        Rejects matches where functions are textually similar but logically different.

        Args:
            entity1: First entity
            entity2: Second entity
            threshold: Maximum allowed structural divergence (default 20%)

        Returns:
            True if structurally compatible (divergence <= threshold)
        """
        counts1 = ASTStructuralAnalyzer.count_control_flow_nodes(entity1.full_text)
        counts2 = ASTStructuralAnalyzer.count_control_flow_nodes(entity2.full_text)

        divergence = ASTStructuralAnalyzer.structural_divergence(counts1, counts2)

        return divergence <= threshold


class SemanticRefactor:
    """LLM-powered refactoring for merging similar code."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize refactor engine.

        Args:
            llm_client: LLM client (creates one if None)
        """
        self.llm = llm_client or LLMClient()

    @staticmethod
    def _extract_imports(code: str) -> Set[str]:
        """Extract import statements from Python code.

        SCOPE AWARENESS: Identifies dependencies that must be hoisted when merging.

        Args:
            code: Python source code

        Returns:
            Set of import statement strings
        """
        imports = set()

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return imports

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        imports.add(f"import {alias.name} as {alias.asname}")
                    else:
                        imports.add(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        imports.add(f"from {module} import *")
                    elif alias.asname:
                        imports.add(f"from {module} import {alias.name} as {alias.asname}")
                    else:
                        imports.add(f"from {module} import {alias.name}")

        return imports

    @staticmethod
    def _check_global_state_leak(code: str) -> tuple[bool, list[str]]:
        """Check if merged code references unsafe global state.

        v4.2.0: PRIVATE MEMBER & GLOBAL STATE GUARD
        Performs static analysis to detect references to variables that are:
        - NOT in the helper function's parameters
        - NOT in the safe globals list (builtins, common libraries)

        Args:
            code: Merged Python code to analyze

        Returns:
            Tuple of (is_safe, unsafe_references)
            - is_safe: False if unsafe state leak detected
            - unsafe_references: List of variable names that are unsafe
        """
        # Safe global modules/names that are allowed
        SAFE_GLOBALS = {
            # Python builtins
            'True', 'False', 'None', 'len', 'range', 'str', 'int', 'float', 'bool',
            'list', 'dict', 'set', 'tuple', 'type', 'isinstance', 'hasattr', 'getattr',
            'setattr', 'print', 'input', 'open', 'enumerate', 'zip', 'map', 'filter',
            'sum', 'min', 'max', 'abs', 'round', 'sorted', 'reversed', 'all', 'any',
            # Common standard library modules
            'os', 'sys', 'json', 'time', 'datetime', 'math', 're', 'Path', 'pathlib',
            'typing', 'Optional', 'List', 'Dict', 'Set', 'Tuple', 'Union', 'Any',
        }

        try:
            tree = ast.parse(code)
        except SyntaxError:
            # If code doesn't parse, it will be caught by syntax validation elsewhere
            return True, []

        # Find the helper function (typically named _merged_logic, _shared_impl, etc.)
        helper_func = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Helper functions typically start with '_' and contain 'merge' or 'shared' in name
                if node.name.startswith('_') and ('merge' in node.name.lower() or 'shared' in node.name.lower()):
                    helper_func = node
                    break

        if not helper_func:
            # No helper function found - code might be malformed, but syntax validator will catch it
            return True, []

        # Extract parameter names from helper function
        param_names = {arg.arg for arg in helper_func.args.args}
        # Add 'self' and 'cls' as they might be used in parameters
        param_names.add('self')
        param_names.add('cls')

        # Collect all Name nodes (variable references) in the helper function
        unsafe_refs = []
        for node in ast.walk(helper_func):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                var_name = node.id
                # Check if this variable is NOT safe
                if (var_name not in param_names and
                    var_name not in SAFE_GLOBALS and
                    not var_name.startswith('_merged') and  # Allow recursive calls
                    not var_name.startswith('_shared')):
                    unsafe_refs.append(var_name)

        # Deduplicate and return
        unsafe_refs = sorted(set(unsafe_refs))
        is_safe = len(unsafe_refs) == 0

        return is_safe, unsafe_refs

    def _clean_response(self, response: str) -> str:
        """Strip Markdown artifacts and explanatory text from LLM response.

        Handles:
        - Markdown code blocks (```python ... ```)
        - Explanatory text before code
        - Multiple code blocks
        - Text interspersed with code

        Args:
            response: Raw LLM response

        Returns:
            Clean Python code only
        """
        # Remove Markdown code blocks (```python ... ``` or ``` ... ```)
        # Use re.DOTALL to match across newlines
        cleaned = re.sub(r'```(?:python)?\s*\n?(.*?)\n?```', r'\1', response, flags=re.DOTALL)

        # If no markdown blocks found, use original response
        if cleaned == response:
            cleaned = response

        # Strip leading/trailing whitespace
        cleaned = cleaned.strip()

        # If the response starts with explanatory text before 'def', remove it
        # Find the first 'def', 'class', 'import', or 'from' keyword
        match = re.search(r'^\s*(def|class|import|from)\s', cleaned, re.MULTILINE)
        if match:
            # There's text before the first Python keyword - strip it
            start_pos = match.start()
            if start_pos > 0:
                cleaned = cleaned[start_pos:]

        return cleaned.strip()

    def merge_similar_functions(self, entity1: Entity, entity2: Entity, similarity: float) -> RefactorPlan:
        """Merge two similar functions into one generic function.

        RULE: If similarity == 1.0 (exact text match), DO NOT call the LLM.
        Just report "Identical".

        Args:
            entity1: First function entity
            entity2: Second function entity
            similarity: Similarity score (0.0-1.0)

        Returns:
            RefactorPlan with merge suggestion
        """
        # Calculate estimated lines saved
        lines1 = len(entity1.full_text.split('\n'))
        lines2 = len(entity2.full_text.split('\n'))
        estimated_lines_saved = lines1 + lines2

        # RULE: If similarity == 1.0, they're identical - skip LLM
        if similarity >= 0.999:  # Use 0.999 to handle floating point precision
            return RefactorPlan(
                entity1=entity1,
                entity2=entity2,
                similarity=similarity,
                merged_code=None,
                is_identical=True,
                estimated_lines_saved=lines2  # Only save one copy
            )

        # v4.0.0-beta.2: HYBRID AST-VECTOR VERIFICATION
        # Pre-filter: Reject if structurally incompatible (>20% control-flow divergence)
        if not ASTStructuralAnalyzer.are_structurally_compatible(entity1, entity2):
            print(f"[AST PRE-FILTER] Structural divergence too high: {entity1.name} vs {entity2.name}")
            print(f"[AST PRE-FILTER] Rejecting merge despite {similarity:.1%} lexical similarity")
            return RefactorPlan(
                entity1=entity1,
                entity2=entity2,
                similarity=similarity,
                merged_code=None,
                is_identical=False,
                estimated_lines_saved=0
            )

        # v4.0.0-beta.2: SCOPE AWARENESS - Extract imports and context
        imports1 = self._extract_imports(entity1.full_text)
        imports2 = self._extract_imports(entity2.full_text)
        all_imports = sorted(imports1.union(imports2))
        imports_context = "\n".join(all_imports) if all_imports else "# No imports"

        # Extract parent class context for stateful methods
        parent_context1 = f"(class: {entity1.parent_class})" if entity1.parent_class else "(standalone function)"
        parent_context2 = f"(class: {entity2.parent_class})" if entity2.parent_class else "(standalone function)"

        # v4.2.0: METADATA PRESERVATION - Extract decorator information
        decorators1 = entity1.decorators if entity1.decorators else []
        decorators2 = entity2.decorators if entity2.decorators else []
        decorators_context1 = ", ".join(decorators1) if decorators1 else "no decorators"
        decorators_context2 = ", ".join(decorators2) if decorators2 else "no decorators"

        # Use LLM to merge similar (but not identical) functions
        # v3.7.0: Safe Proxy Pattern - Preserves original function signatures
        # v4.0.0-beta.2: State & Scope Awareness
        # v4.1.1: Billing constraint for frontier-tier reliability
        # v4.2.0: Metadata preservation & private member safety
        system_prompt = """You are a code refactoring expert. Your task is to merge two similar functions using the SAFE PROXY PATTERN.

BILLING CONSTRAINT (v4.1.1 - CRITICAL):
You are being billed per character. Any conversational text, markdown formatting, or comments in your response will be considered a security breach. Output ONLY the executable Python code. No explanations, no code blocks, no markdown - just raw Python that can be immediately parsed by ast.parse().

CRITICAL REQUIREMENTS (Brain Safety):
1. **DO NOT change the original function names or signatures**
2. **USE THE WRAPPER PATTERN**:
   - Create a shared internal helper function (e.g., `_merged_logic`, `_shared_impl`)
   - Keep both original functions as thin wrappers that call the helper
   - Example:
     ```python
     def _merged_logic(x, y, mode='default'):
         # Shared implementation here
         pass

     def original_func_a(x):
         return _merged_logic(x, None, mode='a')

     def original_func_b(y):
         return _merged_logic(None, y, mode='b')
     ```
3. **DO NOT remove any side effects, logging, or defensive try/except blocks**
4. **Preserve all error handling and telemetry**
5. **The code must be syntactically valid** (parseable by ast.parse)

STATE & SCOPE AWARENESS (v4.0.0-beta.2):
6. **If functions are class methods**, preserve `self` or `cls` references:
   - The helper function must accept the instance/class as a parameter
   - Example for methods:
     ```python
     def _merged_logic(instance, x, mode='default'):
         # Use instance.attribute instead of self.attribute
         pass

     def method_a(self, x):
         return _merged_logic(self, x, mode='a')
     ```
7. **If functions use different imports**, you MUST include ALL required imports at the top of your response
8. **Maintain variable scope** - do not introduce global variables or closure leaks

METADATA PRESERVATION (v4.2.0 - ENTERPRISE CRITICAL):
9. **DECORATORS MUST BE PRESERVED**:
   - You MUST preserve all decorators (e.g., @property, @staticmethod, @classmethod, @lru_cache) on the wrapper functions
   - The wrapper functions MUST retain their original decorators to maintain identical behavior
   - If both functions share the same decorator, it stays on BOTH wrappers (not moved to helper)
   - The `_merged_logic` helper is NEVER decorated (it's an internal implementation detail)
   - Example:
     ```python
     def _merged_logic(instance, x):
         return x * 2

     @property
     def prop_a(self):
         return _merged_logic(self, self.value_a)

     @property
     def prop_b(self):
         return _merged_logic(self, self.value_b)
     ```

PRIVATE MEMBER SAFETY (v4.2.0 - NAME MANGLING GUARD):
10. **PRIVATE ATTRIBUTES** (self.__var):
    - If methods access private attributes (self.__var), you MUST pass them as explicit arguments to the helper
    - This avoids Python name mangling issues (ClassName__var)
    - Example:
      ```python
      def _merged_logic(private_val, x):
          return private_val + x

      def method_a(self, x):
          return _merged_logic(self.__private, x)
      ```

OUTPUT REQUIREMENTS (CRITICAL):
- OUTPUT ONLY THE RAW PYTHON CODE
- DO NOT INCLUDE MARKDOWN CODE BLOCKS (no ``` markers)
- DO NOT INCLUDE COMMENTS OR EXPLANATIONS
- DO NOT INCLUDE ANY TEXT BEFORE OR AFTER THE CODE
- IF YOU INCLUDE ANYTHING OTHER THAN PURE PYTHON CODE, THE SYSTEM WILL REJECT YOUR OUTPUT
- START YOUR RESPONSE IMMEDIATELY WITH 'import' (if needed) OR 'def' OR 'class'

The goal is ZERO BREAKING CHANGES to existing call sites."""

        user_prompt = f"""Merge these two similar functions using the Safe Proxy Pattern (similarity: {similarity:.1%}):

CONTEXT:
- Required imports (merge these at top of response):
```python
{imports_context}
```

FUNCTION 1 {parent_context1} [{decorators_context1}] from {entity1.file_path}:{entity1.start_line}:
```python
{entity1.full_text}
```

FUNCTION 2 {parent_context2} [{decorators_context2}] from {entity2.file_path}:{entity2.start_line}:
```python
{entity2.full_text}
```

CRITICAL REQUIREMENTS:
- Function 1 decorators ({decorators_context1}) MUST be preserved on wrapper 1
- Function 2 decorators ({decorators_context2}) MUST be preserved on wrapper 2
- If methods access private attributes (self.__var), pass them as arguments to helper

Generate:
1. ALL required imports (if any) at the top
2. One internal helper function with shared logic (NO decorators on helper)
3. Both original functions as wrappers (unchanged signatures WITH original decorators)

Return ONLY the Python code (imports + three functions)."""

        # Call LLM
        raw_response = self.llm.ask_llm_with_fallback(system_prompt, user_prompt)

        # v3.9.4: AGGRESSIVE CLEANING - Strip Markdown and explanatory text
        merged_code = self._clean_response(raw_response) if raw_response else None

        # v3.7.0: SYNTAX VALIDATION - Prevent LLM slop from entering the system
        if merged_code:
            try:
                ast.parse(merged_code)
            except SyntaxError as e:
                print(f"[BRAIN SAFETY] LLM generated invalid syntax: {e}")
                print(f"[BRAIN SAFETY] Raw response preview: {raw_response[:200]}...")
                print(f"[BRAIN SAFETY] Cleaned code preview: {merged_code[:200]}...")
                print(f"[BRAIN SAFETY] Discarding unsafe refactor plan for {entity1.name} + {entity2.name}")
                # Return plan with no merged_code (treated as failed merge)
                return RefactorPlan(
                    entity1=entity1,
                    entity2=entity2,
                    similarity=similarity,
                    merged_code=None,
                    is_identical=False,
                    estimated_lines_saved=0
                )

            # v4.2.0: GLOBAL STATE LEAK DETECTION - Prevent unsafe variable references
            is_safe, unsafe_refs = self._check_global_state_leak(merged_code)
            if not is_safe:
                print(f"[STATE GUARD] Unsafe global state leak detected in merge: {', '.join(unsafe_refs)}")
                print(f"[STATE GUARD] Helper function references variables not in its parameters")
                print(f"[STATE GUARD] Unsafe variables: {unsafe_refs}")
                print(f"[STATE GUARD] Discarding unsafe refactor plan for {entity1.name} + {entity2.name}")
                # Return plan with no merged_code (treated as failed merge)
                return RefactorPlan(
                    entity1=entity1,
                    entity2=entity2,
                    similarity=similarity,
                    merged_code=None,
                    is_identical=False,
                    estimated_lines_saved=0
                )

        return RefactorPlan(
            entity1=entity1,
            entity2=entity2,
            similarity=similarity,
            merged_code=merged_code,
            is_identical=False,
            estimated_lines_saved=estimated_lines_saved
        )
