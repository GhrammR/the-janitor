"""LLM-powered code refactoring for merging similar functions."""
from dataclasses import dataclass
from typing import List, Optional
from .llm import LLMClient
import sys
import ast
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzer.extractor import Entity


@dataclass
class RefactorPlan:
    """Refactoring plan for merging similar functions."""
    entity1: Entity
    entity2: Entity
    similarity: float
    merged_code: Optional[str]
    is_identical: bool
    estimated_lines_saved: int


class SemanticRefactor:
    """LLM-powered refactoring for merging similar code."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """Initialize refactor engine.

        Args:
            llm_client: LLM client (creates one if None)
        """
        self.llm = llm_client or LLMClient()

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

        # Use LLM to merge similar (but not identical) functions
        # v3.7.0: Safe Proxy Pattern - Preserves original function signatures
        system_prompt = """You are a code refactoring expert. Your task is to merge two similar functions using the SAFE PROXY PATTERN.

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
5. **Return ONLY valid Python code** - no explanations, no markdown formatting
6. **The code must be syntactically valid** (parseable by ast.parse)

The goal is ZERO BREAKING CHANGES to existing call sites."""

        user_prompt = f"""Merge these two similar functions using the Safe Proxy Pattern (similarity: {similarity:.1%}):

FUNCTION 1 from {entity1.file_path}:{entity1.start_line}:
```python
{entity1.full_text}
```

FUNCTION 2 from {entity2.file_path}:{entity2.start_line}:
```python
{entity2.full_text}
```

Generate:
1. One internal helper function with shared logic
2. Both original functions as wrappers (unchanged signatures)

Return ONLY the Python code with all three functions."""

        # Call LLM
        merged_code = self.llm.ask_llm_with_fallback(system_prompt, user_prompt)

        # v3.7.0: SYNTAX VALIDATION - Prevent LLM slop from entering the system
        if merged_code:
            try:
                ast.parse(merged_code)
            except SyntaxError as e:
                print(f"[BRAIN SAFETY] LLM generated invalid syntax: {e}")
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

        return RefactorPlan(
            entity1=entity1,
            entity2=entity2,
            similarity=similarity,
            merged_code=merged_code,
            is_identical=False,
            estimated_lines_saved=estimated_lines_saved
        )
