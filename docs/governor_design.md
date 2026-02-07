```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Logic Fingerprint",
  "description": "A vector-based signature of a code block used to detect semantic duplication and high-entropy 'AI Slop'.",
  "type": "object",
  "properties": {
    "fingerprint_id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique identifier for this specific logic block analysis."
    },
    "metadata": {
      "type": "object",
      "properties": {
        "repository_id": { "type": "string" },
        "file_path": { "type": "string" },
        "language": { "type": "string", "enum": ["python", "typescript", "go", "rust", "java"] },
        "commit_sha": { "type": "string" },
        "timestamp": { "type": "string", "format": "date-time" }
      },
      "required": ["repository_id", "file_path", "language"]
    },
    "structural_metrics": {
      "type": "object",
      "description": "Deterministic metrics derived from AST analysis.",
      "properties": {
        "cyclomatic_complexity": { "type": "integer", "minimum": 0 },
        "cognitive_complexity": { "type": "integer", "minimum": 0 },
        "lines_of_code": { "type": "integer" },
        "dependency_fan_out": { "type": "integer" }
      }
    },
    "slop_indicators": {
      "type": "object",
      "description": "Heuristics specifically tuned to detect generated boilerplate.",
      "properties": {
        "shannon_entropy": { 
          "type": "number", 
          "description": "Measures information density. Very low entropy suggests repetitive boilerplate." 
        },
        "comment_to_code_ratio": { "type": "number" },
        "variable_naming_variance": { 
          "type": "number",
          "description": "Statistical variance in variable name length (AI often uses consistently verbose naming)."
        }
      }
    },
    "vector_hashes": {
      "type": "object",
      "description": "High-dimensional representations of the logic.",
      "properties": {
        "ast_minhash": {
          "type": "string",
          "description": "Locality Sensitive Hash (LSH) of the Abstract Syntax Tree structure."
        },
        "semantic_embedding": {
          "type": "array",
          "description": "384-dim vector representing the 'intent' of the code.",
          "items": { "type": "number" },
          "minItems": 384,
          "maxItems": 384
        }
      }
    }
  },
  "required": ["metadata", "structural_metrics", "vector_hashes"]
}
```

```python
import hashlib
import math
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# Mock dependencies for architectural demonstration
# In production, these would be AST parsers and Vector DB clients (e.g., Pinecone, Qdrant)
class VectorDBClient:
    def search_similar(self, vector: List[float], threshold: float) -> List[Dict]: pass

class CodeEmbeddingModel:
    def embed_code(self, source_code: str) -> List[float]: pass

class RejectionReason(Enum):
    COMPLEXITY_BREACH = "COMPLEXITY_BREACH"
    SEMANTIC_DUPLICATION = "SEMANTIC_DUPLICATION"
    ENTROPY_ANOMALY = "ENTROPY_ANOMALY"

@dataclass
class GatekeeperDecision:
    approved: bool
    reasons: List[RejectionReason]
    score: float
    message: str

class PRGatekeeper:
    """
    The Governor: Analyzes PR diffs to reject AI Slop based on 
    cyclomatic complexity thresholds and semantic vector duplication.
    """

    def __init__(self, 
                 vector_db: VectorDBClient, 
                 embedder: CodeEmbeddingModel,
                 complexity_threshold: int = 15,
                 similarity_threshold: float = 0.92,
                 entropy_min_threshold: float = 3.5):
        
        self.vector_db = vector_db
        self.embedder = embedder
        self.complexity_threshold = complexity_threshold
        self.similarity_threshold = similarity_threshold
        self.entropy_min_threshold = entropy_min_threshold
        self.logger = logging.getLogger("TheGovernor")

    def process_pr(self, pr_diff_map: Dict[str, str]) -> GatekeeperDecision:
        """
        Main entry point. Iterates through changed files in the PR.
        
        :param pr_diff_map: Dict mapping file_paths to their raw source code content.
        """
        rejection_reasons = []
        cumulative_risk_score = 0.0

        for file_path, source_code in pr_diff_map.items():
            # 1. Generate Logic Fingerprint
            fingerprint = self._generate_fingerprint(source_code)
            
            # 2. Check Complexity (The "Slop" Filter - overly verbose/complex)
            if fingerprint['structural_metrics']['cyclomatic_complexity'] > self.complexity_threshold:
                self.logger.warning(f"Complexity breach in {file_path}")
                rejection_reasons.append(RejectionReason.COMPLEXITY_BREACH)
                cumulative_risk_score += 0.4

            # 3. Check Entropy (The "Boilerplate" Filter)
            if fingerprint['slop_indicators']['shannon_entropy'] < self.entropy_min_threshold:
                 rejection_reasons.append(RejectionReason.ENTROPY_ANOMALY)
                 cumulative_risk_score += 0.2

            # 4. Check Semantic Duplication (The "DRY" Filter)
            if self._is_semantic_duplicate(fingerprint['vector_hashes']['semantic_embedding']):
                self.logger.warning(f"Semantic duplication detected in {file_path}")
                rejection_reasons.append(RejectionReason.SEMANTIC_DUPLICATION)
                cumulative_risk_score += 0.5

        if rejection_reasons:
            return GatekeeperDecision(
                approved=False,
                reasons=list(set(rejection_reasons)),
                score=cumulative_risk_score,
                message="PR rejected by The Governor: High probability of unoptimized AI generation or duplication."
            )

        return GatekeeperDecision(approved=True, reasons=[], score=0.0, message="PR Clean.")

    def _generate_fingerprint(self, source_code: str) -> Dict[str, Any]:
        """
        Orchestrates the creation of the JSON Schema defined fingerprint.
        """
        return {
            "structural_metrics": {
                "cyclomatic_complexity": self._calculate_cyclomatic_complexity(source_code),
                # ... other metrics
            },
            "slop_indicators": {
                "shannon_entropy": self._calculate_shannon_entropy(source_code)
            },
            "vector_hashes": {
                "semantic_embedding": self.embedder.embed_code(source_code)
            }
        }

    def _is_semantic_duplicate(self, vector: List[float]) -> bool:
        """
        Queries the vector database to see if this logic exists elsewhere 
        in the codebase, even if phrased differently.
        """
        results = self.vector_db.search_similar(vector, self.similarity_threshold)
        return len(results) > 0

    def _calculate_cyclomatic_complexity(self, code: str) -> int:
        """
        Parses AST to calculate cyclomatic complexity by counting control flow branches.
        """
        try:
            import ast
            tree = ast.parse(code)
            
            class ComplexityVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.complexity = 1
                    
                def visit_If(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_While(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_For(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_AsyncFor(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_With(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_AsyncWith(self, node):
                    self.complexity += 1
                    self.generic_visit(node)
                    
                def visit_ExceptHandler(self, node):
                    self.complexity += 1
                    self.generic_visit(node)

            visitor = ComplexityVisitor()
            visitor.visit(tree)
            return visitor.complexity
        except Exception:
            # Fallback if parsing fails (e.g. invalid syntax)
            return 1

    def _calculate_shannon_entropy(self, code: str) -> float:
        """
        Calculates Shannon entropy to detect low-information density (repetitive AI slop).
        """
        if not code:
            return 0.0
        entropy = 0.0
        length = len(code)
        # Count byte frequencies
        counts = {}
        for char in code:
            counts[char] = counts.get(char, 0) + 1
        
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy
```