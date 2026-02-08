"""Semantic memory using ChromaDB for entity similarity detection."""

# CRITICAL: Nuclear telemetry suppression BEFORE any imports
import os
import sys
import warnings

# Set environment variables
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_DB_TELEMETRY_OPTOUT"] = "True"

# Suppress all ChromaDB warnings
warnings.filterwarnings("ignore", category=UserWarning, module="chromadb")

from pathlib import Path
from typing import List, Dict

# Import ChromaDB and immediately monkey-patch telemetry
import chromadb
from chromadb import PersistentClient, Settings
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

# Monkey-patch telemetry to be a no-op
try:
    from chromadb.telemetry.product import posthog
    if hasattr(posthog, 'Posthog'):
        # Replace capture method with no-op
        posthog.Posthog.capture = lambda *args, **kwargs: None
except (ImportError, AttributeError):
    pass  # Telemetry module not available or already disabled

import hashlib
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.analyzer.extractor import Entity


class SemanticMemory:
    """Semantic memory for finding duplicate and similar code entities."""

    def __init__(self, persist_dir: str | Path = ".janitor_db"):
        """Initialize semantic memory with ChromaDB.

        Args:
            persist_dir: Directory to persist ChromaDB data
        """
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client with telemetry disabled
        self.client = PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(anonymized_telemetry=False)
        )

        # Initialize embedding function (all-MiniLM-L6-v2)
        self.embedding_fn = SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2",
            normalize_embeddings=True
        )

    def index_entities(self, entities: List[Entity], language: str = "python"):
        """Index entities into ChromaDB using upsert for idempotency.

        CRITICAL: Uses full_text from Entity (entire function/class body)
        for embedding to ensure unique similarity detection.

        Args:
            entities: List of Entity objects to index
            language: Programming language (used for collection name)
        """
        if not entities:
            return

        collection_name = f"{language}_entities"
        collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=self.embedding_fn,
            metadata={"hnsw:space": "cosine"}
        )

        # Prepare data for upsert
        ids = []
        documents = []
        metadatas = []

        for entity in entities:
            # Create globally unique ID: hash(file_path + qualified_name + start_line)
            # This prevents collisions when multiple entities share the same name
            # (e.g., multiple __init__ methods in different classes in the same file)
            qualified_name = entity.qualified_name if entity.qualified_name else entity.name
            id_string = f"{entity.file_path}::{qualified_name}::{entity.start_line}"
            entity_id = hashlib.sha256(id_string.encode('utf-8')).hexdigest()
            ids.append(entity_id)

            # Use FULL text for embedding (critical for similarity)
            documents.append(entity.full_text)

            # Store metadata including qualified_name for accurate self-match detection
            metadatas.append({
                "file_path": entity.file_path,
                "name": entity.name,
                "qualified_name": qualified_name,
                "type": entity.type,
                "start_line": entity.start_line,
                "end_line": entity.end_line,
                "parent_class": entity.parent_class or ""  # Include parent_class for smart filtering
            })

        # Upsert (idempotent operation)
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )

    def find_similar_entities(
        self,
        entity: Entity,
        language: str = "python",
        threshold: float = 0.90
    ) -> List[Dict]:
        """Find entities similar to given entity.

        CRITICAL: Skips self-matches by comparing file_path and name.

        Args:
            entity: Entity to find similarities for
            language: Programming language
            threshold: Similarity threshold (0.0-1.0)

        Returns:
            List of similar entities with similarity scores
        """
        collection_name = f"{language}_entities"

        try:
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_fn
            )
        except ValueError:
            # Collection doesn't exist
            return []

        # Query for similar entities
        results = collection.query(
            query_texts=[entity.full_text],
            n_results=20,  # Get more results to filter
            include=["distances", "metadatas", "documents"]
        )

        if not results or not results['distances'] or not results['distances'][0]:
            return []

        # Filter and format results
        similar_entities = []

        for i, distance in enumerate(results['distances'][0]):
            # Convert distance to similarity (cosine similarity: 1 - distance)
            similarity = 1 - distance

            # Skip if below threshold
            if similarity < threshold:
                continue

            result_metadata = results['metadatas'][0][i]

            # CRITICAL: Skip self-matches using qualified_name and start_line
            entity_qualified_name = entity.qualified_name if entity.qualified_name else entity.name
            result_qualified_name = result_metadata.get('qualified_name', result_metadata['name'])

            if (result_metadata['file_path'] == entity.file_path and
                result_qualified_name == entity_qualified_name and
                result_metadata['start_line'] == entity.start_line):
                continue

            similar_entities.append({
                "id": results['ids'][0][i],
                "similarity": similarity,
                "file_path": result_metadata['file_path'],
                "name": result_metadata['name'],
                "qualified_name": result_metadata.get('qualified_name', result_metadata['name']),
                "type": result_metadata['type'],
                "start_line": result_metadata['start_line'],
                "end_line": result_metadata['end_line'],
                "parent_class": result_metadata.get('parent_class', ''),  # Include parent_class for smart filtering
                "full_text": results['documents'][0][i]
            })

        # Sort by similarity (highest first)
        similar_entities.sort(key=lambda x: x['similarity'], reverse=True)

        return similar_entities

    def get_collection_stats(self, language: str = "python") -> Dict:
        """Get statistics about indexed entities.

        Args:
            language: Programming language

        Returns:
            Dictionary with collection statistics
        """
        collection_name = f"{language}_entities"

        try:
            collection = self.client.get_collection(name=collection_name)
            count = collection.count()

            return {
                "collection_name": collection_name,
                "entity_count": count,
                "persist_dir": str(self.persist_dir)
            }
        except ValueError:
            return {
                "collection_name": collection_name,
                "entity_count": 0,
                "persist_dir": str(self.persist_dir)
            }

    def clear_collection(self, language: str = "python"):
        """Clear all entities from collection.

        Args:
            language: Programming language
        """
        collection_name = f"{language}_entities"

        try:
            self.client.delete_collection(name=collection_name)
        except ValueError:
            # Collection doesn't exist
            pass
