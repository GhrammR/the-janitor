"""Deletion manifest management for safe file restoration."""
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import hashlib


class Manifest:
    """Manage JSON manifest for tracking deleted files."""

    def __init__(self, trash_dir: str | Path):
        """Initialize manifest.

        Args:
            trash_dir: Path to trash directory
        """
        self.trash_dir = Path(trash_dir)
        self.manifest_path = self.trash_dir / "manifest.json"
        self._ensure_manifest_exists()

    def _ensure_manifest_exists(self):
        """Create manifest file if it doesn't exist."""
        self.trash_dir.mkdir(parents=True, exist_ok=True)

        if not self.manifest_path.exists():
            initial_data = {
                "version": "1.0",
                "deletions": []
            }
            self._write_manifest(initial_data)

    def _read_manifest(self) -> Dict:
        """Read manifest from disk.

        Returns:
            Manifest dictionary
        """
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {"version": "1.0", "deletions": []}

    def _write_manifest(self, data: Dict):
        """Write manifest to disk atomically.

        Args:
            data: Manifest dictionary to write
        """
        # Write to temp file first for atomic operation
        temp_path = self.manifest_path.with_suffix('.tmp')
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Atomic rename
        temp_path.replace(self.manifest_path)

    def add_deletion(self, deletion_id: str, original_path: str, trash_path: str,
                    reason: str, file_hash: str):
        """Add deletion record to manifest.

        Args:
            deletion_id: Unique deletion identifier
            original_path: Original file path
            trash_path: Path in trash directory
            reason: Reason for deletion (e.g., 'orphan')
            file_hash: SHA256 hash of file for verification
        """
        manifest = self._read_manifest()

        record = {
            "id": deletion_id,
            "original_path": str(original_path),
            "trash_path": str(trash_path),
            "deleted_at": datetime.now().isoformat(),
            "reason": reason,
            "file_hash": file_hash,
            "restored": False
        }

        manifest["deletions"].append(record)
        self._write_manifest(manifest)

    def get_deletion(self, deletion_id: str) -> Optional[Dict]:
        """Get deletion record by ID.

        Args:
            deletion_id: Deletion identifier

        Returns:
            Deletion record or None if not found
        """
        manifest = self._read_manifest()

        for deletion in manifest["deletions"]:
            if deletion["id"] == deletion_id:
                return deletion

        return None

    def mark_restored(self, deletion_id: str):
        """Mark deletion as restored.

        Args:
            deletion_id: Deletion identifier
        """
        manifest = self._read_manifest()

        for deletion in manifest["deletions"]:
            if deletion["id"] == deletion_id:
                deletion["restored"] = True
                break

        self._write_manifest(manifest)

    def get_all_deletions(self) -> List[Dict]:
        """Get all deletion records.

        Returns:
            List of deletion records
        """
        manifest = self._read_manifest()
        return manifest.get("deletions", [])

    def get_unrestored_deletions(self) -> List[Dict]:
        """Get all unrestored deletion records.

        Returns:
            List of unrestored deletion records
        """
        manifest = self._read_manifest()
        return [d for d in manifest.get("deletions", []) if not d.get("restored", False)]

    @staticmethod
    def calculate_file_hash(file_path: str | Path) -> str:
        """Calculate SHA256 hash of file.

        Args:
            file_path: Path to file

        Returns:
            SHA256 hash as hex string
        """
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()
