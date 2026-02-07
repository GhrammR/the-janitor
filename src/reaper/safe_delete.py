"""Safe file deletion with trash and restoration capabilities."""
import shutil
import secrets
from pathlib import Path
from datetime import datetime
from typing import List
from .manifest import Manifest


class SafeDeleter:
    """Safe file deleter that moves files to trash instead of permanent deletion."""

    def __init__(self, trash_dir: str | Path = ".janitor_trash"):
        """Initialize safe deleter.

        Args:
            trash_dir: Path to trash directory (default: .janitor_trash)
        """
        self.trash_dir = Path(trash_dir)
        self.trash_dir.mkdir(parents=True, exist_ok=True)
        self.manifest = Manifest(self.trash_dir)

    def delete(self, file_path: str | Path, reason: str = "manual") -> str:
        """Move file to trash and record in manifest.

        NEVER uses os.remove() - always moves to trash for safety.

        Args:
            file_path: Path to file to delete
            reason: Reason for deletion (e.g., 'orphan', 'manual')

        Returns:
            Deletion ID for restoration

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If move operation fails
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Generate unique deletion ID
        deletion_id = self._generate_deletion_id()

        # Create deletion-specific subdirectory
        deletion_dir = self.trash_dir / deletion_id
        deletion_dir.mkdir(parents=True, exist_ok=True)

        # Calculate file hash before moving
        file_hash = self.manifest.calculate_file_hash(file_path)

        # Determine trash path (preserve filename)
        trash_path = deletion_dir / file_path.name

        # Move file to trash (using shutil.move for safety)
        shutil.move(str(file_path), str(trash_path))

        # Record in manifest
        self.manifest.add_deletion(
            deletion_id=deletion_id,
            original_path=str(file_path.resolve()),
            trash_path=str(trash_path),
            reason=reason,
            file_hash=file_hash
        )

        return deletion_id

    def delete_multiple(self, file_paths: List[str | Path], reason: str = "batch") -> List[str]:
        """Delete multiple files and return their deletion IDs.

        Args:
            file_paths: List of file paths to delete
            reason: Reason for deletion

        Returns:
            List of deletion IDs in same order as file_paths
        """
        deletion_ids = []

        for file_path in file_paths:
            try:
                deletion_id = self.delete(file_path, reason)
                deletion_ids.append(deletion_id)
            except (FileNotFoundError, IOError) as e:
                # Log error but continue with other files
                print(f"Warning: Failed to delete {file_path}: {e}")
                deletion_ids.append(None)

        return deletion_ids

    def restore(self, deletion_id: str):
        """Restore file from trash to original location.

        Args:
            deletion_id: Deletion identifier

        Raises:
            ValueError: If deletion ID not found
            IOError: If restoration fails
        """
        record = self.manifest.get_deletion(deletion_id)

        if not record:
            raise ValueError(f"Deletion ID not found: {deletion_id}")

        # Silent return if already restored (prevents crashes during error handling)
        if record.get("restored", False):
            return

        trash_path = Path(record["trash_path"])
        original_path = Path(record["original_path"])

        if not trash_path.exists():
            raise IOError(f"File not found in trash: {trash_path}")

        # Ensure parent directory exists
        original_path.parent.mkdir(parents=True, exist_ok=True)

        # Move file back to original location
        shutil.move(str(trash_path), str(original_path))

        # Mark as restored in manifest
        self.manifest.mark_restored(deletion_id)

    def restore_all(self, deletion_ids: List[str]):
        """Restore multiple files from trash.

        Args:
            deletion_ids: List of deletion identifiers

        Raises:
            IOError: If any restoration fails (will attempt to restore all)
        """
        errors = []

        for deletion_id in deletion_ids:
            if deletion_id is None:
                continue

            try:
                self.restore(deletion_id)
            except (ValueError, IOError) as e:
                errors.append(f"{deletion_id}: {e}")

        if errors:
            raise IOError(f"Failed to restore some files:\n" + "\n".join(errors))

    def get_trash_info(self) -> dict:
        """Get information about trash contents.

        Returns:
            Dictionary with trash statistics
        """
        all_deletions = self.manifest.get_all_deletions()
        unrestored = self.manifest.get_unrestored_deletions()

        return {
            "total_deletions": len(all_deletions),
            "unrestored_count": len(unrestored),
            "restored_count": len(all_deletions) - len(unrestored),
            "trash_dir": str(self.trash_dir),
            "unrestored_files": [d["original_path"] for d in unrestored]
        }

    def _generate_deletion_id(self) -> str:
        """Generate unique deletion ID with timestamp.

        Returns:
            Deletion ID in format: YYYYMMDD_HHMMSS_randomhex
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = secrets.token_hex(3)
        return f"{timestamp}_{random_suffix}"
