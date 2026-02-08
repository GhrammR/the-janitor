#!/usr/bin/env python3
"""Version Conductor - Single Source of Truth for version strings.

Reads the VERSION file and synchronizes version strings across:
- README.md (badges and text)
- mkdocs.yml (site_name and extra.version)
- src/config.py (__version__ constant)
- action.yml (description version)
- Dockerfile (version label)
"""

import re
from pathlib import Path


def read_version() -> str:
    """Read version from VERSION file with robust encoding handling.

    Handles:
    - UTF-8 with BOM (utf-8-sig)
    - UTF-16 encoding artifacts
    - Hidden whitespace, newlines, and null bytes

    Returns:
        Validated semantic version string (X.Y.Z)

    Raises:
        ValueError: If version format is invalid
    """
    version_file = Path(__file__).parent.parent / "VERSION"

    # Try UTF-8 with BOM handling first (most common on Windows)
    try:
        raw_version = version_file.read_text(encoding='utf-8-sig')
    except UnicodeDecodeError:
        # Fallback to UTF-16 if UTF-8 fails (rare Windows artifact)
        try:
            raw_version = version_file.read_bytes().decode('utf-16')
        except UnicodeDecodeError:
            # Last resort: Latin-1 (always succeeds but may be garbage)
            raw_version = version_file.read_text(encoding='latin-1')

    # Sanitize: Remove whitespace, newlines, null bytes, and non-printable chars
    version = raw_version.strip().strip('\x00').strip()

    # Validation: Ensure semantic versioning format (X.Y.Z)
    if not re.match(r'^\d+\.\d+\.\d+$', version):
        raise ValueError(
            f"Invalid version format detected: '{version}' (raw: {raw_version!r})\n"
            f"Expected semantic version format: X.Y.Z (e.g., 3.9.1)"
        )

    return version


def update_readme(version: str, project_root: Path) -> None:
    """Update version in README.md."""
    readme_path = project_root / "README.md"
    content = readme_path.read_text(encoding="utf-8")

    # Update badge
    content = re.sub(
        r'\[!\[Release: v[\d.]+\]',
        f'[![Release: v{version}]',
        content
    )

    # Update badge URL
    content = re.sub(
        r'release-v[\d.]+-blue',
        f'release-v{version}-blue',
        content
    )

    readme_path.write_text(content, encoding="utf-8")
    print(f"[OK] Updated README.md to v{version}")


def update_mkdocs(version: str, project_root: Path) -> None:
    """Update version in mkdocs.yml."""
    mkdocs_path = project_root / "mkdocs.yml"
    content = mkdocs_path.read_text(encoding="utf-8")

    # Update site_name
    content = re.sub(
        r'site_name: The Janitor \(v[\d.]+\)',
        f'site_name: The Janitor (v{version})',
        content
    )

    # Update extra.version
    content = re.sub(
        r'version: v[\d.]+',
        f'version: v{version}',
        content
    )

    mkdocs_path.write_text(content, encoding="utf-8")
    print(f"[OK] Updated mkdocs.yml to v{version}")


def update_config(version: str, project_root: Path) -> None:
    """Update or create src/config.py with __version__."""
    config_path = project_root / "src" / "config.py"

    if config_path.exists():
        content = config_path.read_text(encoding="utf-8")
        content = re.sub(
            r'__version__ = ["\'][\d.]+["\']',
            f'__version__ = "{version}"',
            content
        )
    else:
        content = f'''"""The Janitor configuration and constants."""

__version__ = "{version}"
'''

    config_path.write_text(content, encoding="utf-8")
    print(f"[OK] Updated src/config.py to v{version}")


def update_action_yml(version: str, project_root: Path) -> None:
    """Update version in action.yml description."""
    action_path = project_root / "action.yml"
    content = action_path.read_text(encoding="utf-8")

    # Update description if it contains a version
    content = re.sub(
        r"(description: .*)(v[\d.]+)(.*)",
        rf"\1v{version}\3",
        content
    )

    action_path.write_text(content, encoding="utf-8")
    print(f"[OK] Updated action.yml to v{version}")


def update_dockerfile(version: str, project_root: Path) -> None:
    """Update version label in Dockerfile."""
    dockerfile_path = project_root / "Dockerfile"
    content = dockerfile_path.read_text(encoding="utf-8")

    # Add or update LABEL version
    if "LABEL version=" in content:
        content = re.sub(
            r'LABEL version="[\d.]+"',
            f'LABEL version="{version}"',
            content
        )
    else:
        # Add LABEL after FROM line
        content = re.sub(
            r'(FROM python:[\d.]+-slim\n)',
            rf'\1LABEL version="{version}"\n',
            content
        )

    dockerfile_path.write_text(content, encoding="utf-8")
    print(f"[OK] Updated Dockerfile to v{version}")


def main():
    """Synchronize version across all project files."""
    project_root = Path(__file__).parent.parent
    version = read_version()

    print(f"Version Conductor: Synchronizing to v{version}")
    print("=" * 60)

    update_readme(version, project_root)
    update_mkdocs(version, project_root)
    update_config(version, project_root)
    update_action_yml(version, project_root)
    update_dockerfile(version, project_root)

    print("=" * 60)
    print(f"[OK] All files synchronized to v{version}")


if __name__ == "__main__":
    main()
