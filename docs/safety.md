# Safety: Delete with Zero Fear

The Janitor's safety system ensures that **automated code deletion never breaks your build**. Every deletion is transactionally verified with automatic rollback on failure.

## The Safety Guarantee

> **"If The Janitor breaks your tests, the changes are automatically reverted."**

This guarantee is enforced through a **3-stage safety pipeline**:

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Backup                                             │
│ Copy files to .janitor_trash before modification           │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Surgery                                            │
│ AST-based surgical removal (not text replacement)          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Verification                                       │
│ Run your test suite in a sandbox environment               │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    ┌──────────────────┐
                    │ Tests Pass?      │
                    └──────────────────┘
                       ↓            ↓
                     YES          NO
                       ↓            ↓
              Commit Changes   Auto-Rollback
```

## Stage 1: Backup Strategy

### The `.janitor_trash/` Directory

Before any file is modified, The Janitor creates a **timestamped backup**:

```
.janitor_trash/
├── 2026-02-07T14-30-45/
│   ├── src/api/routes.py
│   ├── src/utils/helpers.py
│   └── manifest.json
```

### Manifest Format

Each cleanup session generates a `manifest.json` with metadata:

```json
{
  "timestamp": "2026-02-07T14:30:45",
  "mode": "symbols",
  "files_modified": [
    {
      "path": "src/api/routes.py",
      "symbols_removed": ["unused_function", "dead_class"],
      "backup_path": ".janitor_trash/2026-02-07T14-30-45/src/api/routes.py"
    }
  ],
  "test_command": "pytest",
  "status": "pending"
}
```

### Backup Retention

- **Default**: Backups persist until manually deleted
- **Auto-cleanup**: `janitor clean --delete-backups` removes old `.janitor_trash/` sessions
- **Disk safety**: Backups stored on the same filesystem (no network latency)

## Stage 2: Surgical Removal

### AST-Based Surgery (Not Text Replacement)

The Janitor uses **libcst** (Concrete Syntax Tree) to modify Python code while preserving:

- **Formatting**: Indentation, spacing, line breaks
- **Comments**: Inline and block comments (unless inside dead functions)
- **Imports**: Auto-removal of orphaned imports after symbol deletion

#### Example: Function Removal

**Before:**
```python
def active_function():
    """This is used."""
    return 42

def dead_function():
    """This is never called."""
    return 0

def another_active():
    """Also used."""
    return active_function()
```

**After:**
```python
def active_function():
    """This is used."""
    return 42

def another_active():
    """Also used."""
    return active_function()
```

**Preserved:**
- Line spacing between functions
- Docstrings and comments in active functions
- Indentation style

### JavaScript/TypeScript Surgery

For JavaScript and TypeScript, The Janitor uses **tree-sitter** transformations:

- **Named export removal**: `export { foo, bar }` → `export { foo }` (if bar is dead)
- **Import cleanup**: Removes unused imports automatically
- **Default export protection**: Never removes `export default`

## Stage 3: Test Verification & Sandbox

### Automatic Test Detection

The Janitor auto-detects your test framework:

=== "Python"
    ```bash
    # Detected test commands (in order of preference)
    1. pytest
    2. python -m pytest
    3. python -m unittest discover
    4. nose2
    ```

=== "JavaScript/TypeScript"
    ```bash
    # Detected test commands
    1. npm test
    2. yarn test
    3. pnpm test
    4. vitest run
    5. jest
    ```

### The Sandbox Environment

Tests are executed in an **isolated subprocess** to prevent side effects:

```python
# Sandbox execution
result = subprocess.run(
    test_command,
    cwd=project_root,
    env=clean_environment,  # No JANITOR_* variables leak
    timeout=300,            # 5-minute timeout
    capture_output=True
)

if result.returncode != 0:
    trigger_rollback()
```

### Sandbox Features

- **Timeout protection**: Tests that hang are killed after 5 minutes
- **Exit code validation**: Non-zero exit = automatic rollback
- **Output capture**: Test failures logged for debugging
- **Environment isolation**: No pollution from Janitor process

## Auto-Rollback Mechanism

### When Rollback Triggers

The Janitor restores all files if:

1. **Test suite fails** (non-zero exit code)
2. **Test suite hangs** (timeout exceeded)
3. **Syntax errors** (AST surgery corrupted a file)
4. **Import errors** (circular dependencies created)

### Rollback Process

```python
def rollback_changes(manifest_path):
    """Restore files from .janitor_trash/"""
    manifest = load_manifest(manifest_path)

    for file_info in manifest['files_modified']:
        backup = file_info['backup_path']
        original = file_info['path']

        # Atomic restore
        shutil.copy2(backup, original)

    print("✅ Rollback complete. All changes reverted.")
```

**Atomicity**: Each file is restored individually (if one fails, others still succeed)

### Post-Rollback Diagnostics

The Janitor provides **actionable error messages**:

```
❌ Test suite failed after cleanup. Rolling back...

Failed Tests:
  - tests/test_api.py::test_process_payment
  - tests/test_utils.py::test_helper_function

Likely Cause:
  The Janitor removed 'process_payment' from api/handlers.py,
  but tests/test_api.py still references it.

Recommendation:
  - Review test_api.py - this test may be orphaned
  - Or process_payment() may be called indirectly (metaprogramming?)
  - Run with --library mode to protect all exports
```

## Safety Best Practices

### 1. Use Version Control

**Always commit before running `janitor clean`:**

```bash
git add .
git commit -m "Pre-cleanup checkpoint"
janitor clean --mode symbols .
```

If rollback fails, you can restore from Git.

### 2. Start with Audit Mode

**Dry-run first** to review what will be deleted:

```bash
# Non-destructive audit
janitor audit .

# Review the report, then clean
janitor clean --mode symbols .
```

### 3. Incremental Cleanup

**Clean one directory at a time** for large codebases:

```bash
# Safer than cleaning the entire repo at once
janitor clean --mode symbols ./src/api
janitor clean --mode symbols ./src/utils
janitor clean --mode symbols ./src/models
```

### 4. Test Coverage Requirement

The Janitor's safety depends on **your test suite**:

- **High coverage** (>80%): Safe to clean aggressively
- **Low coverage** (<50%): Use `--library` mode to be conservative
- **No tests**: The Janitor will skip verification (manual review required)

## CI/CD Integration Safety

### Pre-Commit Hook Example

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run Janitor audit (non-destructive)
janitor audit . --library

# If dead code found, warn but allow commit
if [ $? -ne 0 ]; then
  echo "⚠️  Dead code detected. Run 'janitor clean' to remove."
fi
```

### GitHub Actions Workflow

```yaml
name: Dead Code Check

on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Janitor Audit
        run: |
          pip install the-janitor
          janitor audit . --library
```

**Safe for CI**: Audit mode never modifies files.

## Edge Cases Handled

### 1. Partial Deletions
If The Janitor crashes mid-cleanup, the manifest tracks which files were modified. Manual rollback is possible:

```bash
janitor rollback .janitor_trash/latest/manifest.json
```

### 2. Concurrent Modifications
The Janitor detects if files changed during cleanup:

```
❌ File modified externally during cleanup: src/api/routes.py
   Expected checksum: abc123
   Actual checksum: def456

Aborting cleanup. No files were modified.
```

### 3. Network/Disk Failures
If `.janitor_trash/` is unwritable, cleanup aborts before any modifications:

```
❌ Cannot write to .janitor_trash/ (Permission denied)
   Fix permissions or run with sudo.
```

## Recovery Commands

### Manual Rollback
```bash
# Restore from latest backup
janitor rollback .janitor_trash/latest

# Restore from specific timestamp
janitor rollback .janitor_trash/2026-02-07T14-30-45
```

### Cleanup Backups
```bash
# Delete all backups older than 7 days
janitor cleanup-trash --older-than 7d

# Delete all backups
janitor cleanup-trash --all
```

## Next Steps

- [Learn about architecture](architecture.md)
- [Explore Premium features](premium.md)
- [View GitHub repository](https://github.com/GhrammR/the-janitor)
