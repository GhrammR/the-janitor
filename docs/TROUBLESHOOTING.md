# Troubleshooting Guide

**The Janitor v3.0 Enterprise Heuristics**

This guide helps you diagnose and fix common issues when using The Janitor.

---

## Table of Contents

1. [Performance Issues](#performance-issues)
2. [False Positives (Wrong Dead Code Detection)](#false-positives)
3. [False Negatives (Missed Dead Code)](#false-negatives)
4. [Installation Issues](#installation-issues)
5. [Unicode and Encoding Errors](#unicode-and-encoding-errors)
6. [Cache Issues](#cache-issues)
7. [Test Failures After Cleanup](#test-failures-after-cleanup)

---

## Performance Issues

### Symptom: Audit takes too long (>30 seconds on small projects)

**Common Causes**:
1. Analyzing vendored code (node_modules, .venv, site-packages)
2. Very large files with complex AST
3. Grep shield enabled on large codebase

**Solutions**:

#### Solution 1: Exclude vendored directories (default behavior)
```bash
# This is the default - vendored code is automatically excluded
janitor audit .
```

If you see vendored paths in output:
```bash
# Ensure you're NOT using --include-vendored
janitor audit . --library  # Correct
janitor audit . --library --include-vendored  # Slow!
```

#### Solution 2: Disable grep shield (if enabled)
```bash
# Grep shield is OFF by default
janitor audit .  # Fast

# Only use grep shield for critical production audits
janitor audit . --grep-shield  # Slow but thorough
```

#### Solution 3: Check for immortal directory detection
Verify that tests/ docs/ examples/ are being skipped:
```bash
janitor audit . --library
# Look for: "skipped X immortal files" in Phase 2 output
```

---

### Symptom: Phase 3 (Reference Linking) is extremely slow

**Diagnosis**:
- Phase 3 should take <0.5s per file
- If >1s per file, VariableTypeMap lookups may be the bottleneck

**Solutions**:
1. **Temporary**: Run without library mode to reduce symbol count
```bash
janitor audit .  # Faster than --library
```

2. **Long-term**: Enable caching (v3.1+ feature)
```bash
# On first run, cache is built (slower)
janitor audit .

# Subsequent runs use cache (2x faster)
janitor audit .
```

---

## False Positives

### Symptom: Tool wants to delete code that's actually used

**Common Causes**:
1. Dynamic imports (importlib, __import__)
2. String-based references (Celery tasks, Django apps)
3. Framework lifecycle methods
4. Config file references (serverless.yml, settings.py)

**Solutions**:

#### Solution 1: Check protection reason
```bash
janitor audit . --show-protected
# Look for the symbol in "Protected Symbols" table
# If not there, it's a false positive
```

#### Solution 2: File uses metaprogramming
If the file contains `getattr()`, `eval()`, or `exec()`, ALL symbols should be auto-protected:
```python
# This file should trigger Metaprogramming Danger Shield
method = getattr(handler, method_name)  # Dynamic call
```

Expected protection: `[Premium] Metaprogramming Danger (getattr/eval/exec detected)`

If NOT protected, report this as a bug.

#### Solution 3: Config file references
Serverless handlers, Django apps, Docker commands should be auto-detected:

**serverless.yml**:
```yaml
functions:
  upload:
    handler: handlers.image_upload.upload_image  # upload_image should be protected
```

Expected protection: `[Premium] Config Reference: Lambda Handler: handlers.image_upload.upload_image`

**Django settings.py**:
```python
INSTALLED_APPS = [
    'myapp.users',  # 'users' module should be protected
]
```

Expected protection: `[Premium] Config Reference: Django INSTALLED_APPS: myapp.users`

If NOT protected, check:
1. Config file is in project root (not subdirectory)
2. File format matches expected pattern (see examples above)

---

### Symptom: Framework lifecycle methods marked as dead

**Examples**:
- Django `save()`, `delete()` on Model subclasses
- FastAPI dependencies with `Annotated[Type, Depends(...)]`
- pytest fixtures with `@pytest.fixture`
- Qt slots like `on_button_clicked()`

**Solution**: These should be auto-protected by Premium Heuristics.

Check protection status:
```bash
janitor audit . --show-protected | grep "your_method_name"
```

Expected protections:
- **Django ORM**: `[Premium] ORM Lifecycle Method`
- **FastAPI Depends**: `[Premium Protection] Rule: Meta`
- **pytest fixtures**: `[Premium] pytest Fixture`
- **Qt slots**: `[Premium] Qt Auto-Connection Slot`

If NOT protected:
1. Verify inheritance (Django Model must inherit from `Base` or `Model`)
2. Check decorator syntax (`@pytest.fixture` not `@fixture`)
3. Verify Qt slot pattern (`on_<widget>_<signal>`)

---

## False Negatives

### Symptom: Tool doesn't detect actually dead code

**Common Causes**:
1. Symbol name collision (same name used elsewhere)
2. Library mode protecting too much
3. Symbol in immortal directory (tests/, docs/)

**Solutions**:

#### Solution 1: Check if symbol is protected
```bash
janitor audit . --show-protected
# Search for the symbol name
# If protected, check the reason
```

#### Solution 2: Library mode too conservative
```bash
# Library mode protects ALL public symbols
janitor audit . --library  # Conservative

# For internal cleanup, don't use library mode
janitor audit .  # More aggressive
```

#### Solution 3: Symbol in tests/ or docs/
Dead code in `tests/`, `docs/`, `examples/`, `scripts/` is intentionally NOT reported.

If you want to clean these:
```bash
# Audit specific test file
janitor audit tests/test_specific.py
```

---

## Installation Issues

### Symptom: `ModuleNotFoundError` for tree-sitter bindings

**Error**:
```
ModuleNotFoundError: No module named 'tree_sitter_python'
```

**Solution**:
```bash
pip install --upgrade the-janitor
# Or reinstall
pip uninstall the-janitor
pip install the-janitor
```

### Symptom: Docker image fails to build

**Error**:
```
ERROR: failed to solve: process "/bin/sh -c..." did not complete successfully
```

**Solution**:
```bash
# Use pre-built image instead of building locally
docker pull thejanitor/janitor:latest
```

---

## Unicode and Encoding Errors

### Symptom: `UnicodeEncodeError` on Windows

**Error**:
```
UnicodeEncodeError: 'charmap' codec can't encode character '\u2728'
```

**Solution** (v3.0+): This is fixed. Update to latest version:
```bash
pip install --upgrade the-janitor
```

If still occurs:
```bash
# Set environment variable before running
set PYTHONIOENCODING=utf-8
janitor audit .
```

### Symptom: Files with non-UTF-8 encoding crash analysis

**Solution**: The Janitor auto-detects encoding and falls back gracefully.

If crashes persist:
```bash
# Check file encoding
file --mime-encoding problematic_file.py

# Convert to UTF-8
iconv -f ORIGINAL_ENCODING -t UTF-8 problematic_file.py > fixed_file.py
```

---

## Cache Issues

### Symptom: Repeat audits not faster

**Diagnosis**:
```bash
# Check if cache exists
ls .janitor_cache/

# If missing, caching is not yet enabled (v3.1+ feature)
```

**Solution** (v3.1+):
```bash
# First audit builds cache
janitor audit .

# Second audit uses cache (2x faster)
janitor audit .
```

### Symptom: Cache giving wrong results

**Solution**: Clear cache and rebuild
```bash
rm -rf .janitor_cache/
janitor audit .  # Rebuilds cache from scratch
```

---

## Test Failures After Cleanup

### Symptom: Tests pass before cleanup, fail after

**Diagnosis**: False positive detection deleted necessary code.

**Recovery**:
```bash
# The Janitor uses Git-style trash
ls .janitor_trash/

# Restore deleted files
cp .janitor_trash/TIMESTAMP/* .
```

**Prevention**:
```bash
# Always use audit first to verify
janitor audit .

# Review dead symbols list carefully before cleaning
janitor clean . --dry-run  # Shows what would be deleted

# Use sandbox mode (runs tests before committing deletion)
janitor clean .  # Default behavior includes test verification
```

---

## Common Error Messages

### "Zero incoming dependencies"

**Meaning**: File is not imported by any other file in the project.

**Action**: Review if file is:
- Entry point (main.py, __main__.py) - should be protected
- Standalone script - may be legitimately dead
- Test file - should be in tests/ to auto-exclude

### "Protected by Wisdom Registry"

**Meaning**: Symbol matches a framework pattern (FastAPI, Django, etc.)

**Action**: This is GOOD - framework methods are being protected correctly.

### "Skipped X immortal files"

**Meaning**: Files in tests/, docs/, examples/ automatically excluded.

**Action**: No action needed - this is expected behavior.

---

## Getting Help

If you encounter an issue not covered here:

1. **Check GitHub Issues**: https://github.com/GhrammR/the-janitor/issues
2. **Enable verbose mode** (future feature):
   ```bash
   janitor audit . --verbose  # Shows detailed decision-making
   ```
3. **Report a bug** with:
   - Command you ran
   - Expected behavior
   - Actual behavior
   - Sample code that reproduces the issue

---

## Performance Benchmarks

Expected performance on modern hardware:

| Project Size | Files | Symbols | Expected Time |
|--------------|-------|---------|---------------|
| Small (Flask) | 20-50 | 300-500 | 5-10s |
| Medium (FastAPI) | 50-100 | 500-1000 | 10-30s |
| Large (Django) | 100-500 | 1000-5000 | 30-120s |
| Huge (Scrapy) | 500+ | 5000+ | 2-5min |

**Note**: First run is slower (builds cache). Subsequent runs 2x faster.

---

## Best Practices

1. **Always audit before cleaning**:
   ```bash
   janitor audit .  # Review first
   janitor clean .  # Then clean
   ```

2. **Use library mode for public packages**:
   ```bash
   janitor audit . --library  # Protects public API
   ```

3. **Test after every cleanup**:
   ```bash
   janitor clean .
   pytest  # Verify nothing broke
   ```

4. **Commit before major cleanups**:
   ```bash
   git add -A
   git commit -m "Before Janitor cleanup"
   janitor clean .
   ```

5. **Review protected symbols periodically**:
   ```bash
   janitor audit . --show-protected | less
   ```

---

## Version-Specific Issues

### v3.0 Known Issues
- Cache not yet implemented (coming in v3.1)
- TypeScript config parsing not yet supported
- Very large files (>10K lines) may be slow

### Planned Fixes (v3.1)
- SQLite-based caching for 2x speedup on repeat audits
- TypeScript package.json and tsconfig.json parsing
- Incremental analysis (only re-analyze changed files)

---

For more information, see:
- **PREMIUM_LOGIC.md**: Explanation of the 4-Stage Shield system
- **README.md**: Full feature list and examples
- **PRE_PUBLIC_IMPROVEMENTS.md**: Roadmap and future features
