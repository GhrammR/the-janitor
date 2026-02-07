# Stop the Slop, Start the Engineering

![The Janitor in Action](https://raw.githubusercontent.com/GhrammR/the-janitor/main/docs/assets/demo.gif)

## The Problem: AI-Generated Code Bloat

We are drowning in **AI-generated code bloat**. Large Language Models hallucinate dependencies, duplicate logic, and generate functions that are never called. Every coding session with AI assistants leaves behind:

- **Orphaned imports** that slow down module loading
- **Dead classes** that confuse new developers
- **Zombie test fixtures** that waste CI/CD time
- **Duplicate logic** that creates maintenance nightmares

## The Philosophy: Negative Net Lines of Code

The best developers measure success in **Negative Net Lines of Code**. Every line deleted is:

- **One less bug** to debug in production
- **One less security vulnerability** to patch
- **One less cognitive burden** for your team
- **One less import** that breaks when you upgrade dependencies

**The Janitor makes negative LOC your default.**

## The Solution: Intelligent Dead Code Detection

The Janitor is not a simple linter. It's a **semantic analysis engine** that understands:

- **Framework lifecycle methods** (Django models, Flask routes, pytest fixtures)
- **Metaprogramming patterns** (getattr, dynamic imports, exec)
- **Cross-language references** (YAML configs, package.json scripts)
- **Type-aware resolution** (method calls through variable type inference)

### What Makes The Janitor Different?

Traditional tools use text matching. The Janitor uses **compiler-grade analysis**:

| Feature | Traditional Linters | The Janitor |
|---------|-------------------|-------------|
| **Analysis Depth** | Text search | AST + type inference |
| **Framework Support** | Generic rules | 100+ framework patterns |
| **Safety** | None | Sandbox + auto-rollback |
| **False Positives** | High | Near-zero |
| **Configuration Files** | Ignored | Parsed & protected |

## The Guarantee: Zero-Fear Deletion

**Delete with zero fear.** The Janitor refuses to break your build:

1. **Backup**: Files are safely staged in `.janitor_trash`
2. **Surgery**: Dead code is surgically removed (AST-based)
3. **Verification**: Your tests (`pytest`, `npm test`) are executed in a sandbox
4. **Auto-Rollback**: If tests fail, everything is instantly restored

## The Business Case

At **$100/hr**, preventing a single production hotfix yields an **800% ROI**:

- **Production Hotfix**: $800 (8 hours debugging) → $100 (1 hour automated cleanup) = **$700 saved**
- **Onboarding Delay**: $400 (4 hours navigating zombie code) → $50 (30 min clean codebase) = **$350 saved**
- **Security Audit**: $1,200 (12 hours auditing unused attack surface) → $200 (2 hours) = **$1,000 saved**

## Get Started

```bash
# Install
pip install the-janitor

# Audit your codebase
janitor audit .

# Clean dead code (with safety checks)
janitor clean --mode symbols .

# Find duplicates
janitor dedup . --threshold 0.9
```

**Ready to stop the slop?** [View the documentation](architecture.md) or [upgrade to Premium](premium.md).
