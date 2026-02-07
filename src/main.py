"""The Janitor CLI - Autonomous dead-code deletion and semantic deduplication."""

# CRITICAL: Silence ChromaDB telemetry BEFORE any imports
import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_DB_TELEMETRY_OPTOUT"] = "True"

from pathlib import Path
import sys
import time
import typer
import click
from typing import List
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn
)
from rich.markup import escape

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import Windows-safe Console wrapper
from src.utils.safe_console import SafeConsole
from rich.console import Console as RichConsole

from src.analyzer.graph_builder import DependencyGraphBuilder
from src.analyzer.orphan_detector import OrphanDetector
from src.analyzer.parser import LanguageParser
from src.analyzer.extractor import EntityExtractor, Entity
from src.analyzer.reference_tracker import ReferenceTracker
from src.analyzer.cache import AnalysisCache
from src.reaper.safe_delete import SafeDeleter
from src.reaper.sandbox import TestSandbox
from src.reaper.symbol_remover import SymbolRemover
from src.reaper.js_remover import JSSymbolRemover
from src.brain.memory import SemanticMemory
from src.brain.llm import LLMClient
from src.brain.refactor import SemanticRefactor

app = typer.Typer(
    name="janitor",
    help="Autonomous dead-code deletion and semantic deduplication",
    add_completion=False
)
# Use SafeConsole for Windows Unicode compatibility
console = SafeConsole(force_terminal=True)

# Cache management sub-command
cache_app = typer.Typer(name="cache", help="Manage the Janitor analysis cache")


def is_ci_environment() -> bool:
    """Detect if running in CI/CD environment (GitHub Actions, GitLab CI, etc.).

    Returns:
        True if running in CI, False otherwise
    """
    ci_indicators = [
        'GITHUB_ACTIONS',  # GitHub Actions
        'CI',              # Generic CI indicator
        'GITLAB_CI',       # GitLab CI
        'CIRCLECI',        # CircleCI
        'TRAVIS',          # Travis CI
        'JENKINS_HOME',    # Jenkins
    ]
    return any(os.getenv(indicator) for indicator in ci_indicators)


def analyze_project(project_path: Path, language: str, library_mode: bool = False,
                    grep_shield: bool = False, show_progress: bool = True):
    """Shared analysis logic for both audit and clean commands.

    Follows a strict 1-2-3 Phase architecture:
    1. Structure (Graph)
    2. Intelligence (AST)
    3. Context (Linking)

    TURBO UPGRADE: Fast-path bypass for unchanged projects happens BEFORE any UI init.
    """

    # =========================================================================
    # TURBO FAST-PATH: O(1) Cache Check
    # =========================================================================
    # CRITICAL: This runs before any heavy imports or UI rendering

    cache = AnalysisCache(project_path)

    # Quick file discovery (glob only, no parsing) - just for hash calculation
    excluded_dirs = {
        'venv', '.venv', 'env', '.virtualenv',
        'vendor', 'extern', 'third_party', 'blib2to3', '_internal',
        '.tox', 'site-packages', 'dist', 'build', '__pycache__',
        'node_modules', '.git', '.janitor_trash', '.janitor_cache'
    }

    quick_files = []
    # Only scan relevant extensions for the hash
    extensions = ['*.py'] if language == 'python' else ['*.js', '*.jsx', '*.ts', '*.tsx']

    for ext in extensions:
        for file_path in project_path.rglob(ext):
            if not any(excluded in file_path.parts for excluded in excluded_dirs):
                quick_files.append(file_path)

    # Calculate project hash
    project_hash = cache.get_project_hash(quick_files)
    cached_result = cache.get_cached_analysis_result(project_hash)

    if cached_result is not None:
        # TURBO EXIT: Return immediately without initializing Progress or Graph
        cached_dead_symbols, cached_orphans = cached_result

        # Reconstruct Entity objects
        dead_symbols = [
            Entity(
                name=s['name'],
                type=s['type'],
                full_text='',
                start_line=s['start_line'],
                end_line=s['end_line'],
                file_path=s['file_path'],
                qualified_name=s.get('qualified_name'),
                parent_class=s.get('parent_class'),
                protected_by=s.get('protected_by', '')
            )
            for s in cached_dead_symbols
        ]

        # Minimal objects for return signature
        import networkx as nx
        graph = nx.DiGraph() # Empty graph is fine for cached results
        reference_tracker = ReferenceTracker(project_path, library_mode=library_mode)

        return cached_orphans, dead_symbols, [], reference_tracker, graph

    # =========================================================================
    # NORMAL PATH: 3-PHASE ANALYSIS
    # =========================================================================

    # Setup Progress Context
    if show_progress:
        progress_ctx = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            transient=True
        )
    else:
        from contextlib import nullcontext
        progress_ctx = nullcontext()

    with progress_ctx as progress:

        # --- PHASE 1: ANALYZING PROJECT STRUCTURE (Graph Building) ---
        if show_progress:
            task = progress.add_task("[cyan]Phase 1/3: Analyzing Project Structure...", total=None)

        graph_builder = DependencyGraphBuilder(project_path)
        graph = graph_builder.build_graph()
        all_files = list(graph.nodes())

        orphan_detector = OrphanDetector(project_path)
        orphans = orphan_detector.detect_orphans(graph)

        # Filter files for language
        language_files = []
        for file_path in all_files:
            file_path = Path(file_path)
            parser = LanguageParser.from_file_extension(file_path)
            if parser and parser.language == language:
                language_files.append(file_path)

        # --- PHASE 2: EXTRACTING CODE INTELLIGENCE (AST Parsing) ---
        if show_progress:
            progress.update(task, description="[yellow]Phase 2/3: Extracting Code Intelligence...", total=len(language_files))

        reference_tracker = ReferenceTracker(project_path, library_mode=library_mode)
        all_entities = []
        parsed_files = []

        for file_path in language_files:
            # Skip immortal files (tests/docs) for extraction to save time
            if orphan_detector.is_immortal(file_path):
                if show_progress: progress.advance(task)
                continue

            # Try Cache for Symbols
            cached_symbols = reference_tracker.cache.get_symbol_definitions(file_path)

            if cached_symbols:
                # Reconstruct from cache
                entities = [
                    Entity(**s) for s in cached_symbols
                ]
                for entity in entities:
                    reference_tracker.add_definition(entity)
                    all_entities.append(entity)

                # We still need source code for Phase 3 linking if refs aren't cached
                cached_refs = reference_tracker.cache.get_file_references(file_path)
                if not cached_refs:
                    parser = LanguageParser.from_file_extension(file_path)
                    tree = parser.parse_file(file_path)
                    if tree:
                        try:
                            with open(file_path, 'rb') as f:
                                parsed_files.append((file_path, tree, f.read()))
                        except: pass
            else:
                # Full Parse
                parser = LanguageParser.from_file_extension(file_path)
                tree = parser.parse_file(file_path)
                if tree:
                    try:
                        with open(file_path, 'rb') as f:
                            source_code = f.read()

                        extractor = EntityExtractor(language)
                        entities = extractor.extract_entities(tree, source_code, str(file_path))

                        # Cache definitions
                        symbol_dicts = [
                            {
                                'name': e.name, 'type': e.type, 'full_text': e.full_text,
                                'start_line': e.start_line, 'end_line': e.end_line,
                                'file_path': e.file_path, 'qualified_name': e.qualified_name,
                                'parent_class': e.parent_class, 'base_classes': e.base_classes,
                                'protected_by': e.protected_by
                            } for e in entities
                        ]
                        reference_tracker.cache.set_symbol_definitions(file_path, symbol_dicts)

                        for entity in entities:
                            reference_tracker.add_definition(entity)
                            all_entities.append(entity)

                        parsed_files.append((file_path, tree, source_code))
                    except: pass

            if show_progress: progress.advance(task)

        reference_tracker.apply_framework_lifecycle_protection()

        # --- PHASE 3: DEEP CONTEXT ANALYSIS (Linking & Type Inference) ---
        if show_progress:
            progress.update(task, description="[magenta]Phase 3/3: Deep Context Analysis...", total=len(parsed_files), completed=0)

        # Throttling for UI updates
        last_update = 0

        for i, (file_path, tree, source_code) in enumerate(parsed_files):
            cached_references = reference_tracker.cache.get_file_references(file_path)

            if cached_references:
                reference_tracker._replay_cached_references(cached_references)
            else:
                reference_tracker._extract_and_cache_references(file_path, tree, source_code)

            # Update UI every 0.1s to avoid slowing down processing
            now = time.time()
            if show_progress and (now - last_update > 0.1):
                progress.update(task, completed=i+1)
                last_update = now

    # Final Calculation
    dead_symbols = reference_tracker.find_dead_symbols(language=language, enable_grep_shield=grep_shield)

    # Update Cache (use same file list as the initial cache check for consistency)
    cache.set_cached_analysis_result(project_hash, dead_symbols, orphans)

    return orphans, dead_symbols, all_entities, reference_tracker, graph


def _print_premium_statistics(protected_symbols: List, console):
    """Print premium feature statistics table.

    TIER 1 BLOCKER 3: Show breakdown of protection by shield type.
    This justifies the $49 price point by demonstrating value.
    """
    from collections import defaultdict
    from rich.table import Table

    # Count protections by type with normalization
    protection_counts = defaultdict(int)
    premium_map = {}  # Track which shields are premium
    premium_count = 0
    community_count = 0

    def normalize_shield_name(reason):
        """Normalize shield names to unify categories (e.g., Meta rules)."""
        # Remove prefixes to get core name
        name = reason.replace('[Premium Protection]', '').replace('[Premium]', '').replace('Rule:', '').strip()

        # Additional normalization for known categories
        if name.startswith('Protection'):
            name = name.replace('Protection', '').strip()

        return name

    for entity in protected_symbols:
        reason = entity.protected_by if hasattr(entity, 'protected_by') else "Unknown"
        is_premium = '[Premium]' in reason
        normalized = normalize_shield_name(reason)

        protection_counts[normalized] += 1

        # Track if this normalized name has premium instances
        if is_premium:
            premium_map[normalized] = True
            premium_count += 1
        elif normalized not in premium_map:
            premium_map[normalized] = False

        if not is_premium:
            community_count += 1

    # Only show statistics if there are protections
    if len(protection_counts) == 0:
        return

    console.print("\n[bold cyan]Protection Statistics (v3.0 Enterprise Heuristics):[/bold cyan]")

    # Create table
    stats_table = Table(show_header=True, header_style="bold magenta", box=None)
    stats_table.add_column("Shield Type", style="cyan", no_wrap=False, width=50)
    stats_table.add_column("Count", justify="right", style="yellow")

    # Sort by count (descending)
    sorted_protections = sorted(protection_counts.items(), key=lambda x: x[1], reverse=True)

    # Group premium and community based on premium_map
    premium_shields = [item for item in sorted_protections if premium_map.get(item[0], False)]
    community_shields = [item for item in sorted_protections if not premium_map.get(item[0], False)]

    # Add premium shields first (highlighting value)
    if premium_shields:
        for shield_name, count in premium_shields:
            # Use ASCII star instead of emoji for Windows terminal compatibility
            stats_table.add_row(f"[bold blue]* {shield_name} (Premium)[/bold blue]", str(count))

    # Add community shields
    if community_shields:
        for shield_name, count in community_shields:
            stats_table.add_row(f"  {shield_name}", str(count))

    console.print(stats_table)

    # Summary line
    if premium_count > 0:
        console.print(f"\n[bold green][OK] Premium Features Protected: {premium_count} symbols[/bold green]")
        if community_count > 0:
            console.print(f"[dim]   Community Rules Protected: {community_count} symbols[/dim]")
        console.print(f"[dim]   Total Saved: {premium_count + community_count} symbols[/dim]")
    else:
        console.print(f"\n[dim]Total Protected: {community_count} symbols (Community Rules)[/dim]")


@app.command()
def audit(
    project_path: str = typer.Argument(".", help="Project root path to analyze"),
    language: str = typer.Option("python", "--language", "-l", help="Language to analyze (python, javascript, typescript)"),
    library: bool = typer.Option(False, "--library", help="Library mode: treat all public symbols as immortal"),
    show_protected: bool = typer.Option(False, "--show-protected", help="Display the Protected Symbols table"),
    include_vendored: bool = typer.Option(False, "--include-vendored", help="Include vendored/3rd-party code in analysis"),
    grep_shield: bool = typer.Option(False, "--grep-shield", help="Enable grep shield (dynamic usage detection). WARNING: Slow on large codebases."),
):
    """Scan project and list dead files and dead symbols."""

    project_path = Path(project_path).resolve()

    if not project_path.exists():
        console.print(f"[bold red]Error:[/bold red] Project path does not exist: {escape(str(project_path))}")
        raise typer.Exit(1)

    console.print(f"[bold blue]Analyzing project:[/bold blue] {project_path}\n")

    # Use shared analysis function
    import time
    start_time = time.time()

    orphans, dead_symbols, all_entities, reference_tracker, graph = analyze_project(
        project_path, language, library_mode=library, grep_shield=grep_shield, show_progress=True
    )

    elapsed = time.time() - start_time

    # LOW-LATENCY: Show instant cache message
    if elapsed < 2.0 and not all_entities:
        console.print(f"[dim]⚡ Instant analysis from cache ({elapsed:.2f}s)[/dim]\n")

    # Get stats for display
    orphan_detector = OrphanDetector(project_path)
    stats = orphan_detector.get_orphan_stats(graph)

    # Display dead files
    if orphans:
        table = Table(title="Dead Files (Orphans)")
        table.add_column("File Path", style="cyan", no_wrap=False)
        table.add_column("Reason", style="magenta")

        for orphan in orphans:
            try:
                display_path = Path(orphan).relative_to(project_path)
            except ValueError:
                display_path = orphan
            table.add_row(str(display_path), "Zero incoming dependencies")

        console.print(table)
        console.print(f"\n[bold yellow]File Summary:[/bold yellow]")
        console.print(f"  Total files: {stats['total_files']}")
        console.print(f"  Dead files: {len(orphans)}")
        console.print()
    else:
        console.print("[bold green]No dead files found![/bold green]\n")

    # Identify protected symbols (those that would be dead but have protected_by set)
    # LOW-LATENCY: Skip if using cached result (all_entities empty)
    protected_entities = [e for e in all_entities if e.protected_by and e not in dead_symbols] if all_entities else []
    # Filter to only show symbols that HAVE NO external/internal references but were saved by rules
    actually_saved = []
    if protected_entities:
        for entity in protected_entities:
            references = reference_tracker.get_symbol_references(entity)
            if not references:
                actually_saved.append(entity)

    # Filter out vendored code unless --include-vendored is set
    skipped_vendored_count = 0
    if not include_vendored:
        # Filter dead symbols
        vendored_dead = [s for s in dead_symbols if orphan_detector.is_vendored(s.file_path)]
        skipped_vendored_count += len(vendored_dead)
        dead_symbols = [s for s in dead_symbols if not orphan_detector.is_vendored(s.file_path)]

        # Filter protected symbols
        vendored_saved = [s for s in actually_saved if orphan_detector.is_vendored(s.file_path)]
        skipped_vendored_count += len(vendored_saved)
        actually_saved = [s for s in actually_saved if not orphan_detector.is_vendored(s.file_path)]

    if dead_symbols:
        # Create table for dead symbols
        symbol_table = Table(title="Dead Symbols (Functions/Classes)")
        symbol_table.add_column("Symbol", style="cyan")
        symbol_table.add_column("Type", style="yellow")
        symbol_table.add_column("File", style="magenta", no_wrap=False)
        symbol_table.add_column("Line", style="green")

        for symbol in dead_symbols:
            try:
                display_path = Path(symbol.file_path).relative_to(project_path)
            except ValueError:
                display_path = symbol.file_path

            # Use qualified name for clarity (e.g., ClassName.method_name)
            display_name = symbol.qualified_name if symbol.qualified_name else symbol.name

            symbol_table.add_row(
                display_name,
                symbol.type,
                str(display_path),
                str(symbol.start_line)
            )

        console.print(symbol_table)

    if actually_saved and show_protected:
        # Create table for saved symbols (only shown with --show-protected flag)
        saved_table = Table(title="Protected Symbols (Wisdom Safeguard)")
        saved_table.add_column("Symbol", style="cyan")
        saved_table.add_column("Type", style="yellow")
        saved_table.add_column("Protection", style="bold green")
        saved_table.add_column("File", style="magenta")

        for symbol in actually_saved:
             try:
                 display_path = Path(symbol.file_path).relative_to(project_path)
             except ValueError:
                 display_path = symbol.file_path

             display_name = symbol.qualified_name if symbol.qualified_name else symbol.name

             # Highlight Premium Protection
             protection = symbol.protected_by
             if "[Premium Protection]" in protection:
                 protection = f"[bold gold3]{protection}[/bold gold3]"

             saved_table.add_row(
                 display_name,
                 symbol.type,
                 protection,
                 str(display_path)
             )

        console.print(saved_table)

    # === TIER 1 BLOCKER 3: Premium Feature Statistics ===
    # Show breakdown of protection by shield type (justifies $49 price point)
    if actually_saved:
        _print_premium_statistics(actually_saved, console)

    if dead_symbols or actually_saved or skipped_vendored_count > 0:
        console.print(f"\n[bold yellow]Symbol Summary:[/bold yellow]")
        console.print(f"  Total symbols: {len(all_entities)}")
        console.print(f"  Dead symbols: {len(dead_symbols)}")
        if actually_saved:
            # PERFORMANCE ENGINEER FIX: Separate Premium and Community counts
            premium_saved = sum(1 for s in actually_saved if hasattr(s, 'protected_by') and '[Premium]' in s.protected_by)
            community_saved = len(actually_saved) - premium_saved

            if premium_saved > 0 and community_saved > 0:
                console.print(f"  Saved symbols: [bold cyan]Premium: {premium_saved}[/bold cyan] | Community: {community_saved} | [bold green]Total: {len(actually_saved)}[/bold green]")
            elif premium_saved > 0:
                console.print(f"  Saved symbols: [bold cyan]Premium: {premium_saved}[/bold cyan] | [bold green]Total: {len(actually_saved)}[/bold green]")
            else:
                console.print(f"  Saved symbols: Community: {community_saved} | [bold green]Total: {len(actually_saved)}[/bold green]")
        if skipped_vendored_count > 0:
            console.print(f"  Skipped symbols: {skipped_vendored_count} (Vendored/3rd Party directories)")
        console.print("")
    else:
        console.print("[bold green]No dead symbols found![/bold green]\n")

    # Overall summary
    if not orphans and not dead_symbols:
        console.print("[bold green]Your codebase is clean![/bold green]")
    else:
        console.print(f"[dim]Use 'janitor clean' to safely remove dead code[/dim]")

    # Licensing footer
    licensing = reference_tracker.get_licensing_status()
    if not licensing['has_premium']:
        console.print(f"\n[bold yellow]NOTE:[/bold yellow] Using Community Rules ({licensing['community_rules']} patterns). [cyan]Premium Wisdom Pack[/cyan] not detected.")
        console.print(f"[dim]Upgrade for advanced framework detection: https://github.com/GhrammR/the-janitor[/dim]")


@app.command()
def clean(
    project_path: str = typer.Argument(".", help="Project root path to clean"),
    mode: str = typer.Option(None, "--mode", "-m", help="Clean mode: 'files', 'symbols', or 'both'"),
    language: str = typer.Option("python", "--language", "-l", help="Language to analyze for symbol cleaning (python, javascript, typescript)"),
    library: bool = typer.Option(False, "--library", help="Library mode: treat all public symbols as immortal"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted without actually deleting"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    skip_tests: bool = typer.Option(False, "--skip-tests", help="Skip running tests (NOT RECOMMENDED)"),
    test_command: str = typer.Option(None, "--test-command", help="Custom test command (default: pytest)"),
    include_vendored: bool = typer.Option(False, "--include-vendored", help="Include vendored/3rd-party code in cleanup"),
    grep_shield: bool = typer.Option(False, "--grep-shield", help="Enable grep shield (dynamic usage detection). WARNING: Slow on large codebases."),
):
    """Remove dead code (files or symbols) after running tests for safety."""

    project_path = Path(project_path).resolve()

    if not project_path.exists():
        console.print(f"[bold red]Error:[/bold red] Project path does not exist: {escape(str(project_path))}")
        raise typer.Exit(1)

    # Prompt for mode if not provided
    if mode is None:
        console.print("[bold yellow]No clean mode specified.[/bold yellow]")
        mode = typer.prompt(
            "What would you like to clean?",
            type=click.Choice(["Files", "Symbols", "Both"], case_sensitive=False),
            default="Both"
        ).lower()

    if mode not in ['files', 'symbols', 'both']:
        console.print(f"[bold red]Error:[/bold red] Invalid mode '{escape(mode)}'. Use 'files', 'symbols', or 'both'.")
        raise typer.Exit(1)

    console.print(f"[bold blue]Analyzing project:[/bold blue] {project_path}\n")
    console.print(f"[bold blue]Mode:[/bold blue] {mode}\n")

    # Run Baseline Test
    console.print("Running baseline tests...")
    sandbox = TestSandbox(project_path)
    baseline = sandbox.run_baseline_test(test_command)
    baseline_failures_count = baseline["failure_count"]
    baseline_failures_set = baseline["failures"]
    baseline_status = baseline.get("status", "RAN")

    if baseline["exit_code"] != 0 or baseline_status == "NO_TESTS_FOUND":
        if baseline_status == "NO_TESTS_FOUND":
             console.print(f"\n[bold yellow]NOTICE:[/bold yellow] No tests detected for this environment. Manual verification is recommended.")
        elif baseline_failures_count == 0 and baseline["exit_code"] != 0: 
             # Non-zero exit but no parsed failures (maybe runtime crash or parsing issue)
             console.print(f"[bold red]WARNING:[/bold red] Baseline tests failed (Exit Code {baseline['exit_code']}) but no individual failures were parsed.")
        else:
             console.print(f"\n[bold red]WARNING:[/bold red] The repository has pre-existing test failures ({baseline_failures_count}).")
             
             # Show first 10 failures
             table = Table(title="Baseline Failures (Top 10)")
             table.add_column("Test ID", style="red")
             
             sorted_failures = sorted(list(baseline_failures_set))
             for failure in sorted_failures[:10]:
                 table.add_row(failure)
                 
             if len(baseline_failures_set) > 10:
                 table.add_row(f"... and {len(baseline_failures_set) - 10} more")
                 
             console.print(table)
             
        console.print("\n[dim]Cleaning will proceed, but verification will check for NEW failures (Fingerprinting).[/dim]\n")
    else:
        console.print("[green]Baseline tests passed.[/green]\n")

    # Use shared analysis function (optimized with lazy analysis and graph filtering)
    # Progress bars enabled for visual feedback during analysis
    console.print("[bold blue]Analyzing project...[/bold blue]\n")
    orphans, dead_symbols, all_entities, reference_tracker, graph = analyze_project(
        project_path, language, library_mode=library, grep_shield=grep_shield, show_progress=True
    )
    console.print("")  # Add spacing after progress bars

    # Filter based on mode
    if mode == 'files':
        dead_symbols = []
    elif mode == 'symbols':
        orphans = []

    # Create orphan detector for display
    orphan_detector = OrphanDetector(project_path)

    # Display what will be cleaned
    if mode in ['files', 'both'] and orphans:
        console.print(f"\n[bold yellow]Found {len(orphans)} dead file(s) to delete:[/bold yellow]\n")

        table = Table(title="Files to Delete")
        table.add_column("File Path", style="cyan", no_wrap=False)
        table.add_column("Reason", style="magenta")

        for orphan in orphans:
            try:
                display_path = Path(orphan).relative_to(project_path)
            except ValueError:
                display_path = orphan
            table.add_row(str(display_path), "Zero incoming dependencies")

        console.print(table)
    elif mode in ['files', 'both']:
        console.print("[bold green]No dead files found.[/bold green]")

    if mode in ['symbols', 'both']:
        console.print(f"Found {len(all_entities)} symbols, {len(dead_symbols)} are dead")

    # ==========================
    #    VENDORED FILTERING
    # ==========================
    skipped_vendored_count = 0

    if not include_vendored:
        # Filter orphan files
        if orphans:
            vendored_orphans = [f for f in orphans if orphan_detector.is_vendored(f)]
            skipped_vendored_count += len(vendored_orphans)
            orphans = [f for f in orphans if not orphan_detector.is_vendored(f)]

        # Filter dead symbols
        if dead_symbols:
            vendored_symbols = [s for s in dead_symbols if orphan_detector.is_vendored(s.file_path)]
            skipped_vendored_count += len(vendored_symbols)
            dead_symbols = [s for s in dead_symbols if not orphan_detector.is_vendored(s.file_path)]

    # ==========================
    #    DISPLAY DELETION LISTS
    # ==========================

    if mode in ['files', 'both'] and orphans:
        # Display files to be deleted
        console.print(f"\n[bold yellow]Found {len(orphans)} dead file(s) to delete:[/bold yellow]\n")

        table = Table(title="Files to Delete")
        table.add_column("File Path", style="cyan", no_wrap=False)
        table.add_column("Reason", style="magenta")

        for orphan in orphans:
            try:
                display_path = Path(orphan).relative_to(project_path)
            except ValueError:
                display_path = orphan
            table.add_row(str(display_path), "Zero incoming dependencies")

        console.print(table)
    elif mode in ['files', 'both']:
        console.print("[bold green]No dead files found.[/bold green]")

    if mode in ['symbols', 'both']:
        if not dead_symbols:
            console.print("[bold green]No dead symbols found.[/bold green]")
            # Do NOT return here if mode is 'both', otherwise we skip file deletion confirmation/execution!
            if mode == 'symbols':
                return
        else:
            # Group dead symbols by file
            symbols_by_file = {}
            for symbol in dead_symbols:
                file_path = Path(symbol.file_path)
                if file_path not in symbols_by_file:
                    symbols_by_file[file_path] = []
                symbols_by_file[file_path].append(symbol)

            # Display symbols to be removed
            console.print(f"\n[bold yellow]Found {len(dead_symbols)} dead symbol(s) to remove:[/bold yellow]\n")

            table = Table(title="Symbols to Remove")
            table.add_column("Symbol", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("File", style="magenta", no_wrap=False)
            table.add_column("Line", style="green")

            for symbol in dead_symbols:
                try:
                    display_path = Path(symbol.file_path).relative_to(project_path)
                except ValueError:
                    display_path = symbol.file_path

                # Use qualified name for clarity (e.g., ClassName.method_name)
                display_name = symbol.qualified_name if symbol.qualified_name else symbol.name

                table.add_row(display_name, symbol.type, str(display_path), str(symbol.start_line))

            console.print(table)

    # Vendored items notification
    if skipped_vendored_count > 0:
        console.print(f"\n[dim]Note: Skipped {skipped_vendored_count} vendored symbols/files from deletion list.[/dim]")



    # ==========================
    #    DISPLAY & CONFIRMATION
    # ==========================
    
    has_work = False
    
    if orphans:
        has_work = True
        
    if dead_symbols:
        has_work = True
        
    if not has_work:
         console.print("[bold green]Project is clean. No dead code found.[/bold green]")
         return

    if dry_run:
        console.print("\n[bold blue]DRY RUN - No changes were made[/bold blue]")
        return
        
    if not yes:
        console.print("\n[bold yellow]Warning:[/bold yellow] This will delete files and/or modify code in place.")
        confirm = typer.confirm("Proceed with cleanup?", default=False)
        if not confirm:
            console.print("[red]Aborted[/red]")
            return
            
    # ==========================
    #       EXECUTION
    # ==========================

    # 1. Delete Files
    if orphans:
        console.print("\n[bold blue]Deleting files...[/bold blue]")
        safe_deleter = SafeDeleter(project_path / ".janitor_trash")
        
        if skip_tests:
             console.print("[yellow]Warning: Skipping tests (--skip-tests)[/yellow]")
             for orphan in orphans:
                 try:
                     safe_deleter.delete(orphan, reason="orphan")
                 except Exception as e:
                     console.print(f"[red]Error deleting {orphan}: {e}[/red]")
             console.print(f"[bold green]Deleted {len(orphans)} file(s)[/bold green]")
        else:
            console.print("Running tests to verify deletion safety...")
            result = sandbox.delete_with_tests(
                files=orphans,
                reason="orphan",
                safe_deleter=safe_deleter,
                test_command=test_command,
                allowed_failures=baseline_failures_set
            )
            if not result["success"]:
                 console.print(f"\n[bold red]Clean aborted: Checks failed. New failures detected.[/bold red]")
                 console.print(result.get('test_output', ''))
                 raise typer.Exit(1)
            console.print(f"[bold green]Deleted {result['deleted_count']} file(s)[/bold green]")
        
        # If we deleted files, we ideally should refresh symbols but we rely on simple filtration or safe removal
        # If a file is deleted, we can't delete symbols from it (obviously).
        # We rely on existing checks during symbol removal.

    # 2. Delete Symbols
    if dead_symbols:
        # Re-verify symbols are still valid (file still exists)
        valid_symbols = [s for s in dead_symbols if Path(s.file_path).exists()]
        
        if valid_symbols:
             console.print(f"\n[bold blue]Removing {len(valid_symbols)} symbols...[/bold blue]")
             
             # Group by file
             symbols_by_file = {}
             for symbol in valid_symbols:
                file_path = Path(symbol.file_path)
                if file_path not in symbols_by_file:
                    symbols_by_file[file_path] = []
                symbols_by_file[file_path].append(symbol)
                
             deletion_ids = []
             try:
                 from reaper.symbol_remover import SymbolRemover
                 from reaper.js_remover import JSSymbolRemover
                 
                 python_remover = SymbolRemover()
                 js_remover = JSSymbolRemover()
                 # Reuse safe_deleter for backups
                 safe_deleter = SafeDeleter(project_path / ".janitor_trash")

                 # Read files
                 file_contents = {}
                 for fpath in symbols_by_file:
                     with open(fpath, 'r', encoding='utf-8') as f:
                         file_contents[fpath] = f.read()
                 
                 # Process removals
                 python_work = {k:v for k,v in symbols_by_file.items() if k.suffix == '.py'}
                 js_work = {k:v for k,v in symbols_by_file.items() if k.suffix in ('.js', '.ts', '.jsx', '.tsx')}
                 
                 results = {}
                 if python_work:
                      results.update(python_remover.remove_symbols_batch(python_work, file_contents))
                 if js_work:
                      results.update(js_remover.remove_symbols_batch(js_work, file_contents))
                      
                 # Backup
                 for fpath in symbols_by_file:
                      did = safe_deleter.delete(fpath, reason="symbol_removal_backup")
                      deletion_ids.append((fpath, did))
                      
                 # Write
                 modified_count = 0
                 for fpath, (code, _) in results.items():
                      with open(fpath, 'w', encoding='utf-8') as f:
                          f.write(code)
                      modified_count += 1
                      
                 console.print(f"[bold green]Modified {modified_count} files.[/bold green]")

                 # Verify
                 if not skip_tests:
                     console.print("Running tests to verify symbol removal...")
                     res = sandbox._run_tests(test_command)
                     
                     success = False
                     current_failures = sandbox._parse_failures(res["stdout"] + res["stderr"])
                     new_failures = current_failures - baseline_failures_set
                     
                     # Success if exit code 0 OR if no new failures are introduced
                     if res["exit_code"] == 0:
                         success = True
                     elif not new_failures:
                         success = True
                             
                     if not success:
                         console.print(f"[bold red]Symbol removal failed verification. New failures detected.[/bold red]")
                         # Print new failures
                         if new_failures:
                             console.print("[red]New failing tests:[/red]")
                             for nf in new_failures:
                                 console.print(f" - {nf}")
                                 
                         console.print("[yellow]Rolling back...[/yellow]")
                         for _, del_id in deletion_ids:
                             safe_deleter.restore(del_id)
                         console.print(res.get('test_output', res['stderr']))
                         raise typer.Exit(1)
                         
                 console.print("[bold green]Symbol removal verified successfully.[/bold green]")

             except Exception as e:
                 console.print(f"[red]Error removing symbols: {e}. Restoring...[/red]")
                 for _, del_id in deletion_ids:
                     safe_deleter.restore(del_id)
                 raise typer.Exit(1)


@app.command()
def dedup(
    project_path: str = typer.Argument(".", help="Project root path to analyze"),
    language: str = typer.Option("python", "--language", "-l", help="Language to analyze (python, javascript, typescript)"),
    threshold: float = typer.Option(0.90, "--threshold", "-t", help="Similarity threshold (0.0-1.0)"),
    limit: int = typer.Option(10, "--limit", help="Maximum number of duplicates to show")
):
    """Find and suggest merges for duplicate/similar functions using AI."""

    project_path = Path(project_path).resolve()

    if not project_path.exists():
        console.print(f"[bold red]Error:[/bold red] Project path does not exist: {escape(str(project_path))}")
        raise typer.Exit(1)

    console.print(f"[bold blue]Analyzing code for duplicates:[/bold blue] {project_path}\n")

    # Build dependency graph to get all files
    console.print("Discovering source files...")
    graph_builder = DependencyGraphBuilder(project_path)
    graph = graph_builder.build_graph()
    all_files = list(graph.nodes())

    console.print(f"Found {len(all_files)} files")

    # Parse all files and extract entities
    console.print(f"Extracting {language} functions and classes...")
    all_entities = []

    for file_path in all_files:
        file_path = Path(file_path)

        # Check if file matches language
        parser = LanguageParser.from_file_extension(file_path)
        if not parser or parser.language != language:
            continue

        # Parse file
        tree = parser.parse_file(file_path)
        if not tree:
            continue

        # Extract entities
        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()

            extractor = EntityExtractor(language)
            entities = extractor.extract_entities(tree, source_code, str(file_path))
            all_entities.extend(entities)

        except (IOError, OSError):
            continue

    console.print(f"Extracted {len(all_entities)} entities")

    if not all_entities:
        console.print("[yellow]No functions or classes found to analyze[/yellow]")
        return

    # Index entities in ChromaDB
    console.print("Building semantic index with ChromaDB...")
    memory = SemanticMemory(project_path / ".janitor_db")
    memory.index_entities(all_entities, language)

    # Find duplicates
    console.print(f"Finding duplicates (threshold: {threshold:.0%})...")
    duplicates = []
    seen_pairs = set()

    for entity in all_entities:
        similar = memory.find_similar_entities(entity, language, threshold)

        for sim in similar:
            # Create unique pair ID to avoid duplicates
            # Use qualified_name and start_line for globally unique identification
            entity_qualified = entity.qualified_name if entity.qualified_name else entity.name
            sim_qualified = sim.get('qualified_name', sim['name'])

            pair_id = tuple(sorted([
                f"{entity.file_path}::{entity_qualified}::{entity.start_line}",
                f"{sim['file_path']}::{sim_qualified}::{sim['start_line']}"
            ]))

            if pair_id not in seen_pairs:
                seen_pairs.add(pair_id)
                duplicates.append((entity, sim))

    if not duplicates:
        console.print("[bold green]No duplicate code found! Your codebase is well-organized.[/bold green]")
        return

    # Limit results
    duplicates = duplicates[:limit]

    console.print(f"\n[bold yellow]Found {len(duplicates)} duplicate/similar code pair(s)[/bold yellow]\n")

    # Analyze duplicates with LLM
    try:
        llm_client = LLMClient()
        refactor = SemanticRefactor(llm_client)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {escape(str(e))}")
        console.print("[yellow]Showing duplicates without refactoring suggestions[/yellow]\n")
        refactor = None

    # Display duplicates
    for idx, (entity, sim) in enumerate(duplicates, 1):
        similarity = sim['similarity']

        # Create relative paths for display
        try:
            path1 = Path(entity.file_path).relative_to(project_path)
            path2 = Path(sim['file_path']).relative_to(project_path)
        except ValueError:
            path1 = entity.file_path
            path2 = sim['file_path']

        console.print(f"[bold cyan]Duplicate #{idx}[/bold cyan] - Similarity: {similarity:.1%}")

        # Show original functions in panels
        console.print(Panel(
            Syntax(entity.full_text, language, theme="monokai", line_numbers=True),
            title=f"Function 1: {entity.name} ({path1}:{entity.start_line})",
            border_style="cyan"
        ))

        console.print(Panel(
            Syntax(sim['full_text'], language, theme="monokai", line_numbers=True),
            title=f"Function 2: {sim['name']} ({path2}:{sim['start_line']})",
            border_style="cyan"
        ))

        # Get refactoring suggestion if LLM available
        if refactor:
            # Use 0.9999 threshold to catch floating-point precision issues
            if similarity >= 0.9999:
                # Exact duplicate (1.0 similarity)
                # Check if both entities are in the same file
                same_file = entity.file_path == sim['file_path']

                if same_file:
                    # Both in same file - suggest removing one function
                    entity_display = entity.qualified_name if entity.qualified_name else entity.name
                    sim_display = sim.get('qualified_name', sim['name'])
                    suggestion = (
                        f"[bold green]IDENTICAL DUPLICATE[/bold green]\n\n"
                        f"These functions have 100% identical code within the same file.\n\n"
                        f"[bold yellow]Recommendation:[/bold yellow]\n"
                        f"1. Remove the duplicate function: {sim_display} (line {sim['start_line']})\n"
                        f"2. Keep: {entity_display} (line {entity.start_line})\n"
                        f"3. Update all references to use the remaining function\n"
                        f"4. Run tests to verify no regressions"
                    )
                else:
                    # Different files - suggest deleting one file or consolidating
                    suggestion = (
                        f"[bold green]IDENTICAL DUPLICATE[/bold green]\n\n"
                        f"These functions have 100% identical code.\n\n"
                        f"[bold yellow]Recommendation:[/bold yellow]\n"
                        f"1. Delete the duplicate from: {path2}\n"
                        f"2. Update all imports to use: {path1}\n"
                        f"3. Run tests to verify no regressions"
                    )

                console.print(Panel(
                    suggestion,
                    title="[bold green]IDENTICAL DUPLICATE[/bold green]",
                    border_style="green"
                ))
            else:
                # Use LLM to merge
                console.print("[dim]Generating refactoring suggestion with AI...[/dim]")

                # Create entity from sim dict
                from analyzer.extractor import Entity as EntityClass
                similar_entity = EntityClass(
                    name=sim['name'],
                    type=sim['type'],
                    full_text=sim['full_text'],
                    start_line=sim['start_line'],
                    end_line=sim['end_line'],
                    file_path=sim['file_path']
                )

                plan = refactor.merge_similar_functions(entity, similar_entity, similarity)

                if plan.merged_code:
                    console.print(Panel(
                        Syntax(plan.merged_code, language, theme="monokai", line_numbers=True),
                        title=f"Suggested Merge (saves ~{plan.estimated_lines_saved} lines)",
                        border_style="green"
                    ))
                else:
                    console.print(Panel(
                        "[red]Failed to generate merge suggestion[/red]",
                        border_style="red"
                    ))

        console.print()  # Blank line between duplicates

    # Summary
    console.print(f"[bold yellow]Summary:[/bold yellow]")
    console.print(f"  Total entities analyzed: {len(all_entities)}")
    console.print(f"  Duplicate pairs found: {len(duplicates)}")
    console.print(f"  Similarity threshold: {threshold:.0%}")


# =========================================================================
# CACHE MANAGEMENT COMMANDS
# =========================================================================

@cache_app.command("clear")
def cache_clear(
    project_path: str = typer.Argument(".", help="Project root path"),
):
    """Clear the analysis cache for a project.

    This forces a full re-analysis on the next audit or clean command.
    Completes in <200ms without running any analysis phases.
    """
    project_path = Path(project_path).resolve()

    if not project_path.exists():
        console.print(f"[bold red]Error:[/bold red] Project path does not exist: {escape(str(project_path))}")
        raise typer.Exit(1)

    # Initialize cache and clear
    cache = AnalysisCache(project_path)
    cache.clear_cache()
    cache.close()

    console.print(f"[green]✓ Cache cleared for {escape(str(project_path))}[/green]")


@cache_app.command("stats")
def cache_stats(
    project_path: str = typer.Argument(".", help="Project root path"),
):
    """Display cache statistics for a project.

    Shows the number of cached files, symbols, and dependencies.
    """
    project_path = Path(project_path).resolve()

    if not project_path.exists():
        console.print(f"[bold red]Error:[/bold red] Project path does not exist: {escape(str(project_path))}")
        raise typer.Exit(1)

    # Initialize cache and get stats
    cache = AnalysisCache(project_path)
    stats = cache.get_cache_stats()
    cache.close()

    # Display stats in a table
    table = Table(title=f"Cache Statistics: {project_path}", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Total Files Cached", str(stats['total_files']))
    table.add_row("Symbol Definitions", str(stats['symbol_definitions_cached']))
    table.add_row("File References", str(stats['file_references_cached']))
    table.add_row("File Dependencies", str(stats['dependencies_cached']))
    table.add_row("Metaprogramming Danger", str(stats['metaprogramming_danger_cached']))

    console.print(table)


# Register cache sub-command
app.add_typer(cache_app)


@app.callback()
def main():
    """The Janitor - Autonomous dead-code deletion and semantic deduplication."""
    pass


if __name__ == "__main__":
    app()
