#!/usr/bin/env python3
"""Performance benchmarking script for The Janitor."""

import time
import subprocess
import sys

def benchmark_project(project_path, project_name):
    """Run audit and time it."""
    print(f"\n{'='*70}")
    print(f"Benchmarking: {project_name}")
    print(f"Path: {project_path}")
    print(f"{'='*70}\n")

    cmd = [
        sys.executable,
        "-m", "src.main",
        "audit", project_path,
        "--library"
    ]

    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    end = time.time()

    elapsed = end - start

    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    print(f"\n{'-'*70}")
    print(f"Total Time: {elapsed:.2f}s")
    print(f"{'-'*70}\n")

    # Parse output for metrics
    output = result.stdout
    files_count = 0
    symbols_count = 0
    dead_symbols = 0
    protected_symbols = 0

    for line in output.split('\n'):
        if 'Linked' in line and 'files' in line:
            # Parse "Phase 3: Linked 48 files"
            parts = line.split()
            for i, part in enumerate(parts):
                if part.isdigit() and i + 1 < len(parts) and parts[i + 1] == 'files':
                    files_count = int(part)
                    break
        elif 'Total symbols:' in line:
            parts = line.split(':')
            if len(parts) > 1:
                symbols_count = int(parts[1].strip())
        elif 'Dead symbols:' in line:
            parts = line.split(':')
            if len(parts) > 1:
                dead_symbols = int(parts[1].strip())
        elif 'Saved symbols:' in line:
            # Parse "Saved symbols: Community: 37 | Total: 37"
            if 'Total:' in line:
                total_part = line.split('Total:')[1].strip()
                protected_symbols = int(total_part)

    # Calculate Phase 3 time per file
    phase3_per_file = (elapsed / files_count) if files_count > 0 else 0

    return {
        'name': project_name,
        'path': project_path,
        'total_time': elapsed,
        'files': files_count,
        'symbols': symbols_count,
        'dead_symbols': dead_symbols,
        'protected_symbols': protected_symbols,
        'phase3_per_file': phase3_per_file
    }


if __name__ == "__main__":
    benchmarks = [
        ("../janitor-gauntlet/fastapi", "FastAPI"),
        ("../janitor-gauntlet/flask", "Flask"),
        ("../janitor-gauntlet/requests", "Requests"),
    ]

    results = []
    for path, name in benchmarks:
        result = benchmark_project(path, name)
        results.append(result)

    # Summary table
    print("\n" + "="*100)
    print("PERFORMANCE REGRESSION SUMMARY")
    print("="*100)
    print(f"{'Project':<15} {'Files':<8} {'Symbols':<10} {'Total Time':<12} {'Phase3/File':<15} {'Status':<10}")
    print("-"*100)

    for r in results:
        status = "✅ PASS" if r['phase3_per_file'] < 0.2 else "⚠️ SLOW"
        print(f"{r['name']:<15} {r['files']:<8} {r['symbols']:<10} {r['total_time']:<12.2f} {r['phase3_per_file']:<15.4f} {status:<10}")

    print("-"*100)
    print(f"\n{'CRITICAL THRESHOLD: Phase 3 must be <0.2s per file'}")
    print(f"All projects: {len([r for r in results if r['phase3_per_file'] < 0.2])}/{len(results)} PASSED\n")
