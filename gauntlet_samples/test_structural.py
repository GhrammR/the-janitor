"""Test cases for AST structural verification."""


def simple_add(a, b):
    """Simple addition - should match sum_vals."""
    return a + b


def complex_process(data):
    """Complex function with multiple control flows - should NOT match simple functions."""
    if not data:
        return None

    results = []
    for item in data:
        if item > 0:
            results.append(item * 2)
        else:
            results.append(item)

    while len(results) > 10:
        results.pop()

    return results


def another_simple(x, y):
    """Another simple function - should match simple_add and sum_vals."""
    result = x + y
    return result


def fake_complex():
    """
    This function has a long docstring that mentions many keywords:
    if, for, while, return, process, data, complex, algorithm
    But the actual code is simple.
    Should NOT be confused with complex_process despite textual similarity.
    """
    return 42
