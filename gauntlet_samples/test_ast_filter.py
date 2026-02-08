"""Test AST pre-filter rejection of structurally divergent functions."""


def process_simple(data):
    """
    This function processes data in a simple way.
    It just validates and returns.
    Very straightforward logic.
    No complex control flow here.
    Just a simple data processor.
    """
    # Simple validation
    if not data:
        return None
    return data


def process_complex(data):
    """
    This function processes data in a complex way.
    It just validates and returns.
    Very straightforward logic.
    No complex control flow here.
    Just a simple data processor.
    """
    # Complex processing with multiple control flows
    if not data:
        return None

    results = []
    for item in data:
        if item > 0:
            results.append(item * 2)
        elif item < 0:
            results.append(abs(item))
        else:
            continue

        if len(results) > 100:
            break

    while len(results) > 10:
        results.pop()

    if not results:
        return None

    return results
