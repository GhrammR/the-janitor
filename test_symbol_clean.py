"""Test file for symbol-level cleaning demonstration."""


def used_function():
    """This function is used."""
    return "I am used"


class UsedClass:
    """This class is used."""

    def __init__(self):
        self.value = "used"


class DeadClass:
    """This class is never used."""

    def __init__(self):
        self.value = "dead"


# Actually use the used_function and UsedClass
if __name__ == "__main__":
    print(used_function())
    obj = UsedClass()
    print(obj.method())
