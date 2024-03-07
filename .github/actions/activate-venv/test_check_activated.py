import os
import pathlib
import sys

reference = pathlib.Path(os.environ["REFERENCE_PATH"]).absolute()
actual = pathlib.Path(sys.executable)
expected_inside = {"true": True, "false": False}[os.environ["EXPECTED_INSIDE"]]

is_inside: bool
try:
    actual.relative_to(reference)
except ValueError:
    is_inside = False
else:
    is_inside = True

correct = expected_inside == is_inside

print(f"      reference: {reference}")
print(f"         actual: {actual}")
print(f"expected_inside: {expected_inside}")
print(f"      is_inside: {is_inside}")
print(f"        correct: {'yes' if correct else 'no'}")

if not correct:
    sys.exit(1)
