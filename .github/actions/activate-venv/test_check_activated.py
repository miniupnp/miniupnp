#    Copyright 2024 Chia Network Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

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
