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

import json
import os
import pathlib
import sys

directories = [
    pathlib.Path(directory).absolute()
    for directory in json.loads(os.environ["INPUT_DIRECTORIES"])
]
github_env = pathlib.Path(os.environ["GITHUB_ENV"])
github_path = pathlib.Path(os.environ["GITHUB_PATH"])

for directory in directories:
    if directory.exists():
        break

    print(f"No environment found at: {os.fspath(directory)}")
else:
    print("No environment found")
    sys.exit(1)

print(f"Environment found at: {os.fspath(directory)}")

if sys.platform == "win32":
    bin_scripts_path = directory.joinpath("Scripts")
else:
    bin_scripts_path = directory.joinpath("bin")

with github_path.open("a") as file:
    print(os.fspath(bin_scripts_path), file=file)

with github_env.open("a") as file:
    print(f"VIRTUAL_ENV={os.fspath(directory)}", file=file)
