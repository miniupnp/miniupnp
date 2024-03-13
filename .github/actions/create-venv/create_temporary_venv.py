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
import tempfile
import venv

runner_temp = os.environ["RUNNER_TEMP"]
temporary_directory = pathlib.Path(tempfile.mkdtemp(dir=runner_temp))
github_output = pathlib.Path(os.environ["GITHUB_OUTPUT"])

python_executable: pathlib.Path
if sys.platform == "win32":
    python_executable = temporary_directory.joinpath("Scripts", "python.exe")
else:
    python_executable = temporary_directory.joinpath("bin", "python")

activate_venv_directories = json.dumps([os.fspath(temporary_directory)])

with github_output.open("a") as file:
    print(f"temp-venv-path={os.fspath(temporary_directory.as_posix())}", file=file)
    print(
        f"temp-python-executable={os.fspath(python_executable.as_posix())}",
        file=file,
    )
    print(f"activate-venv-directories={activate_venv_directories}", file=file)

venv.create(env_dir=temporary_directory, with_pip=True)
