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
