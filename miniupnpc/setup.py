# MiniUPnP Project (c) 2007-2026 Thomas Bernard
# https://miniupnp.tuxfamily.org/
#
# Build the Python extension from C sources on all platforms.
# Does not shell out to make, so Windows can pip-install from an sdist.

import os
import platform
import sys
from pathlib import Path

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext

LIB_SOURCES = [
    "src/miniwget.c",
    "src/minixml.c",
    "src/igd_desc_parse.c",
    "src/minisoap.c",
    "src/miniupnpc.c",
    "src/upnpreplyparse.c",
    "src/upnpcommands.c",
    "src/upnperrors.c",
    "src/connecthostport.c",
    "src/portlistingparse.c",
    "src/receivedata.c",
    "src/upnpdev.c",
    "src/addr_is_reserved.c",
    # the Makefile only drops this one on AmigaOS
    "src/minissdpc.c",
]


def write_miniupnpcstrings_h(outdir: Path) -> None:
    version = Path("VERSION").read_text(encoding="utf-8").strip()
    os_string = f"{platform.system()}/{platform.release()}"
    text = Path("miniupnpcstrings.h.in").read_text(encoding="utf-8")
    text = text.replace('OS_STRING "OS/version"', f'OS_STRING "{os_string}"')
    text = text.replace(
        'MINIUPNPC_VERSION_STRING "version"',
        f'MINIUPNPC_VERSION_STRING "{version}"',
    )
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "miniupnpcstrings.h").write_text(text, encoding="utf-8")


class build_ext(_build_ext):
    def run(self):
        write_miniupnpcstrings_h(Path(self.build_temp))
        super().run()

    def build_extension(self, ext):
        ext.include_dirs = [self.build_temp, *ext.include_dirs]
        super().build_extension(ext)


define_macros = [
    ("MINIUPNP_STATICLIB", None),
    ("MINIUPNPC_SET_SOCKET_TIMEOUT", None),
    ("MINIUPNPC_GET_SRC_ADDR", None),
]
libraries = []
if os.name == "nt":
    libraries.extend(["ws2_32", "iphlpapi"])
    if sys.version_info >= (3, 5):
        libraries.append("legacy_stdio_definitions")
else:
    define_macros.extend(
        [
            ("_BSD_SOURCE", None),
            ("_DEFAULT_SOURCE", None),
        ]
    )
    if sys.platform not in ("darwin", "freebsd"):
        define_macros.append(("_XOPEN_SOURCE", "600"))
    if sys.platform == "darwin":
        define_macros.append(("_DARWIN_C_SOURCE", None))

setup(
    ext_modules=[
        Extension(
            name="miniupnpc",
            sources=["src/miniupnpcmodule.c", *LIB_SOURCES],
            include_dirs=["include"],
            define_macros=define_macros,
            libraries=libraries,
        )
    ],
    cmdclass={"build_ext": build_ext},
)
