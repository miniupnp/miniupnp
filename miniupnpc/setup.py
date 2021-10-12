#! /usr/bin/env python
# vim: tabstop=8 shiftwidth=8 expandtab
# $Id: setup.py,v 1.14 2020/04/06 10:23:02 nanard Exp $
# the MiniUPnP Project (c) 2007-2021 Thomas Bernard
# https://miniupnp.tuxfamily.org/ or http://miniupnp.free.fr/
#
# python script to build the miniupnpc module under unix
#
# Uses MAKE environment variable (defaulting to 'make')

from setuptools import setup, Extension
from setuptools.command import build_ext
import subprocess
import os

EXT = ['build/libminiupnpc.a']

class make_then_build_ext(build_ext.build_ext):
      def run(self):
            subprocess.check_call([os.environ.get('MAKE', 'make')] + EXT)
            build_ext.build_ext.run(self)

setup(name='miniupnpc',
      version=open('VERSION').read().strip(),
      author='Thomas BERNARD',
      author_email='miniupnp@free.fr',
      license=open('LICENSE').read(),
      url='http://miniupnp.free.fr/',
      description='miniUPnP client',
      cmdclass={'build_ext': make_then_build_ext},
      ext_modules=[
         Extension(name='miniupnpc', sources=['src/miniupnpcmodule.c'],
                   include_dirs=['include'], extra_objects=EXT)
      ],
      )

# deploying scripts didn't work
#      scripts=['miniupnpc.dll'],
#      scripts=glob('*.exe') + glob('*.dll') + glob('*.a') + glob('*.lib'),
# Specifying the files to distribute: https://docs.python.org/3/distutils/sourcedist.html#manifest
