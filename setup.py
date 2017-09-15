#!/usr/bin/env python

from os import environ
from os.path import abspath, dirname, join
from setuptools import setup, find_packages
from sys import version_info, path as sys_path

deps = ['tornado', 'Twisted', 'requests', 'requests-toolbelt']

# When we build an egg for the Windows bootstrap we don't want dependency
# information built into it.
if environ.get('NO_DEPS'):
    deps = []

srcdir = join(dirname(abspath(__file__)), 'src/')
sys_path.insert(0, srcdir)

setup(
    name='gDNS',
    version='0.1.1',
    description='Google DNS-over-HTTPS',
    url='https://github.com/arn7av/gDNS',
    download_url='https://github.com/arn7av/gDNS/archive/0.1.tar.gz',
    author='arnAV',
    author_email='arnav@arnav.at',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={
      'console_scripts': ['gdns=gdns.main:main']
    },
    install_requires=deps,
    classifiers=[],
)
