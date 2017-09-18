#!/usr/bin/env python

from os import environ
from os.path import abspath, dirname, join
from setuptools import setup, find_packages
from sys import version_info, path as sys_path

gdns_version = '0.1.4'

deps = ['Twisted', 'tornado', 'requests', 'requests-toolbelt']

# When we build an egg for the Windows bootstrap we don't want dependency
# information built into it.
if environ.get('NO_DEPS'):
    deps = []

srcdir = join(dirname(abspath(__file__)), 'src/')
sys_path.insert(0, srcdir)

setup(
    name='gDNS',
    version=gdns_version,
    description='Google DNS-over-HTTPS',
    url='https://github.com/arn7av/gDNS',
    download_url='https://github.com/arn7av/gDNS/archive/{}.tar.gz'.format(gdns_version),
    author='arnAV',
    author_email='arnav@arnav.at',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={
        'console_scripts': ['gdns=gdns.main:main']
    },
    install_requires=deps,
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, <4',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Internet :: Name Service (DNS)',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Framework :: Twisted',
    ],
    keywords='dns https google gdns',
)
