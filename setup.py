#!/usr/bin/env python
"""chaostoolkit-cf-appblocker extension builder and installer"""

import sys
import io

import setuptools

name = 'chaostoolkit-cf-appblocker'
desc = 'Chaos Toolkit Extension for Targeted Blocking of Cloud Foundry Apps and Services'

with io.open('README.md', encoding='utf-8') as strm:
    long_desc = strm.read()

classifiers = [
    'Development Status :: 2 - Pre-Alpha',
    'Intended Audience :: Developers',
    'License :: Freely Distributable',
    'Operating System :: OS Independent',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: Implementation',
    'Programming Language :: Python :: Implementation :: CPython'
]
author = "Matthew Conover"
author_email = 'matthew.conover1@t-mobile.com'
url = 'http://chaostoolkit.org'
packages = ['cfblocker']

install_require = []
with io.open('requirements.txt') as f:
    install_require = [l.strip() for l in f if not l.startswith('#')]

setup_params = dict(
    name=name,
    version='0.1.0',
    description=desc,
    long_description=long_desc,
    classifiers=classifiers,
    author=author,
    author_email=author_email,
    url=url,
    packages=packages,
    include_package_data=True,
    install_requires=install_require,
    python_requires='>=3.5.*'
)


def main():
    """Package installation entry point."""
    setuptools.setup(**setup_params)


if __name__ == '__main__':
    main()
