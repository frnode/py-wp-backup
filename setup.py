#!/usr/bin/env python3
# coding: utf-8

# py-wp-backup
# Copyright (C) 2020 - Node
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages

from py_wp_backup import py_wp_backup_old

setup(
    name='py-wp-backup',
    version=py_wp_backup_old.__version__,
    packages=find_packages(),
    author="frnode",
    author_email="gp.corentin@gmail.com",
    description="Secure Wordpress backup.",
    long_description=open('README.md').read(),
    # install_requires= ,
    include_package_data=True,
    url='http://github.com/frnode/py-wp-backup',

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers.
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 1 - Planning",
        "License :: OSI Approved",
        "Natural Language :: French",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Topic :: Communications",
    ],
    entry_points={
        'console_scripts': [
            'wp-backup = py_wp_backup.py_wp_backup:cli',
        ],
    },
    license="GPL3", install_requires=['click', 'python-gnupg']

)
