# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : count_files.py
# @Project  : MalDataCollect
# Time      : 4/4/24 10:14 am
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os

def count_files():
    count = 0
    directory = "/Users/blue/Documents/GitHub/pypi_malregistry"
    packages = os.listdir(directory)
    for package in packages:
        package_dir = os.path.join(directory, package)
        if os.path.isdir(package_dir):
            versions = os.listdir(package_dir)
            count += len(versions)
    print(count)


count_files()
