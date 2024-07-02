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

def count_packages_and_versions(directory):
    package_count = 0
    version_count = 0

    for package_name in os.listdir(directory):
        package_path = os.path.join(directory, package_name)
        if os.path.isdir(package_path):
            package_count += 1
            version_count += len(os.listdir(package_path))

    return package_count, version_count

if __name__ == "__main__":
    directory = "/Users/blue/Documents/GitHub/pypi_malregistry"
    package_count, version_count = count_packages_and_versions(directory)
    print(f"Total number of package files: {package_count}")
    print(f"Total number of version files: {version_count}")

