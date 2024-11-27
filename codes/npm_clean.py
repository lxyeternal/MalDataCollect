# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : npm_clean.py
# @Project  : MalDataCollect
# Time      : 23/8/24 4:24 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import shutil


def clean_package_folders(base_folder):
    # Traverse package directories
    for package_name in os.listdir(base_folder):
        package_path = os.path.join(base_folder, package_name)

        # Ensure the current path is a directory
        if os.path.isdir(package_path):
            # Get a list of version folders
            versions = [v for v in os.listdir(package_path) if os.path.isdir(os.path.join(package_path, v))]
            # Filter versions that start with '0.0.1-security'
            security_versions = [v for v in versions if v.startswith("0.0.1-security")]

            # If there's only one version and it starts with '0.0.1-security', delete the entire package directory
            if len(versions) == 1 and security_versions:
                print(f"Deleting package folder: {package_path}")
                shutil.rmtree(package_path)
            # If there are multiple versions and any version starts with '0.0.1-security', delete those version folders
            elif security_versions:
                for version in security_versions:
                    version_path = os.path.join(package_path, version)
                    print(f"Deleting version folder: {version_path}")
                    shutil.rmtree(version_path)
            else:
                print(f"Skipping package: {package_name}, versions: {versions}")


# Usage of the function
base_folder = "/Users/blue/Documents/Github/MalDataCollect/malicious-package-dataset/npm"
clean_package_folders(base_folder)
