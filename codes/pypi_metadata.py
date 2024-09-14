# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : pypi_metadata.py
# @Project  : MalDataCollect
# Time      : 19/8/24 8:08 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import json
import requests


def mkdir(dataset_pypi, pkgname, version) -> None:
    dirpath = os.path.join(dataset_pypi, pkgname, version)
    folder = os.path.exists(dirpath)
    if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
        os.makedirs(dirpath)  # makedirs 创建文件时如果路径不存在会创建这个路径
    else:
        pass

def package_download(dataset_pypi, pkgname, extracted_version, source_code_filename, download_link):
    file_response = requests.get(download_link)
    if file_response.status_code == 200:
        mkdir(dataset_pypi, pkgname, extracted_version)
        # if source_code_filename.endswith(".whl"):
        #     source_code_filename = source_code_filename.replace(".whl", ".zip")
        with open(source_code_filename, "ab") as f:
            f.write(file_response.content)
            f.flush()


def process_json_and_download(file_path, dataset_pypi):
    downloaded_packages = os.listdir("/Users/blue/Documents/GitHub/malicious-package-dataset")
    # Dictionary to hold the versions and paths for each package
    packages_dict = {}
    # Read and process the JSON file
    with open(file_path, 'r') as f:
        packages = json.load(f)
        for package in packages:
            name = package.get('name', '')
            version = package.get('version', '')
            path = package.get('path', '')
            if not name or not version or not path:
                continue
            # Initialize the package name in the dictionary if not already present
            if name not in packages_dict:
                packages_dict[name] = []
            # Check if the version already exists in the list for this package
            if not any(v['version'] == version for v in packages_dict[name]):
                # Append the version and path as a dictionary to the list for this package
                packages_dict[name].append({'version': version, 'path': path})

    # Download each package that isn't already downloaded
    for pkgname, versions_info in packages_dict.items():
        for info in versions_info:
            version = info['version']
            path = info['path']
            download_url = f"https://files.pythonhosted.org/packages/{path}"
            source_code_filename = os.path.join(dataset_pypi, pkgname, version, os.path.basename(path))
            # Download the package
            package_download(dataset_pypi, pkgname, version, source_code_filename, download_url)




process_json_and_download("/Users/blue/Downloads/bquxjob_70d8f852_191e051697c.json", "/Users/blue/Downloads/new")
