# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : npm_collect.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:44
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import requests
from file_operation import mkdir


def npm_pkg_links(npm_mirrors, pkgname, dataset_npm, versions) -> int:
    flag = 0
    for mirror, url in npm_mirrors.items():
        response = requests.get(os.path.join(url, pkgname))
        if response.status_code == 200:
            data = response.json()
            versions_data = data.get('versions', {})
            if not isinstance(versions_data, dict):
                print(f"No valid version data found for package: {pkgname}")
                continue

            for i, (version, details) in enumerate(versions_data.items()):
                if i >= 10:  # Only process the first 10 versions
                    break
                version = details.get('version', 'N/A')
                if "0" not in versions and version not in versions:
                    continue
                complete_link = details.get('dist', {}).get('tarball', 'N/A')
                link_filename = complete_link.split("/")[-1]
                mkdir(dataset_npm, pkgname.replace("/", "##"), version)
                save_path = os.path.join(dataset_npm, pkgname.replace("/", "##"), version, link_filename)
                file_response = requests.get(complete_link)
                with open(save_path, "ab") as f:
                    f.write(file_response.content)
                    f.flush()
                    flag = 1
                    print(f"Downloaded {pkgname} {version} from {mirror} {os.path.join(url, pkgname)}")
        if flag:
            break
    return flag