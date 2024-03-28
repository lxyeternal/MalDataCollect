# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : nuget_collect.py
# @Project  : MalDataCollect
# Time      : 2023/11/21 16:13
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import requests
from file_operation import mkdir


def nuget_pkg_links(nuget_mirrors, pkgname, dataset_nuget) -> int:
    flag = 0
    for mirror, url in nuget_mirrors.items():
        response = requests.get(url.format(pkgname))
        if response.status_code == 200:
            data = response.json()
            items_data = data.get('items', {})
            versions_data = items_data[0]["items"]
            for details in versions_data:
                version = details["catalogEntry"].get('version', 'NA')
                complete_link = details["packageContent"]
                file_name = os.path.basename(complete_link)
                mkdir(dataset_nuget, pkgname.replace("/", "##"), version)
                save_path = os.path.join(dataset_nuget, pkgname.replace("/", "##"), version, file_name)
                file_response = requests.get(complete_link)
                with open(save_path, "ab") as f:
                    f.write(file_response.content)
                    f.flush()
                    flag = 1
        if flag:
            break
    return flag