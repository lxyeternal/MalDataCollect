# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : osv_dataset.py
# @Project  : MalDataCollect
# Time      : 27/3/24 12:42 am
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import json


def extract_json_files(directory):
    json_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                json_files.append(os.path.join(root, file))
    return json_files


def osv_dataset():
    dataset_dir = "../osv"
    pkg_managers = os.listdir(dataset_dir)
    for pkg_manager in pkg_managers:
        if pkg_manager == "pypi":
            pkg_names = os.listdir(os.path.join(dataset_dir, pkg_manager))
            for pkg_name in pkg_names:
                json_files = extract_json_files(os.path.join(dataset_dir, pkg_manager, pkg_name))
                for pkg_malinfo_file in json_files:
                    with open(pkg_malinfo_file, "r") as fr:
                        malinfo = json.load(fr)
                        affected_info = malinfo.get("affected", [])
                        for affected in affected_info:
                            package_info = affected.get("package", {})
                            package_name = package_info.get("name", "NA")
                            package_version = affected.get("versions", [])
                            if package_version != []:
                                print(package_name + "\t" + str(package_version))
                            else:
                                print(package_name)


osv_dataset()

