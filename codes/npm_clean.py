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
    # 遍历包名文件夹
    for package_name in os.listdir(base_folder):
        package_path = os.path.join(base_folder, package_name)

        # 确保当前路径是一个文件夹
        if os.path.isdir(package_path):
            # 获取版本号文件夹列表
            versions = [v for v in os.listdir(package_path) if os.path.isdir(os.path.join(package_path, v))]

            # 如果只有一个版本且是0.0.1-security，删除整个包名文件夹
            if len(versions) == 1 and versions[0] == "0.0.1-security":
                print(f"Deleting package folder: {package_path}")
                shutil.rmtree(package_path)
            # 如果有多个版本且包含0.0.1-security，删除0.0.1-security版本文件夹
            elif "0.0.1-security" in versions:
                version_path = os.path.join(package_path, "0.0.1-security")
                print(f"Deleting version folder: {version_path}")
                shutil.rmtree(version_path)
            else:
                print(f"Skipping package: {package_name}, versions: {versions}")


# 使用函数
base_folder = "/Users/blue/Documents/MalDataset/npm"
clean_package_folders(base_folder)
