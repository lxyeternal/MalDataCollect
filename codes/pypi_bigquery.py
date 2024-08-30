# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : pypi_bigquery.py
# @Project  : MalDataCollect
# Time      : 12/8/24 10:39 am
# Author    : honywen
# version   : python 3.8
# Description：
"""

import csv
import os
import requests
from collections import defaultdict
from urllib.parse import urlparse


def process_csv_and_download(csv_file_path):
    packages = {}

    # 读取CSV文件
    with open(csv_file_path, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # 跳过第一行

        for row in csv_reader:
            name = row[0]
            version = row[1]
            link = row[5]

            # 如果这个版本还没有下载链接,就添加
            if (name, version) not in packages:
                packages[(name, version)] = link

    # 下载文件
    for (name, version), link in packages.items():
        full_link = f"https://files.pythonhosted.org/packages/{link}"

        # 创建保存路径
        save_dir = f"/Users/blue/Downloads/data/{name}/{version}"
        os.makedirs(save_dir, exist_ok=True)

        # 获取文件名
        file_name = os.path.basename(urlparse(full_link).path)

        # 如果是.whl文件,改名为.zip
        if file_name.endswith('.whl'):
            file_name = file_name[:-4] + '.zip'

        save_path = os.path.join(save_dir, file_name)

        # 下载文件
        response = requests.get(full_link)
        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded: {save_path}")
        else:
            print(f"Failed to download: {full_link}")


def generate_package_summary(root_dir):
    packages = defaultdict(set)

    # 遍历文件夹结构
    for name in os.listdir(root_dir):
        name_path = os.path.join(root_dir, name)
        if os.path.isdir(name_path):
            for version in os.listdir(name_path):
                version_path = os.path.join(name_path, version)
                if os.path.isdir(version_path):
                    packages[name].add(version)

    # 生成摘要
    summary = []
    for name, versions in packages.items():
        versions_str = ', '.join(sorted(versions))
        summary.append(f"{name} [{versions_str}] <br>")

    return '\n'.join(summary)


# 使用函数
# process_csv_and_download('/Users/blue/Downloads/bquxjob_71a4b589_191a150bd4a.csv')
result = generate_package_summary("/Users/blue/Downloads/data")
print(result)
