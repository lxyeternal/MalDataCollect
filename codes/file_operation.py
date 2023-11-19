# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : file_operation.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:48
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import csv


def read_stop_file(stop_file):
    stop_packages = dict()
    # 打开文件并逐行读取
    with open(stop_file, "r") as file:
        for line in file:
            # 分割每一行为两部分
            key, value = line.strip().split('\t')
            # 将分割后的键值对添加到字典中
            stop_packages[key] = value
    return stop_packages


def write_stop_file(stop_file, stop_packages):
    # 打开文件并逐行读取
    with open(stop_file, "w") as file:
        # 遍历字典中的每个键值对
        for key, value in stop_packages.items():
            # 将键和值以制表符分隔的形式写入一行
            file.write(f"{key}\t{value}\n")


def write_snyk_pkginfo(record_file, snyk_pkginfo):
    folder = os.path.exists(record_file)
    with open(record_file, 'a+') as f:
        #  文件不存在，写表头
        if not folder:
            csv_header = ['manager', 'package_name', 'snyk_link', 'security_score', 'affected_version', 'install_type',
                          'cve', 'cwe', ' fix_method', 'overview', 'update_date', 'package_type', 'axploit_maturity',
                          'attack_complexity', 'confidentiality', 'integrity', 'availability', 'attack_vector',
                          'privileges_required', 'user_interaction', 'scope', 'snyk_id', 'published', 'disclosed',
                          'credit', 'source']
            csv_write = csv.writer(f)
            csv_write.writerow(csv_header)
        csv_write = csv.writer(f)
        csv_write.writerow(snyk_pkginfo)


def mkdir(dataset_pypi, pkgname, version) -> None:
    dirpath = os.path.join(dataset_pypi, pkgname, version)
    folder = os.path.exists(dirpath)
    if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
        os.makedirs(dirpath)  # makedirs 创建文件时如果路径不存在会创建这个路径
    else:
        pass