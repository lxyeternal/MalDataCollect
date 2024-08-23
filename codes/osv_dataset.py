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
import ast
import json
from pymongo import MongoClient
from codes.pypi_collect import pypi_pkg_links


def extract_json_files(directory):
    json_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                json_files.append(os.path.join(root, file))
    return json_files


def save_info_txt(package_manager, package_name, version, file_path):
    with open(file_path, "a") as fw:
        fw.write(package_manager + "\t" + package_name + "\t" + version + "\n")


def osv_dataset():
    dataset_dir = "/Users/blue/Downloads/OSV"
    pkg_managers = os.listdir(dataset_dir)
    for pkg_manager in pkg_managers:
        if pkg_manager == "npm":
            pkg_names = os.listdir(os.path.join(dataset_dir, pkg_manager))
            for pkg_name in pkg_names:
                json_files = extract_json_files(os.path.join(dataset_dir, pkg_manager, pkg_name))
                for pkg_malinfo_file in json_files:
                    with open(pkg_malinfo_file, "r") as fr:
                        malinfo = json.load(fr)
                        affected_info = malinfo.get("affected", [])
                        references_info = malinfo.get("references", [])
                        for reference_info in references_info:
                            type = reference_info.get("type", "NA")
                            url = reference_info.get("url", "NA")
                            if type != "NA":
                                print(type + "\t" + url)
                        for affected in affected_info:
                            package_info = affected.get("package", {})
                            package_name = package_info.get("name", "NA")
                            package_version = affected.get("versions", [])
                            if package_version != []:
                                print(package_name + "\t" + str(package_version))
                            else:
                                print(package_name)
                            save_info_txt(pkg_manager, package_name, str(package_version), "../records/osv_npm_dataset.txt")

def read_txt(file_path):
    package_names = []
    with open(file_path, "r") as fr:
        lines = fr.readlines()
        for line in lines:
            package_manager, package_name, version = line.strip().split("\t")
            package_names.append([package_manager, package_name, version])
    return package_names


def osv_collection():
    pypi_mirrors = {"tencent": "http://mirrors.cloud.tencent.com/pypi/", "tsinghua": "https://pypi.tuna.tsinghua.edu.cn/", "douban": "http://pypi.doubanio.com/"}
    package_names = read_txt("../records/osv_dataset.txt")
    collected_pkgs = os.listdir("/Users/blue/Documents/MalDataset/pypi")
    for index, pkg in enumerate(package_names):
        print("Processing ", index)
        package_manager = pkg[0]
        package_name = pkg[1]
        versions = pkg[2]
        if versions == "[]":
            versions = None
        else:
            print(package_name, versions)
            versions = ast.literal_eval(versions)
        if package_name in collected_pkgs:
            continue
        else:
            pypi_pkg_links(pypi_mirrors, package_name, "/Users/blue/Documents/MalDataset/osv_pypi", versions)


def query_mongodb(requested_name):
    # 连接到MongoDB
    client = MongoClient('mongodb://localhost:27017/')  # 替换为你的MongoDB连接字符串
    # 选择数据库和集合
    db = client['pypi']  # 替换为你的数据库名
    collection = db['pypimetadata']  # 替换为你的集合名
    # 尝试原始名称和替换 "-" 为 "_" 的名称
    names_to_try = [requested_name, requested_name.replace('-', '_')]
    results = []
    for name in names_to_try:
        # 构建查询
        query = {"requested_name": name}
        # 执行查询
        results = list(collection.find(query))
        if results:
            break  # 如果找到结果，就退出循环
    if not results:
        # print(f"No results found for package: {requested_name}")
        pass
    else:
        for document in results:
            if 'releases' in document:
                releases = document['releases']
                for version, release_info in releases.items():
                    if release_info and isinstance(release_info, list) and len(release_info) > 0:
                        url = release_info[0].get('url')
                        if url:
                            print(f"Package: {requested_name}, Version: {version}, URL: {url}")


def data_existed():
    dataset_dir = "/Users/blue/Documents/GitHub/pypi_malregistry"
    exist_packages = os.listdir(dataset_dir)
    package_names = read_txt("../records/osv_dataset.txt")
    for pkg in package_names:
        package_name = pkg[1]
        if package_name not in exist_packages:
            query_mongodb(package_name)


osv_dataset()

