# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : pypi_collect.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:44
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import requests
from bs4 import BeautifulSoup
from file_operation import mkdir


def pypi_pkg_links(pypi_mirrors, pkgname, dataset_pypi, input_version=None) -> int:
    flag = 0
    versions = set()
    extension_tar = ".tar.gz"
    extension_zip = ".zip"
    extension_whl = ".whl"
    for mirror, url in pypi_mirrors.items():
        pkgurl = os.path.join(url, "simple", pkgname)
        rq = requests.get(pkgurl)
        if rq.status_code == 200:
            #  为包创建文件夹
            soup = BeautifulSoup(rq.content, 'html.parser')  # 文档对象
            if len(soup.find_all('a')) > 10:
                break
            # 查找文档中所有a标签
            for a in soup.find_all('a'):
                # 查找href标签
                link = a.get('href')
                if link.startswith("http:"):
                    download_link = link
                elif link.startswith("../../"):
                    download_link = url + link.replace("../../", "")
                else:
                    download_link = url + link.replace("../../", "")
                link_filename = a.text.lower()
                if input_version and sorted(versions) == sorted(set(input_version)):
                    flag = 1
                    break
                if link_filename.endswith(extension_whl) or link_filename.endswith(extension_tar) or link_filename.endswith(extension_zip):
                    try:
                        extracted_version = link_filename.replace(pkgname + '-', "").replace(extension_tar, "").replace(extension_zip, "").replace(extension_whl, "").replace("-py3-none-any","").replace('/', '-')
                    except:
                        extracted_version = 'aaa.bbb.ccc'
                    if extracted_version in versions:
                        continue
                    if input_version:
                        if extracted_version in input_version:
                            source_code_filename = os.path.join(dataset_pypi, pkgname, extracted_version, link_filename)
                            if source_code_filename.endswith(".whl"):
                                source_code_filename = source_code_filename.replace(".whl", ".tar.gz")
                            file_response = requests.get(download_link)
                            if file_response.status_code == 200:
                                print("Download from ", mirror)
                                mkdir(dataset_pypi, pkgname, extracted_version)
                                with open(source_code_filename, "ab") as f:
                                    f.write(file_response.content)
                                    f.flush()
                                    versions.add(extracted_version)
                                    flag = 1
                    else:
                        source_code_filename = os.path.join(dataset_pypi, pkgname, extracted_version, link_filename)
                        if source_code_filename.endswith(".whl"):
                            source_code_filename = source_code_filename.replace(".whl", ".tar.gz")
                        file_response = requests.get(download_link)
                        if file_response.status_code == 200:
                            print("Download from ", mirror)
                            mkdir(dataset_pypi, pkgname, extracted_version)
                            with open(source_code_filename, "ab") as f:
                                f.write(file_response.content)
                                f.flush()
                                versions.add(extracted_version)
                                flag = 1
        if flag:
            break
    return flag
