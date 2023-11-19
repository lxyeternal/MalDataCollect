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


def pypi_pkg_links(pypi_mirrors, pkgname, dataset_pypi) -> int:
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
                if link_filename.endswith(extension_whl) or link_filename.endswith(extension_tar) or link_filename.endswith(extension_zip):
                    try:
                        version = link_filename.replace(pkgname + '-', "").replace(extension_tar, "").replace(extension_zip, "").replace(extension_whl, "").replace("-py3-none-any","").replace('/', '-')
                        if version in versions:
                            continue
                    except:
                        version = 'aaa.bbb.ccc'
                    source_code_filename = os.path.join(dataset_pypi, pkgname, version, link_filename)
                    file_response = requests.get(download_link)
                    if file_response.status_code == 200:
                        print(mirror)
                        mkdir(dataset_pypi, pkgname, version)
                        with open(source_code_filename, "ab") as f:
                            f.write(file_response.content)
                            f.flush()
                            versions.add(version)
                            flag = 1
        if flag:
            break
    return flag
