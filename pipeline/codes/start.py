# !/usr/bin/env python
# -*- coding:utf-8 -*-
"""
# @File     : start
# @Project  : MalDataCollect
# Time      : 11/26/24 20:05
# Author    : blue
# version   : python 
# Description：
"""

import os
import json
from snyk_database import SnykDatabase
from osv_database import OSVDatabase
from npm_clean import clean_package_folders




class CollectMain:
    def __init__(self):
        self.config_path = "../configs/config.json"
        with open(self.config_path, "r") as fr:
            self.config = json.load(fr)
        self.osv_baseurl = self.config["osv_baseurl"]
        self.nuget_mirrors = self.config["nuget_mirrors"]
        self.npm_mirrors = self.config["npm_mirrors"]
        self.go_mirrors = self.config["go_mirrors"]
        self.maven_mirrors = self.config["maven_mirrors"]
        self.pypi_mirrors = self.config["pypi_mirrors"]
        self.records_dir = self.config["records_dir"]
        self.chromedriver = self.config["chromedriver"]
        self.dataset_pypi = self.config["dataset_pypi"]
        self.dataset_npm = self.config["dataset_npm"]
        self.dataset_go = self.config["dataset_go"]
        self.dataset_maven = self.config["dataset_maven"]
        self.dataset_nuget = self.config["dataset_nuget"]
        self.dataset_rubygems = self.config["dataset_rubygems"]
        self.snyk_baseurl = self.config["snyk_baseurl"]
        self.synk_vulurl = self.config["synk_vulurl"]
        self.osv_repo_link = self.config["osv_repo_link"]
        self.google_cloud_key = self.config["google_cloud_key"]
        self.manual_packages = []
        self.collected_pkgs = []

    def collect_snyk(self):
        # 初始化Snyk数据库收集器
        snyk_collector = SnykDatabase(
            google_cloud_key=self.google_cloud_key,
            pypi_dataset_path=self.dataset_pypi,
            npm_dataset_path=self.dataset_npm,
            npm_mirrors = self.npm_mirrors,
            chromedriver=self.chromedriver,
            snyk_baseurl=self.snyk_baseurl,
            snyk_vulurl=self.synk_vulurl,
            records_dir=self.records_dir
        )
        # 启动收集过程
        snyk_collector.start_collect()
        # 删除无恶意的npm包
        clean_package_folders(self.dataset_npm)

    def collect_osv(self):
        """收集 OSV 恶意包数据"""
        # 初始化 OSV 数据库收集器
        osv_collector = OSVDatabase(
            google_cloud_key=self.google_cloud_key,
            pypi_dataset_path=self.dataset_pypi,
            npm_dataset_path=self.dataset_npm,
            npm_mirrors=self.npm_mirrors,
            base_dir=os.path.dirname(self.records_dir),  # 使用 records_dir 的父目录作为基础目录
            records_dir=self.records_dir,
            repo_url=self.osv_repo_link
        )
        # 启动收集过程
        osv_collector.start_collect()
        # 删除无恶意的npm包
        clean_package_folders(self.dataset_npm)


if __name__ == '__main__':
    collect_main = CollectMain()
    collect_main.collect_snyk()
    collect_main.collect_osv()