# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : collect_main.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 02:07
# Author    : honywen
# version   : python 3.8
# Description：
"""


import json
import os

from file_operation import read_stop_file
from codes.snyk_database import SnykDatabase
from codes.pypi_collect import pypi_pkg_links
from codes.npm_collect import npm_pkg_links


class CollectMain:
    def __init__(self, manager):
        self.manager = manager
        self.config_path = "../configs/config.json"
        with open(self.config_path, "r") as fr:
            self.config = json.load(fr)
        self.npm_mirrors = self.config["npm_mirrors"]
        self.go_mirrors = self.config["go_mirrors"]
        self.maven_mirrors = self.config["maven_mirrors"]
        self.pypi_mirrors = self.config["pypi_mirrors"]
        self.record_file = self.config["record_file"]
        self.chromedriver = self.config["chromedriver"]
        self.dataset_pypi = self.config["dataset_pypi"]
        self.dataset_npm = self.config["dataset_npm"]
        self.dataset_go = self.config["dataset_go"]
        self.dataset_maven = self.config["dataset_maven"]
        self.dataset_nuget = self.config["dataset_nuget"]
        self.dataset_rubygems = self.config["dataset_rubygems"]
        self.snyk_baseurl = self.config["snyk_baseurl"]
        self.synk_vulurl = self.config["synk_vulurl"]
        self.stop_file = self.config["stop_file"]
        self.collected_pkgs = []
        self.stop_packages = read_stop_file(self.stop_file)
        self.snykdatabase = SnykDatabase(self.record_file, self.chromedriver, self.snyk_baseurl, self.synk_vulurl, self.stop_file, self.stop_packages)


    def find_collected_pkgs(self):
        if self.manager == "pip":
            self.collected_pkgs = os.listdir(self.dataset_pypi)
        elif self.manager == "npm":
            self.collected_pkgs = os.listdir(self.dataset_npm)
            self.collected_pkgs = [pkg.replace("##", "/") for pkg in self.collected_pkgs]
        elif self.manager == "golang":
            self.collected_pkgs = os.listdir(self.dataset_go)
        elif self.manager == "maven":
            self.collected_pkgs = os.listdir(self.dataset_maven)
        elif self.manager == "nuget":
            self.collected_pkgs = os.listdir(self.dataset_nuget)
        elif self.manager == "rubygems":
            self.collected_pkgs = os.listdir(self.dataset_rubygems)
        else:
            pass

    def start(self):
        self.find_collected_pkgs()
        for snyk_index in range(1, 5):
            print("正在采集第 {} 页数据".format(snyk_index))
            snyk_pkgs = self.snykdatabase.parse_snyk_database(self.manager, str(snyk_index))
            for snyk_pkg in snyk_pkgs:
                #  从镜像网站中下载恶意数据源代码
                if self.manager == "pip":
                    flag = pypi_pkg_links(self.pypi_mirrors, snyk_pkg[1], self.dataset_pypi)
                elif self.manager == "npm":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_npm)
                elif self.manager == "golang":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_go)
                elif self.manager == "maven":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_maven)
                elif self.manager == "nuget":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_nuget)
                elif self.manager == "rubygems":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_rubygems)
                else:
                    flag = 0
                    pass
                if flag:
                    self.snykdatabase.snyk_pkginfo(self.manager, snyk_pkg[0], snyk_pkg[1], snyk_pkg[2])


if __name__ == '__main__':
    collect_main = CollectMain("npm")
    collect_main.start()