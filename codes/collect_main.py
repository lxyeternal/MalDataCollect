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


import os
import json
from codes.osv_database import OSVDatabase
from file_operation import read_stop_file
from codes.snyk_database import SnykDatabase
from codes.pypi_collect import pypi_pkg_links
from codes.npm_collect import npm_pkg_links
from codes.nuget_collect import nuget_pkg_links
from file_operation import write_snyk_pkginfo



class CollectMain:
    def __init__(self, manager):
        self.manager = manager
        self.config_path = "../configs/config.json"
        with open(self.config_path, "r") as fr:
            self.config = json.load(fr)
        self.osv_baseurl = self.config["osv_baseurl"]
        self.nuget_mirrors = self.config["nuget_mirrors"]
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
        self.pip_manual_file = self.config["pip_manual_file"]
        self.npm_manual_file = self.config["npm_manual_file"]
        self.rubygems_manual_file = self.config["rubygems_manual_file"]
        self.manual_packages = []
        self.collected_pkgs = []
        self.stop_packages = read_stop_file(self.stop_file)
        self.snykdatabase = SnykDatabase(self.record_file, self.chromedriver, self.snyk_baseurl, self.synk_vulurl, self.stop_file, self.stop_packages)


    def find_collected_pkgs(self):
        if self.manager == "pip":
            self.collected_pkgs = os.listdir("/Users/blue/Documents/GitHub/pypi_malregistry")
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


    def collect_manual(self):
        self.find_collected_pkgs()
        with open(self.pip_manual_file, "r") as fr:
            for line in fr:
                pkg = line.strip().split("\t")
                pkg_manager = pkg[0]
                pkg_name = pkg[0]
                try:
                    pkg_version = pkg[1]
                except:
                    pkg_version = None
                print(self.manager, pkg_name, pkg_version)
                if pkg_name in self.collected_pkgs:
                    print("已经采集过该包：{}".format(pkg_name))
                    continue
                if self.manager == "pip":
                    flag = pypi_pkg_links(self.pypi_mirrors, pkg_name, self.dataset_pypi, pkg_version)
                elif self.manager == "npm":
                    try:
                        flag = npm_pkg_links(self.npm_mirrors, pkg_name, self.dataset_npm)
                    except:
                        flag = 0
                elif self.manager == "nuget":
                    flag = nuget_pkg_links(self.nuget_mirrors, pkg_name, self.dataset_nuget)
                elif self.manager == "golang":
                    flag = npm_pkg_links(self.go_mirrors, pkg_name, self.dataset_go)
                elif self.manager == "maven":
                    flag = npm_pkg_links(self.maven_mirrors, pkg_name, self.dataset_maven)
                elif self.manager == "rubygems":
                    flag = npm_pkg_links(self.npm_mirrors, pkg_name, self.dataset_rubygems)
                else:
                    flag = 0
                    pass
                if flag:
                    format_info_list = [self.manager, pkg_name, "", "", pkg_version, "osv"]
                    write_snyk_pkginfo(self.record_file, format_info_list)
                else:
                    format_info_list = [self.manager, pkg_name, "", "", pkg_version, "No source code"]
                    write_snyk_pkginfo(self.record_file, format_info_list)


    def collect_snyk(self):
        self.find_collected_pkgs()
        for snyk_index in range(1, 30):
            print("正在采集第 {} 页数据".format(snyk_index))
            snyk_pkgs = self.snykdatabase.parse_snyk_database(self.manager, str(snyk_index))
            for snyk_pkg in snyk_pkgs:
                if snyk_pkg[1] in self.collected_pkgs:
                    print("已经采集过该包：{}".format(snyk_pkg[1]))
                    continue
                #  从镜像网站中下载恶意数据源代码
                if self.manager == "pip":
                    flag = pypi_pkg_links(self.pypi_mirrors, snyk_pkg[1], self.dataset_pypi)
                elif self.manager == "npm":
                    try:
                        flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_npm)
                    except:
                        flag = 0
                elif self.manager == "nuget":
                    flag = nuget_pkg_links(self.nuget_mirrors, snyk_pkg[1], self.dataset_nuget)
                elif self.manager == "golang":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_go)
                elif self.manager == "maven":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_maven)
                elif self.manager == "rubygems":
                    flag = npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.dataset_rubygems)
                else:
                    flag = 0
                    pass
                if flag:
                    self.snykdatabase.snyk_pkginfo(self.manager, snyk_pkg[0], snyk_pkg[1], snyk_pkg[2])
                else:
                    format_info_list = [self.manager, snyk_pkg[1], snyk_pkg[0], "", snyk_pkg[2], "No source code"]
                    write_snyk_pkginfo(self.record_file, format_info_list)

    def collect_osv(self):
        self.find_collected_pkgs()
        osvdatabase = OSVDatabase(self.chromedriver, self.osv_baseurl, "PyPI")
        osvdatabase.parse_osv_database(100)
        for pkg_info in osvdatabase.malicious_pkg_info:
            package_name = pkg_info[1]
            package_version = pkg_info[3]
            if package_name in self.collected_pkgs:
                print("已经采集过该包：{}".format(package_name))
                continue
            if self.manager == "pip":
                flag = pypi_pkg_links(self.pypi_mirrors, package_name, self.dataset_pypi, package_version)
            else:
                flag = 0
            if flag:
                format_info_list = [self.manager, package_name, "", "", package_version, "osv"]
                write_snyk_pkginfo(self.record_file, format_info_list)
            else:
                format_info_list = [self.manager, package_name, "", "", package_version, "No source code"]
                write_snyk_pkginfo(self.record_file, format_info_list)



if __name__ == '__main__':
    collect_main = CollectMain("pip")
    collect_main.collect_manual()
    # collect_main.collect_snyk()
    # collect_main.collect_osv()