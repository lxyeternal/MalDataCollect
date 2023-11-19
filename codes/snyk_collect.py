# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : snyk_collect.py
# @Project  : MalDataCollect
# Time      : 2023/11/19 17:38
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import sys
import csv
import json
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service

class SnykCollect:
    def __init__(self, manager):
        self.manager = manager
        self.config_path = "../configs/config.json"
        with open(self.config_path, "r") as fr:
            self.config = json.load(fr)
        self.npm_mirrors = self.config["npm_mirrors"]
        self.go_mirrors = self.config["go_mirrors"]
        self.maven_mirrors = self.config["maven_mirrors"]
        self.pypi_mirrors = self.config["pypi_mirrors"]
        self.dataset_pypi = self.config["dataset_pypi"]
        self.record_file = self.config["record_file"]
        self.chromedriver = self.config["chromedriver"]
        self.dataset_pypi = self.config["dataset_pypi"]
        self.snyk_baseurl = self.config["snyk_baseurl"]
        self.synk_vulurl = self.config["synk_vulurl"]
        self.stop_file = self.config["stop_file"]
        self.stop_packages = {}
        self.stop_pkgname = ""
        self.extension_tar = ".tar.gz"
        self.extension_zip = ".zip"
        self.extension_whl = ".whl"
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        # options.add_argument('--headless')
        # options.add_argument('--no-sandbox')
        # options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(service=service, options=options)
        self.infodriver = webdriver.Chrome(service=service, options=options)
        self.item_name_list = ['Exploit Maturity', 'Attack Complexity','Confidentiality','Integrity','Availability','Attack Vector','Privileges Required','User Interaction','Scope', 'Snyk ID', 'Published', 'Disclosed', 'Credit']


    def read_stop_file(self):
        # 打开文件并逐行读取
        with open(self.stop_file, "r") as file:
            for line in file:
                # 分割每一行为两部分
                key, value = line.strip().split('\t')
                # 将分割后的键值对添加到字典中
                self.stop_packages[key] = value
        self.stop_pkgname = self.stop_packages[self.manager]

    def write_stop_file(self):
        # 打开文件并逐行读取
        with open(self.stop_file, "w") as file:
            # 遍历字典中的每个键值对
            for key, value in self.stop_packages.items():
                # 将键和值以制表符分隔的形式写入一行
                file.write(f"{key}\t{value}\n")

    def write_snyk_pkginfo(self, snyk_pkginfo):
        folder = os.path.exists(self.record_file)
        with open(self.record_file, 'a+') as f:
            #  文件不存在，写表头
            if not folder:
                csv_header = ['manager', 'package_name','snyk_link','security_score','affected_version','install_type','cve', 'cwe',' fix_method', 'overview', 'update_date', 'package_type', 'axploit_maturity', 'attack_complexity','confidentiality','integrity','availability','attack_vector','privileges_required','user_interaction','scope','snyk_id','published','disclosed','credit','source']
                csv_write = csv.writer(f)
                csv_write.writerow(csv_header)
            csv_write = csv.writer(f)
            csv_write.writerow(snyk_pkginfo)


    def mkdir(self, pkgname, version) -> None:
        dirpath = os.path.join(self.dataset_pypi, pkgname, version)
        folder = os.path.exists(dirpath)
        if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
            os.makedirs(dirpath)  # makedirs 创建文件时如果路径不存在会创建这个路径
        else:
            pass


    def format_infodata(self, pkg_info_dict) -> list:
        format_info_list = list()
        for info in self.item_name_list:
            try:
                format_info_list.append(pkg_info_dict[info])
            except:
                format_info_list.append('')
        return format_info_list

    def mirror_pkg_links(self, pkgname) -> str:
        flag = 0
        versions = set()
        for mirror, url in self.pypi_mirrors.items():
            pkgurl = os.path.join(url, "simple", pkgname)
            rq = requests.get(pkgurl)
            if rq.status_code == 200:
                #  为包创建文件夹
                soup = BeautifulSoup(rq.content, 'html.parser')         # 文档对象
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
                    if link_filename.endswith(self.extension_whl) or link_filename.endswith(self.extension_tar) or link_filename.endswith(self.extension_zip):
                        try:
                            version = link_filename.replace(pkgname + '-', "").replace(self.extension_tar, "").replace(self.extension_zip, "").replace(self.extension_whl, "").replace("-py3-none-any","").replace('/', '-')
                            if version in versions:
                                continue
                        except:
                            version = 'aaa.bbb.ccc'
                        source_code_filename = os.path.join(self.dataset_pypi, pkgname, version, link_filename)
                        file_response = requests.get(download_link)
                        if file_response.status_code == 200:
                            print(mirror)
                            self.mkdir(pkgname, version)
                            with open(source_code_filename, "ab") as f:
                                f.write(file_response.content)
                                f.flush()
                                versions.add(version)
                                flag = 1
            if flag == 1:
                break
        return flag


    def parse_snyk_database(self, manager, page_index):
        print(os.path.join(self.synk_vulurl, manager, page_index))
        self.driver.get(os.path.join(self.synk_vulurl, manager, page_index))
        self.driver.implicitly_wait(10)
        vulns_table = self.driver.find_element(By.CLASS_NAME, "vulns-table")
        table_tbody = vulns_table.find_element(By.CLASS_NAME, "vue--table__tbody")
        vue_table_row = table_tbody.find_elements(By.TAG_NAME, "tr")
        for row_index, row in enumerate(vue_table_row):
            row_tds = row.find_elements(By.TAG_NAME, "td")
            for td_index, td in enumerate(row_tds):
                if td_index == 0:
                    td_type = td.text.split("\n")[1].strip()
                    td_href = td.find_element(By.TAG_NAME, "a").get_attribute('href')
                    if td_type != 'Malicious Package':
                        break
                if td_index == 1:
                    pkgname = td.text.split(" ")[0].strip()
                    pkgversion = td.text.replace(pkgname, "").strip()
                    if td_index == 1 and row_index == 1:
                        self.stop_packages[manager] = pkgname
                        self.write_stop_file()
                    if pkgname == self.stop_pkgname:
                        sys.exit()
                    #  下载包文件
                    flag = self.mirror_pkg_links(pkgname)
                    if flag:
                        self.snyk_pkginfo(td_href, pkgname, pkgversion)

    def snyk_pkginfo(self, pkg_info_url, pkgname, pkgversion):
        pkg_complete_url = pkg_info_url
        self.infodriver.get(pkg_complete_url)
        self.driver.implicitly_wait(10)
        vuln_page_body_wrapper = self.infodriver.find_element(By.CLASS_NAME, "vuln-page__body-wrapper")
        pkg_score = vuln_page_body_wrapper.find_element(By.CLASS_NAME, "severity-widget__score").get_attribute("data-snyk-test-score")
        right_div = vuln_page_body_wrapper.find_elements(By.CLASS_NAME, "vue--card__body")
        #  点击按钮，查看更多
        right_div[0].find_element(By.CLASS_NAME, "see-all").click()
        self.driver.implicitly_wait(2)
        pkg_info_dict = dict()
        for box in right_div:
            div_uls = box.find_elements(By.TAG_NAME, "ul")
            for div_ul in div_uls:
                ul_lis = div_ul.find_elements(By.TAG_NAME, "li")
                details_items = div_ul.find_elements(By.CLASS_NAME, "cvss-details-item")
                for ul_li in ul_lis:
                    item_name = ul_li.find_element(By.TAG_NAME, "span").text
                    item_level = ul_li.find_element(By.TAG_NAME, "strong").text
                    pkg_info_dict[item_name] = item_level
                for details_item in details_items:
                    span_item = details_item.find_elements(By.TAG_NAME, "span")
                    item_name = span_item[0].text
                    item_level = span_item[1].text
                    pkg_info_dict[item_name] = item_level
        print(pkg_info_dict)
        #  update code to adapt the website new UI elements
        left_div = vuln_page_body_wrapper.find_element(By.CLASS_NAME, "left")
        vuln_info_block = left_div.find_element(By.CLASS_NAME, "vuln-info-block")
        update_date = vuln_info_block.find_element(By.XPATH, "h4[@data-snyk-test='formatted-date']").text
        pkg_type = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='malicious-badge']").text
        cve_number = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='no-cve']").text
        cwe_number = vuln_info_block.find_element(By.XPATH, "span[@data-snyk-test='cwe']").text.replace(
            "OPEN THIS LINK IN A NEW TAB", "").strip()
        vuln_fix_content = left_div.find_elements(By.CLASS_NAME, "markdown-section")
        fix_method = vuln_fix_content[0].find_element(By.CLASS_NAME, "vue--prose").text
        overview = vuln_fix_content[1].find_element(By.CLASS_NAME, "vue--prose").text
        #  格式化数据，对应起来
        format_info_list = self.format_infodata(pkg_info_dict)
        format_info_list = [self.manager, pkgname, pkg_complete_url, pkg_score, pkgversion, 'pip', cve_number, cwe_number, fix_method, overview, update_date, pkg_type] + format_info_list
        self.write_snyk_pkginfo(format_info_list)

    def start(self):
        self.read_stop_file()
        for snyk_index in range(1, 30):
            print("正在采集第 {} 页数据".format(snyk_index))
            self.parse_snyk_database(self.manager, str(snyk_index))



if __name__ == '__main__':
    snykcollect = SnykCollect("pip")
    snykcollect.start()