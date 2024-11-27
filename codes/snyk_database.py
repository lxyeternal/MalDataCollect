# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : parse_snyk_database.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:45
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import sys
from selenium import webdriver
from info_format import format_infodata
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from file_operation import write_stop_file, write_snyk_pkginfo


class SnykDatabase:
    def __init__(self, record_file, chromedriver, snyk_baseurl, synk_vulurl, stop_file, stop_packages):
        self.record_file = record_file
        self.chromedriver = chromedriver
        self.snyk_baseurl = snyk_baseurl
        self.synk_vulurl = synk_vulurl
        self.stop_file = stop_file
        self.stop_packages = stop_packages
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


    def parse_snyk_database(self, manager, page_index):
        snyk_pkgs = []
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
                        write_stop_file(self.stop_file, self.stop_packages)
                    if pkgname == self.stop_pkgname:
                        sys.exit()
                    snyk_pkgs.append([td_href, pkgname, pkgversion])
        return snyk_pkgs


    def snyk_pkginfo(self, manager, pkg_info_url, pkgname, pkgversion):
        pkg_complete_url = pkg_info_url
        self.infodriver.get(pkg_complete_url)
        self.driver.implicitly_wait(10)
        vuln_page_body_wrapper = self.infodriver.find_element(By.CLASS_NAME, "vuln-page__body-wrapper")
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
        relink_block = left_div.find_elements(By.CSS_SELECTOR, ".vue--heading.heading")[2]
        li_tags = relink_block.find_elements(By.TAG_NAME, "li")
        ref_links = []
        for li_tag in li_tags:
            ref_links.append(li_tag.find_element(By.TAG_NAME, "a").get_attribute("href"))
        # CVSS
        cvss_block = left_div.find_element(By.CLASS_NAME, "vue--block-expandable__content")
        vendorcvss__container = cvss_block.find_element(By.CLASS_NAME, "vendorcvss__container")
        vendorcvss__list_item = vendorcvss__container.find_elements(By.CLASS_NAME, "vendorcvss__list_item")
        cvss_info = {}
        for cvss_item in vendorcvss__list_item:
            cvss_item_name = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__label_tooltip").text
            cvss_item_value = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__value").text
            cvss_info[cvss_item_name] = cvss_item_value
        #  格式化数据，对应起来
        format_info_list = [manager, pkgname, pkg_complete_url, "00", pkgversion, manager, cve_number, cwe_number, fix_method, overview, update_date, pkg_type]
        write_snyk_pkginfo(self.record_file, format_info_list)