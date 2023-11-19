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
        format_info_list = format_infodata(pkg_info_dict)
        format_info_list = [manager, pkgname, pkg_complete_url, pkg_score, pkgversion, manager, cve_number, cwe_number, fix_method, overview, update_date, pkg_type] + format_info_list
        write_snyk_pkginfo(self.record_file, format_info_list)