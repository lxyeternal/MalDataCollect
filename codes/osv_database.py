# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : osv_collect.py
# @Project  : MalDataCollect
# Time      : 27/3/24 12:04 am
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import sys
import time
from selenium import webdriver
from info_format import format_infodata
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from file_operation import write_stop_file, write_snyk_pkginfo


class OSVDatabase:
    def __init__(self, chromedriver, osv_baseurl, pkg_manager):
        self.osv_baseurl = osv_baseurl
        self.pkg_manager = pkg_manager
        self.chromedriver = chromedriver
        # 加载启动项，这里设置headless，表示不启动浏览器，只开一个监听接口获取返回值
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        # options.add_argument('--headless')
        # options.add_argument('--no-sandbox')
        # options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(service=service, options=options)


    def parse_osv_database(self, page_index):
        self.driver.get(self.osv_baseurl.format(self.pkg_manager))
        self.driver.implicitly_wait(3)
        # TODO: click 10 times
        for i in range(page_index):
            try:
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                wait = WebDriverWait(self.driver, 10)  # 等待时间10秒，根据实际情况调整
                more_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, ".next-page-button.link-button")))
                more_button.click()
                wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, ".next-page-button.link-button")))
            except Exception as e:
                print(f"在点击下一页时出现问题：{e}")
                break
        vuln_table_rows = self.driver.find_elements(By.CLASS_NAME, "vuln-table-rows mdc-data-table__content")



if __name__ == '__main__':
    osv_baseurl = "https://osv.dev/list?ecosystem={}"
    chromedriver = "/Users/blue/Documents/GitHub/MalDataCollect/utils/chromedriver/macarm/chromedriver"
    pkg_manager = "PyPI"
    osvdatabase = OSVDatabase(chromedriver, osv_baseurl, pkg_manager)
    osvdatabase.parse_osv_database(10)