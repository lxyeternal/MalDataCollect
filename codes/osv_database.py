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

import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


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
        self.malicious_pkg_info = []

    def parse_osv_database(self, page_index):
        self.driver.get(self.osv_baseurl.format(self.pkg_manager))
        self.driver.implicitly_wait(3)
        # TODO: click 10 times
        for i in range(page_index):
            try:
                wait = WebDriverWait(self.driver, 10)
                # Wait for the "next page" button to be clickable
                more_button_selector = ".next-page-button.link-button"
                more_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, more_button_selector)))
                # Scroll the button into view and click
                self.driver.execute_script("arguments[0].scrollIntoView();", more_button)
                self.driver.execute_script("arguments[0].click();", more_button)
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                # Wait for the page to load
                time.sleep(3)
            except Exception as e:
                print(f"Error clicking next page: {e}")
                break
        vuln_table_contents = self.driver.find_element(By.CSS_SELECTOR, ".vuln-table-rows.mdc-data-table__content")
        vuln_table_rows = vuln_table_contents.find_elements(By.CSS_SELECTOR, ".vuln-table-row.mdc-data-table__row")
        for vuln_table_row in vuln_table_rows:
            vuln_id_link = vuln_table_row.find_element(By.CSS_SELECTOR, ".vuln-table-cell.mdc-data-table__cell").find_element(By.CSS_SELECTOR, "a").get_attribute("href")
            vuln_package_manager = vuln_table_row.find_element(By.CSS_SELECTOR, ".vuln-table-cell.vuln-packages").text
            # vuln_manager = vuln_package_manager.split("/")[0]
            # vuln_package_name = "".join(vuln_package_manager.split("/")[1:])
            vuln_version_row = vuln_table_row.find_element(By.CSS_SELECTOR,".vuln-table-cell.vuln-versions")
            vuln_versions = vuln_version_row.find_elements(By.CLASS_NAME, "version")
            malicious_versions = list()
            for vuln_version in vuln_versions:
                malicious_versions.append(vuln_version.text)
            vuln_data = vuln_table_row.find_element(By.TAG_NAME, "relative-time").text
            malicious_info = vuln_table_row.find_element(By.CSS_SELECTOR, ".vuln-table-cell.vuln-summary").text.strip()
            if "Malicious code in" in malicious_info:
                malicious_package_name = malicious_info.replace("Malicious code in", "").replace("(npm)", "").strip()
                malicious_manager = "NPM"
                print(f"NPM\t{malicious_package_name}\t{malicious_versions}")
                self.malicious_pkg_info.append([vuln_id_link, malicious_package_name, malicious_manager, malicious_versions, vuln_data])



if __name__ == '__main__':
    osv_baseurl = "https://osv.dev/list?ecosystem={}"
    chromedriver = "/Users/blue/Documents/GitHub/MalDataCollect/utils/chromedriver/macarm/chromedriver"
    pkg_manager = "npm"
    osvdatabase = OSVDatabase(chromedriver, osv_baseurl, pkg_manager)
    osvdatabase.parse_osv_database(30)