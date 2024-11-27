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
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from pypi_bigquery import query_bigquery, download_packages
from npm_collect import npm_pkg_links
from file_operation import create_package_info, save_package_info


class SnykDatabase:
    def __init__(self, google_cloud_key, pypi_dataset_path, npm_dataset_path, npm_mirrors, chromedriver, snyk_baseurl, snyk_vulurl, records_dir):
        self.google_cloud_key = google_cloud_key
        self.pypi_dataset_path = pypi_dataset_path
        self.npm_dataset_path = npm_dataset_path
        self.npm_mirrors = npm_mirrors
        self.chromedriver = chromedriver
        self.snyk_baseurl = snyk_baseurl
        self.snyk_vulurl = snyk_vulurl
        self.records_dir = records_dir
        self.google_cloud_key = google_cloud_key
        self.pypi_dataset_path = pypi_dataset_path
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=service, options=options)
        self.infodriver = webdriver.Chrome(service=service, options=options)
        # 预加载已采集的包
        self.collected_packages = self._load_collected_packages()

    def _load_collected_packages(self):
        """
        加载已经采集的包名集合
        同时加载 osv 和 snyk 的记录，合并为一个集合
        """
        collected_packages = {'npm': set(), 'pip': set()}

        # 读取 npm 的记录（合并 osv 和 snyk）
        for source in ['osv', 'snyk']:
            npm_file = os.path.join(self.records_dir, f"{source}_npm_packages.json")
            if os.path.exists(npm_file):
                try:
                    with open(npm_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, dict) and "packages" in data:
                            # 使用 update 合并集合
                            collected_packages['npm'].update(set(data["packages"].keys()))
                except Exception as e:
                    print(f"读取 {source} npm 记录文件失败: {str(e)}")

        # 读取 pip 的记录（合并 osv 和 snyk）
        for source in ['osv', 'snyk']:
            pip_file = os.path.join(self.records_dir, f"{source}_pip_packages.json")
            if os.path.exists(pip_file):
                try:
                    with open(pip_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, dict) and "packages" in data:
                            # 使用 update 合并集合
                            collected_packages['pip'].update(set(data["packages"].keys()))
                except Exception as e:
                    print(f"读取 {source} pip 记录文件失败: {str(e)}")

        return collected_packages


    def collect_snyk(self, package_manager):
        for snyk_index in range(1, 30):
            print(f"正在采集第 {snyk_index} 页数据")
            snyk_pkgs = self.parse_snyk_database(package_manager, str(snyk_index))
            # 如果返回 None，说明发现了已采集的包，停止采集
            if snyk_pkgs is None:
                print(f"已采集完所有新包，停止 {package_manager} 的采集")
                break

            for snyk_pkg in snyk_pkgs:
                if snyk_pkg[1] in self.collected_packages[package_manager]:
                    print(f"已经采集过该包：{snyk_pkg[1]}")
                    continue
                if package_manager == "pip":
                    query_result = query_bigquery(self.google_cloud_key, [snyk_pkg[1]])
                    if query_result:
                        download_packages(self.pypi_dataset_path, query_result)
                elif package_manager == "npm":
                    npm_pkg_links(self.npm_mirrors, snyk_pkg[1], self.npm_dataset_path)
                # 无论下载是否成功，都获取包的详细信息
                try:
                    self.snyk_pkginfo(package_manager, snyk_pkg[0], snyk_pkg[1], snyk_pkg[2])
                except Exception as e:
                    print(f"获取 {snyk_pkg[1]} 信息失败: {str(e)}")
                    # 创建基本信息
                    pkg_info = create_package_info(
                        package_name=snyk_pkg[1],
                        affected_version=snyk_pkg[2],  # 版本信息我们还是有的
                        data_source_link=snyk_pkg[0],  # URL信息也有
                        update_date="",
                        package_type="",
                        cve="",
                        cwe="",
                        fix_method="",
                        overview="",
                        reference_links=[],
                    )
                    # 保存基本信息
                    save_package_info(self.records_dir, "snyk", package_manager, pkg_info)


    def parse_snyk_database(self, package_manager, page_index):
        snyk_pkgs = []
        print(os.path.join(self.snyk_vulurl, package_manager, page_index))
        self.driver.get(os.path.join(self.snyk_vulurl, package_manager, page_index))
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

                    # 判断是否已采集
                    if pkgname in self.collected_packages[package_manager]:
                        print(f"发现已采集的包：{pkgname}，停止采集")
                        return None  # 返回 None 表示需要停止采集

                    snyk_pkgs.append([td_href, pkgname, pkgversion])
        return snyk_pkgs


    def snyk_pkginfo(self, package_manager, pkg_info_url, pkgname, pkgversion):
        print(package_manager, pkg_info_url, pkgname, pkgversion)
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
        try:
            relink_block = left_div.find_elements(By.CSS_SELECTOR, ".vue--heading.heading")[2]
            li_tags = relink_block.find_elements(By.TAG_NAME, "li")
            ref_links = []
            for li_tag in li_tags:
                ref_links.append(li_tag.find_element(By.TAG_NAME, "a").get_attribute("href"))
        except:
            ref_links = []
        # CVSS
        # cvss_block = left_div.find_element(By.CLASS_NAME, "vue--block-expandable__content")
        # vendorcvss__container = cvss_block.find_element(By.CLASS_NAME, "vendorcvss__container")
        # vendorcvss__list_item = vendorcvss__container.find_elements(By.CLASS_NAME, "vendorcvss__list_item")
        # cvss_info = {}
        # for cvss_item in vendorcvss__list_item:
        #     cvss_item_name = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__label_tooltip").text
        #     cvss_item_value = cvss_item.find_element(By.CLASS_NAME, "cvss-details-item__value").text
        #     cvss_info[cvss_item_name] = cvss_item_value
        #  格式化数据，对应起来
        pkg_info = create_package_info(
            package_name=pkgname,
            affected_version=pkgversion,
            data_source_link=pkg_info_url,
            update_date=update_date,
            package_type=pkg_type,
            cve=cve_number,
            cwe=cwe_number,
            fix_method=fix_method,
            overview=overview,
            reference_links=ref_links
        )
        save_package_info(self.records_dir, "snyk", package_manager, pkg_info)



    def start_collect(self):
        for ecosystem in ['npm', 'pip']:
            self.collect_snyk(ecosystem)
        self.driver.quit()
        self.infodriver.quit()