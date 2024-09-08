# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : finopensec_database.py
# @Project  : MalDataCollect
# Time      : 8/9/24 4:13 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time


class FinopensecDatabase:
    def __init__(self, chromedriver, finopensec_baseurl, pkg_manager):
        self.finopensec_baseurl = finopensec_baseurl
        self.pkg_manager = pkg_manager
        self.chromedriver = chromedriver
        # 启动Chrome浏览器
        service = Service(executable_path=self.chromedriver)
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')  # 忽略SSL证书错误
        self.driver = webdriver.Chrome(service=service, options=options)
        self.malicious_pkg_info = []

    def parse_osv_database(self, page_index):
        # 访问指定网页
        self.driver.get(self.finopensec_baseurl)
        self.driver.implicitly_wait(3)
        # 提取 class == "body" 的元素
        body_element = self.driver.find_element(By.CLASS_NAME, "body")
        # 提取所有的 body-tr tr g-mb-8 元素
        elements = body_element.find_elements(By.CSS_SELECTOR, ".body-tr.tr.g-mb-8")
        for elem in elements:
            try:
                # 提取每个元素中的所有 <span> 标签
                spans = elem.find_elements(By.TAG_NAME, 'span')
                if len(spans) >= 2:
                    # 判断是否包含 NPM 或 PyPI 关键词
                    package_info = spans[0].text
                    if 'NPM' in package_info:
                        platform = "NPM"
                    elif 'PyPI' in package_info:
                        platform = "PyPI"
                    else:
                        platform = "Unknown"
                    # 提取第二个 <span> 的内容 (例如 MPS-7km3-xwnr)
                    link_code = spans[1].text
                    print(f"Platform: {platform}, Code: {link_code}")
                    # 拼接链接并访问新页面
                    new_link = "https://www.finopensec.com/hd/" + link_code
                    self.driver.get(new_link)
                    self.driver.implicitly_wait(3)
                    try:
                        see_more_button = WebDriverWait(self.driver, 10).until(
                            EC.presence_of_element_located((By.CLASS_NAME, "el-icon"))
                        )
                        self.driver.execute_script("arguments[0].click();", see_more_button)  # 使用JavaScript点击
                    except Exception as e:
                        print(f"通过JavaScript点击查看更多按钮失败: {e}")
                    # 提取 class == "art-paragraph" 的内容
                    accordion_view = self.driver.find_element(By.CLASS_NAME, "accordion-view")
                    # 采集 class == "effect-summary-card" 的内容
                    effect_cards = accordion_view.find_elements(By.CLASS_NAME, "effect-summary-card")
                    for card in effect_cards:
                        # 提取包名和受影响版本
                        package_name = card.find_element(By.CSS_SELECTOR, ".deac.g-mb-8").find_element(By.TAG_NAME, "span").text
                        # 提取包管理器类型
                        package_type = card.find_element(By.CSS_SELECTOR, "div.deac button span").text
                        affected_version = card.find_element(By.CSS_SELECTOR, ".g-flex.g-cross-center").find_element(By.CLASS_NAME, "result").text
                        # 仅处理 npm 的数据
                        if package_type == "npm":
                            # 打印结果
                            print(f"{package_type}\t{package_name}\t{[]}")
                    # 回到上一页
                    self.driver.back()
            except Exception as e:
                print(f"Error processing element: {e}")
    def close_driver(self):
        # 关闭浏览器
        self.driver.quit()

# 使用示例
if __name__ == "__main__":
    chromedriver_path = "/Users/blue/Documents/GitHub/MalDataCollect/utils/chromedriver/macarm/chromedriver"  # 替换为实际的chromedriver路径
    base_url = "http://www.finopensec.com/secinfo/malicious"  # 替换为实际的URL模板
    pkg_manager = "NPM"

    osv = FinopensecDatabase(chromedriver_path, base_url, pkg_manager)
    osv.parse_osv_database(1)  # 传递页面索引
    osv.close_driver()