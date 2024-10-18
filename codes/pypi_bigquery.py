# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : pypi_bigquery.py
# @Project  : MalDataCollect
# Time      : 12/8/24 10:39 am
# Author    : honywen
# version   : python 3.8
# Description：
"""

import os
import json
import requests
from google.cloud import bigquery
from urllib.parse import urlparse


def query_bigquery(names):
    # 设置凭证文件路径（使用你的服务账户 JSON 凭证文件）
    client = bigquery.Client.from_service_account_json('../configs/taicen-36403b880a33.json')
    # 构建查询字符串
    names_condition = ' OR '.join([f'name = "{name}"' for name in names])
    query = f"""
    SELECT name, version, path 
    FROM `bigquery-public-data.pypi.distribution_metadata` 
    WHERE {names_condition}
    """
    # 执行查询
    query_job = client.query(query)
    # 获取查询结果
    results = query_job.result()
    return results


def process_txt_and_query(txt_file_path):
    names = []
    # 读取TXT文件
    with open(txt_file_path, 'r') as file:
        for line in file:
            parts = line.strip().split('\t')
            if len(parts) > 1:
                names.append(parts[1])
    # 调用 BigQuery 查询
    results = query_bigquery(names)
    # 处理查询结果，按规则筛选路径
    packages = {}
    for row in results:
        name = row.name
        version = row.version
        path = row.path
        # 只保留一个路径，优先级为 .tar.gz > .zip > .whl
        if (name, version) not in packages:
            packages[(name, version)] = path
        else:
            current_path = packages[(name, version)]
            if (path.endswith('.tar.gz') or path.endswith('.zip')) and not (current_path.endswith('.tar.gz') or current_path.endswith('.zip')):
                packages[(name, version)] = path

    # 调用下载函数
    download_packages(packages)


def download_packages(packages):
    for (name, version), link in packages.items():
        full_link = f"https://files.pythonhosted.org/packages/{link}"

        # 创建保存路径
        save_dir = f"/Users/blue/Downloads/data/{name}/{version}"
        os.makedirs(save_dir, exist_ok=True)

        # 获取文件名
        file_name = os.path.basename(urlparse(full_link).path)

        # 下载文件
        response = requests.get(full_link)
        if response.status_code == 200:
            save_path = os.path.join(save_dir, file_name)
            with open(save_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded: {save_path}")
        else:
            print(f"Failed to download: {full_link}")


if __name__ == "__main__":
    txt_file_path = "/Users/blue/Documents/GitHub/MalDataCollect/records/osv_pypi_dataset.txt"  # 请替换为你的 TXT 文件路径
    process_txt_and_query(txt_file_path)
