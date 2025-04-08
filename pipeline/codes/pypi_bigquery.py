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
import requests
from google.cloud import bigquery
from urllib.parse import urlparse


def query_bigquery(google_cloud_key, names):
    # 设置凭证文件路径（使用你的服务账户 JSON 凭证文件）
    client = bigquery.Client.from_service_account_json(google_cloud_key)
    # 构建查询字符串
    # 构建查询条件
    if len(names) == 1:
        names_condition = f'name = "{names[0]}"'
    else:
        names_condition = ' OR '.join([f'name = "{name}"' for name in names])
    query = f"""
    SELECT name, version, description, author, author_email,  uploaded_via, upload_time, size, python_version, packagetype, path
    FROM `bigquery-public-data.pypi.distribution_metadata` 
    WHERE {names_condition}
    """
    # 执行查询
    query_job = client.query(query)
    # 获取查询结果
    results = query_job.result()
    # 解析结果并进行聚合
    aggregated_results = {}
    for row in results:
        package_name = row.name.lower()
        version = row.version
        # 如果包名不存在，初始化基本信息
        if package_name not in aggregated_results:
            aggregated_results[package_name] = {
                'description': row.description,
                'author': row.author,
                'author_email': row.author_email,
                'versions': {}
            }
        # 如果版本不存在，初始化该版本的信息
        if version not in aggregated_results[package_name]['versions']:
            aggregated_results[package_name]['versions'][version] = {
                'uploaded_via': set(),
                'upload_time': set(),
                'size': set(),
                'python_version': set(),
                'packagetype': set(),
                'path': set()  # 新增 path 字段
            }
        # 添加版本特定的信息
        if row.uploaded_via is not None:
            aggregated_results[package_name]['versions'][version]['uploaded_via'].add(row.uploaded_via)
        if row.upload_time is not None:
            # 将日期转换为指定格式的字符串
            date_str = row.upload_time.date().strftime('%Y-%m-%d')
            aggregated_results[package_name]['versions'][version]['upload_time'].add(date_str)
        if row.size is not None:
            aggregated_results[package_name]['versions'][version]['size'].add(row.size)
        if row.python_version is not None:
            aggregated_results[package_name]['versions'][version]['python_version'].add(row.python_version)
        if row.packagetype is not None:
            aggregated_results[package_name]['versions'][version]['packagetype'].add(row.packagetype)
        if row.path is not None:  # 新增处理 path 字段
            aggregated_results[package_name]['versions'][version]['path'].add(row.path)
    return aggregated_results

def get_priority(file_path):
    """
    根据文件类型返回优先级，数字越小优先级越高
    """
    if file_path.endswith('.zip'):
        return 0
    elif file_path.endswith('.tar.gz'):
        return 1
    elif file_path.endswith('.whl'):
        return 2
    return 3


def download_packages(pypi_dataset_path, query_results, versions):
    for package_name, package_info in query_results.items():
        # 遍历每个版本
        for version, version_info in package_info['versions'].items():
            # 检查是否需要下载该版本
            if "0" in versions or version in versions:
                paths = version_info.get('path', set())
                if not paths:
                    print(f"No files found for {package_name} version {version}")
                    continue
                # 将路径列表按优先级排序
                sorted_paths = sorted(paths, key=get_priority)
                # 只取优先级最高的文件
                selected_path = sorted_paths[0]
                full_link = f"https://files.pythonhosted.org/packages/{selected_path}"
                # 创建保存路径
                save_dir = os.path.join(pypi_dataset_path, package_name, version)
                os.makedirs(save_dir, exist_ok=True)
                # 获取文件名
                file_name = os.path.basename(urlparse(full_link).path)
                # 下载文件
                try:
                    response = requests.get(full_link)
                    if response.status_code == 200:
                        save_path = os.path.join(save_dir, file_name)
                        with open(save_path, 'wb') as f:
                            f.write(response.content)
                        print(f"Successfully downloaded: {save_path}")
                    else:
                        print(f"Failed to download {full_link} - Status code: {response.status_code}")
                except Exception as e:
                    print(f"Error downloading {full_link}: {str(e)}")



# if __name__ == '__main__':
#     google_cloud_key = '/Users/blue/Documents/Github/MalDataCollect/pipeline/configs/cryptic-gate-453708-g4-65479bc3c72d.json'
#     names = ['faq', 'a-function', 'an-instance']
#     pypi_dataset_path = 'pypi_dataset'
#     query_results = query_bigquery(google_cloud_key, names)
#     print(query_results)
#     download_packages(pypi_dataset_path, query_results)