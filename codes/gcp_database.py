# !/usr/bin/env python
# -*- coding:utf-8 -*-
"""
# @File     : gcp_database
# @Project  : MalDataCollect
# Time      : 12/7/24 15:57
# Author    : blue
# version   : python 
# Description：
"""

from google.cloud import storage
from google.oauth2 import service_account
import os

# 设置认证文件路径
key_path = '../configs/metatrust-01-a8043294c5af.json'

# 使用服务账户密钥进行认证
credentials = service_account.Credentials.from_service_account_file(key_path)

# 创建存储客户端
client = storage.Client(credentials=credentials, project='scantist-malicious')  # 替换为你的实际项目ID

# 设置存储桶名称
bucket_name = 'scantist-malicious'

# 获取存储桶对象
bucket = client.get_bucket(bucket_name)

# 定义文件和文件夹
json_files = ['osv_npm_packages.json', 'osv_pip_packages.json', 'snyk_npm_packages.json', 'snyk_pip_packages.json']
folders = ['pip', 'npm']


# 下载 JSON 文件
def download_json_files():
    for json_file in json_files:
        blob = bucket.blob(json_file)
        destination_path = os.path.join('local_files', json_file)

        # 确保目标文件夹存在
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)

        # 下载 JSON 文件
        blob.download_to_filename(destination_path)
        print(f"Downloaded {json_file} to {destination_path}")


# 下载压缩包文件
def download_compressed_files(folder_name):
    blobs = bucket.list_blobs(prefix=folder_name)

    for blob in blobs:
        # 跳过文件夹本身
        if blob.name.endswith('/'):
            continue

        # 设置目标文件路径
        destination_path = os.path.join('local_files', folder_name, blob.name)

        # 确保目标文件夹存在
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)

        # 下载文件
        blob.download_to_filename(destination_path)
        print(f"Downloaded {blob.name} to {destination_path}")


# 下载所有数据
def download_all_data():
    # 下载 JSON 文件
    download_json_files()

    # 下载 pip 和 npm 文件夹下的压缩包
    for folder in folders:
        download_compressed_files(folder)


if __name__ == "__main__":
    download_all_data()



