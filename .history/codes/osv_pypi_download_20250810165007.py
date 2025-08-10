#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
OSV PyPI 恶意包下载器
从BigQuery导出的JSON文件中解析并下载恶意包
"""

import os
import json
import requests
from urllib.parse import urlparse
from collections import defaultdict
from multiprocessing import Pool, Manager, Lock
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_priority(file_path):
    """
    根据文件类型返回优先级，数字越小优先级越高
    tar.gz 优先级最高
    """
    if file_path.endswith('.tar.gz'):
        return 0
    elif file_path.endswith('.zip'):
        return 1
    elif file_path.endswith('.whl'):
        return 2
    return 3


def parse_json_file(json_file_path):
    """
    解析JSON文件，提取包信息并去重
    """
    print(f"正在解析JSON文件: {json_file_path}")
    
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 按包名和版本分组，去重处理
    packages = defaultdict(lambda: defaultdict(list))
    
    for item in data:
        package_name = item['name']
        version = item['version']
        path = item['path']
        
        packages[package_name][version].append({
            'path': path,
            'size': item.get('size', 0),
            'upload_time': item.get('upload_time', ''),
            'packagetype': item.get('packagetype', ''),
            'python_version': item.get('python_version', '')
        })
    
    # 去重处理：同一个包的同一个版本只保留优先级最高的文件
    deduplicated_packages = {}
    
    for package_name, versions in packages.items():
        deduplicated_packages[package_name] = {}
        
        for version, files in versions.items():
            # 按优先级排序，选择优先级最高的文件
            sorted_files = sorted(files, key=lambda x: get_priority(x['path']))
            selected_file = sorted_files[0]
            
            deduplicated_packages[package_name][version] = selected_file
            
            print(f"包 {package_name} 版本 {version}: 选择了 {os.path.basename(selected_file['path'])} "
                  f"(共有 {len(files)} 个候选文件)")
    
    return deduplicated_packages


def download_packages(packages_data, download_base_path):
    """
    下载恶意包到指定目录
    """
    print(f"\n开始下载包到目录: {download_base_path}")
    
    # 创建基础下载目录
    os.makedirs(download_base_path, exist_ok=True)
    
    total_packages = sum(len(versions) for versions in packages_data.values())
    downloaded_count = 0
    failed_count = 0
    
    print(f"总共需要下载 {total_packages} 个包文件\n")
    
    for package_name, versions in packages_data.items():
        for version, file_info in versions.items():
            file_path = file_info['path']
            full_url = f"https://files.pythonhosted.org/packages/{file_path}"
            
            # 创建保存目录：包名/版本/
            save_dir = os.path.join(download_base_path, package_name, version)
            os.makedirs(save_dir, exist_ok=True)
            
            # 获取文件名
            file_name = os.path.basename(urlparse(full_url).path)
            save_path = os.path.join(save_dir, file_name)
            
            # 检查文件是否已存在
            if os.path.exists(save_path):
                print(f"⏭️  文件已存在，跳过: {package_name}/{version}/{file_name}")
                downloaded_count += 1
                continue
            
            # 下载文件
            try:
                print(f"📥 下载中: {package_name}/{version}/{file_name}")
                response = requests.get(full_url, timeout=30)
                
                if response.status_code == 200:
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                    
                    file_size = len(response.content)
                    print(f"✅ 下载成功: {save_path} ({file_size} bytes)")
                    downloaded_count += 1
                else:
                    print(f"❌ 下载失败: {full_url} - HTTP {response.status_code}")
                    failed_count += 1
                    
            except Exception as e:
                print(f"❌ 下载异常: {full_url} - {str(e)}")
                failed_count += 1
    
    print(f"\n📊 下载统计:")
    print(f"   ✅ 成功: {downloaded_count}")
    print(f"   ❌ 失败: {failed_count}")
    print(f"   📦 总计: {total_packages}")


def print_summary(packages_data):
    """
    打印解析摘要
    """
    print("\n" + "="*60)
    print("📋 解析摘要")
    print("="*60)
    
    total_packages = len(packages_data)
    total_versions = sum(len(versions) for versions in packages_data.values())
    
    print(f"总包数量: {total_packages}")
    print(f"总版本数量: {total_versions}")
    
    # 统计文件类型分布
    file_types = defaultdict(int)
    for package_name, versions in packages_data.items():
        for version, file_info in versions.items():
            file_path = file_info['path']
            if file_path.endswith('.tar.gz'):
                file_types['tar.gz'] += 1
            elif file_path.endswith('.whl'):
                file_types['whl'] += 1
            elif file_path.endswith('.zip'):
                file_types['zip'] += 1
            else:
                file_types['other'] += 1
    
    print(f"\n文件类型分布:")
    for file_type, count in sorted(file_types.items()):
        print(f"  {file_type}: {count}")
    
    print("\n前10个包:")
    for i, (package_name, versions) in enumerate(list(packages_data.items())[:10], 1):
        version_count = len(versions)
        print(f"  {i:2d}. {package_name} ({version_count} 个版本)")
    
    print("="*60)


def main():
    """
    主函数
    """
    print("🚀 OSV PyPI 恶意包下载器")
    print("="*60)
    
    # 配置路径
    json_file_path = "/Users/blue/Documents/Github/MalDataCollect/bquxjob_68385913_198931a31a8.json"
    download_base_path = "/Users/blue/Downloads/new_malicious_packages"
    
    print(f"JSON文件路径: {json_file_path}")
    print(f"下载保存路径: {download_base_path}")
    
    # 检查JSON文件是否存在
    if not os.path.exists(json_file_path):
        print(f"❌ JSON文件不存在: {json_file_path}")
        return
    
    print(f"JSON文件存在: {os.path.exists(json_file_path)}")
    print(f"JSON文件大小: {os.path.getsize(json_file_path) / 1024 / 1024:.2f} MB")
    
    try:
        # 1. 解析JSON文件
        packages_data = parse_json_file(json_file_path)
        
        # 2. 打印摘要
        print_summary(packages_data)
        
        # 3. 下载包
        download_packages(packages_data, download_base_path)
        
        print(f"\n🎉 任务完成!")
        print(f"所有文件已下载到: {download_base_path}")
        
    except Exception as e:
        print(f"\n❌ 程序执行过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
