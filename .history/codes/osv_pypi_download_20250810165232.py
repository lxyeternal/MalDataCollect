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


def download_single_package(package_info):
    """
    下载单个包文件的工作函数
    """
    package_name, version, file_info, download_base_path, package_version_count = package_info
    
    file_path = file_info['path']
    full_url = f"https://files.pythonhosted.org/packages/{file_path}"
    
    # 根据包的版本数量决定保存到哪个文件夹
    if package_version_count == 1:
        version_type_dir = "single-version"
    else:
        version_type_dir = "multi-version"
    
    # 创建保存目录：版本类型/包名/版本/
    save_dir = os.path.join(download_base_path, version_type_dir, package_name, version)
    os.makedirs(save_dir, exist_ok=True)
    
    # 获取文件名
    file_name = os.path.basename(urlparse(full_url).path)
    save_path = os.path.join(save_dir, file_name)
    
    # 检查文件是否已存在
    if os.path.exists(save_path):
        return {
            'status': 'skipped',
            'package': package_name,
            'version': version,
            'file': file_name,
            'message': '文件已存在'
        }
    
    # 下载文件
    try:
        response = requests.get(full_url, timeout=30)
        
        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(response.content)
            
            file_size = len(response.content)
            return {
                'status': 'success',
                'package': package_name,
                'version': version,
                'file': file_name,
                'size': file_size,
                'path': save_path
            }
        else:
            return {
                'status': 'failed',
                'package': package_name,
                'version': version,
                'file': file_name,
                'error': f"HTTP {response.status_code}",
                'url': full_url
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'package': package_name,
            'version': version,
            'file': file_name,
            'error': str(e),
            'url': full_url
        }


def download_packages(packages_data, download_base_path, max_workers=20):
    """
    使用多进程并行下载恶意包到指定目录
    """
    print(f"\n🚀 开始多进程下载包到目录: {download_base_path}")
    print(f"🔧 使用 {max_workers} 个并行进程")
    
    # 创建基础下载目录
    os.makedirs(download_base_path, exist_ok=True)
    
    # 准备下载任务列表
    download_tasks = []
    for package_name, versions in packages_data.items():
        for version, file_info in versions.items():
            download_tasks.append((package_name, version, file_info, download_base_path))
    
    total_packages = len(download_tasks)
    print(f"📦 总共需要下载 {total_packages} 个包文件\n")
    
    # 统计变量
    downloaded_count = 0
    skipped_count = 0
    failed_count = 0
    error_count = 0
    
    start_time = time.time()
    
    # 使用ThreadPoolExecutor进行多线程下载
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_task = {executor.submit(download_single_package, task): task for task in download_tasks}
        
        # 处理完成的任务
        for i, future in enumerate(as_completed(future_to_task), 1):
            result = future.result()
            
            # 更新统计
            if result['status'] == 'success':
                downloaded_count += 1
                print(f"✅ [{i:4d}/{total_packages}] 下载成功: {result['package']}/{result['version']}/{result['file']} ({result['size']} bytes)")
            elif result['status'] == 'skipped':
                skipped_count += 1
                print(f"⏭️  [{i:4d}/{total_packages}] 跳过: {result['package']}/{result['version']}/{result['file']} - {result['message']}")
            elif result['status'] == 'failed':
                failed_count += 1
                print(f"❌ [{i:4d}/{total_packages}] 下载失败: {result['package']}/{result['version']}/{result['file']} - {result['error']}")
            elif result['status'] == 'error':
                error_count += 1
                print(f"💥 [{i:4d}/{total_packages}] 下载异常: {result['package']}/{result['version']}/{result['file']} - {result['error']}")
            
            # 每100个包显示一次进度
            if i % 100 == 0:
                elapsed_time = time.time() - start_time
                avg_time_per_package = elapsed_time / i
                estimated_remaining = (total_packages - i) * avg_time_per_package
                print(f"\n📊 进度报告 [{i}/{total_packages}]:")
                print(f"   ⏱️  已用时间: {elapsed_time:.1f}s")
                print(f"   🔮 预计剩余: {estimated_remaining:.1f}s")
                print(f"   ⚡ 平均速度: {i/elapsed_time:.1f} 包/秒\n")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n" + "="*60)
    print(f"📊 最终下载统计:")
    print(f"   ✅ 下载成功: {downloaded_count}")
    print(f"   ⏭️  跳过文件: {skipped_count}")
    print(f"   ❌ 下载失败: {failed_count}")
    print(f"   💥 下载异常: {error_count}")
    print(f"   📦 总计文件: {total_packages}")
    print(f"   ⏱️  总用时间: {total_time:.1f}s")
    print(f"   ⚡ 平均速度: {total_packages/total_time:.1f} 包/秒")
    print("="*60)


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
        
        # 3. 下载包 (使用20个并行线程)
        download_packages(packages_data, download_base_path, max_workers=20)
        
        print(f"\n🎉 任务完成!")
        print(f"所有文件已下载到: {download_base_path}")
        
    except Exception as e:
        print(f"\n❌ 程序执行过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
