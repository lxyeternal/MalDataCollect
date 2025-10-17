#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyPI恶意包清理脚本

根据empty.txt文件中的恶意包列表，清理pypi_malregistry目录下的恶意包。
删除规则：
1. 如果包名文件夹下只有一个版本文件夹，且该版本文件夹下只有一个压缩包，且该压缩包在txt中，则删除整个包名文件夹
2. 如果包名文件夹下有多个版本文件夹，但只有一个版本文件夹的压缩包在txt中，则只删除该版本文件夹
3. 如果一个版本文件夹下有多个压缩包，只有一个在txt中，则只删除该压缩包

作者：AI助手
日期：2025年1月
"""

import os
import shutil
import re
from pathlib import Path
from typing import Set, List, Tuple, Dict


class PyPIMaliciousCleaner:
    """PyPI恶意包清理器"""
    
    def __init__(self, malregistry_path: str, malicious_list_path: str):
        """
        初始化清理器
        
        Args:
            malregistry_path: pypi_malregistry目录路径
            malicious_list_path: 恶意包列表文件路径
        """
        self.malregistry_path = Path(malregistry_path)
        self.malicious_list_path = Path(malicious_list_path)
        self.malicious_packages: Set[str] = set()
        self.malicious_archives: Set[str] = set()
        
        # 支持的压缩包扩展名
        self.archive_extensions = {'.tar', '.zip', '.whl', '.tar.gz'}
        
    def load_malicious_list(self) -> None:
        """加载恶意包列表"""
        print("正在加载恶意包列表...")
        
        if not self.malicious_list_path.exists():
            raise FileNotFoundError(f"恶意包列表文件不存在: {self.malicious_list_path}")
            
        with open(self.malicious_list_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                # 判断是包名还是压缩包
                if self._is_archive_file(line):
                    self.malicious_archives.add(line)
                else:
                    self.malicious_packages.add(line)
        
        print(f"加载完成: {len(self.malicious_packages)} 个恶意包名, {len(self.malicious_archives)} 个恶意压缩包")
        
    def _is_archive_file(self, filename: str) -> bool:
        """
        判断文件名是否为压缩包
        
        Args:
            filename: 文件名
            
        Returns:
            bool: 是否为压缩包
        """
        return any(filename.endswith(ext) for ext in self.archive_extensions)
    
    def _extract_package_name_from_archive(self, archive_name: str) -> str:
        """
        从压缩包名称中提取包名
        
        Args:
            archive_name: 压缩包名称
            
        Returns:
            str: 包名
        """
        # 移除扩展名
        name_without_ext = archive_name
        for ext in self.archive_extensions:
            if name_without_ext.endswith(ext):
                name_without_ext = name_without_ext[:-len(ext)]
                break
                
        # 移除版本号部分 (通常是 -数字.数字.数字 格式)
        # 使用正则表达式匹配版本号模式
        version_pattern = r'-\d+(\.\d+)*([a-zA-Z0-9]*)?$'
        package_name = re.sub(version_pattern, '', name_without_ext)
        
        return package_name
    
    def _remove_extension(self, filename: str) -> str:
        """
        移除文件扩展名
        
        Args:
            filename: 文件名
            
        Returns:
            str: 移除扩展名后的文件名
        """
        for ext in self.archive_extensions:
            if filename.endswith(ext):
                return filename[:-len(ext)]
        return filename
    
    def scan_malregistry(self) -> Dict[str, List[Tuple[str, List[str]]]]:
        """
        扫描malregistry目录结构
        
        Returns:
            Dict: 包名 -> [(版本, [压缩包列表])]
        """
        print("正在扫描malregistry目录...")
        
        package_structure = {}
        
        if not self.malregistry_path.exists():
            raise FileNotFoundError(f"malregistry目录不存在: {self.malregistry_path}")
            
        # 遍历所有包名文件夹
        for package_dir in self.malregistry_path.iterdir():
            if not package_dir.is_dir():
                continue
                
            package_name = package_dir.name
            versions = []
            
            # 遍历版本文件夹
            for version_dir in package_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                    
                version = version_dir.name
                archives = []
                
                # 遍历压缩包文件
                for file in version_dir.iterdir():
                    if file.is_file() and self._is_archive_file(file.name):
                        archives.append(file.name)
                
                if archives:
                    versions.append((version, archives))
            
            if versions:
                package_structure[package_name] = versions
        
        print(f"扫描完成: 发现 {len(package_structure)} 个包")
        return package_structure
    
    def find_malicious_items(self, package_structure: Dict[str, List[Tuple[str, List[str]]]]) -> List[Tuple[str, str, str]]:
        """
        查找需要删除的恶意项目
        
        Args:
            package_structure: 包结构字典
            
        Returns:
            List[Tuple[str, str, str]]: [(包名, 版本, 压缩包名)] 需要删除的项目
        """
        print("正在查找恶意项目...")
        
        malicious_items = []
        
        for package_name, versions in package_structure.items():
            # 检查包名是否在恶意列表中
            if package_name in self.malicious_packages:
                # 整个包都是恶意的，记录所有版本的所有压缩包
                for version, archives in versions:
                    for archive in archives:
                        malicious_items.append((package_name, version, archive))
                continue
            
            # 检查各个压缩包
            for version, archives in versions:
                malicious_archives_in_version = []
                
                for archive in archives:
                    # 直接检查压缩包名
                    if archive in self.malicious_archives:
                        malicious_archives_in_version.append(archive)
                        malicious_items.append((package_name, version, archive))
                    else:
                        # 检查压缩包名是否匹配恶意列表中的任何条目（忽略扩展名差异）
                        archive_base = self._remove_extension(archive)
                        for malicious_archive in self.malicious_archives:
                            malicious_base = self._remove_extension(malicious_archive)
                            if archive_base == malicious_base:
                                malicious_archives_in_version.append(archive)
                                malicious_items.append((package_name, version, archive))
                                break
                        else:
                            # 从压缩包名提取包名检查
                            extracted_name = self._extract_package_name_from_archive(archive)
                            if extracted_name in self.malicious_packages:
                                malicious_archives_in_version.append(archive)
                                malicious_items.append((package_name, version, archive))
        
        print(f"找到 {len(malicious_items)} 个恶意项目")
        return malicious_items
    
    def analyze_deletion_strategy(self, package_structure: Dict[str, List[Tuple[str, List[str]]]], 
                                malicious_items: List[Tuple[str, str, str]]) -> Dict[str, List[str]]:
        """
        分析删除策略
        
        Args:
            package_structure: 包结构字典
            malicious_items: 恶意项目列表
            
        Returns:
            Dict: 删除策略 {'packages': [], 'versions': [], 'archives': []}
        """
        print("正在分析删除策略...")
        
        deletion_plan = {
            'packages': [],  # 需要删除整个包
            'versions': [],  # 需要删除版本文件夹
            'archives': []   # 需要删除单个压缩包
        }
        
        # 按包名分组恶意项目
        malicious_by_package = {}
        for package_name, version, archive in malicious_items:
            if package_name not in malicious_by_package:
                malicious_by_package[package_name] = []
            malicious_by_package[package_name].append((version, archive))
        
        for package_name, malicious_versions in malicious_by_package.items():
            if package_name not in package_structure:
                continue
                
            all_versions = package_structure[package_name]
            malicious_version_names = set(version for version, _ in malicious_versions)
            
            # 情况1: 整个包只有一个版本，且该版本的所有压缩包都是恶意的
            if len(all_versions) == 1:
                version_name, all_archives = all_versions[0]
                malicious_archives_in_version = [archive for version, archive in malicious_versions 
                                               if version == version_name]
                
                if len(malicious_archives_in_version) == len(all_archives):
                    # 删除整个包
                    deletion_plan['packages'].append(package_name)
                else:
                    # 只删除恶意压缩包
                    for version, archive in malicious_versions:
                        deletion_plan['archives'].append((package_name, version, archive))
            
            # 情况2: 包有多个版本
            else:
                # 检查是否有版本的所有压缩包都是恶意的
                for version_name, all_archives in all_versions:
                    malicious_archives_in_version = [archive for version, archive in malicious_versions 
                                                   if version == version_name]
                    
                    if len(malicious_archives_in_version) == len(all_archives):
                        # 删除整个版本文件夹
                        deletion_plan['versions'].append((package_name, version_name))
                    else:
                        # 只删除恶意压缩包
                        for version, archive in malicious_versions:
                            if version == version_name:
                                deletion_plan['archives'].append((package_name, version, archive))
        
        print(f"删除策略分析完成:")
        print(f"  - 需要删除整个包: {len(deletion_plan['packages'])} 个")
        print(f"  - 需要删除版本文件夹: {len(deletion_plan['versions'])} 个")
        print(f"  - 需要删除单个压缩包: {len(deletion_plan['archives'])} 个")
        
        return deletion_plan
    
    def execute_deletion(self, deletion_plan: Dict[str, List], dry_run: bool = True) -> None:
        """
        执行删除操作
        
        Args:
            deletion_plan: 删除计划
            dry_run: 是否为试运行（不实际删除）
        """
        print(f"\n{'='*50}")
        print(f"{'试运行模式' if dry_run else '实际删除模式'}")
        print(f"{'='*50}")
        
        # 删除整个包
        for package_name in deletion_plan['packages']:
            package_path = self.malregistry_path / package_name
            if package_path.exists():
                print(f"{'[试运行] ' if dry_run else ''}删除整个包: {package_name}")
                if not dry_run:
                    shutil.rmtree(package_path)
        
        # 删除版本文件夹
        for package_name, version_name in deletion_plan['versions']:
            version_path = self.malregistry_path / package_name / version_name
            if version_path.exists():
                print(f"{'[试运行] ' if dry_run else ''}删除版本文件夹: {package_name}/{version_name}")
                if not dry_run:
                    shutil.rmtree(version_path)
        
        # 删除单个压缩包
        for package_name, version_name, archive_name in deletion_plan['archives']:
            archive_path = self.malregistry_path / package_name / version_name / archive_name
            if archive_path.exists():
                print(f"{'[试运行] ' if dry_run else ''}删除压缩包: {package_name}/{version_name}/{archive_name}")
                if not dry_run:
                    archive_path.unlink()
        
        if dry_run:
            print(f"\n试运行完成！如需实际删除，请设置 dry_run=False")
        else:
            print(f"\n删除操作完成！")
    
    def run(self, dry_run: bool = True) -> None:
        """
        运行清理程序
        
        Args:
            dry_run: 是否为试运行
        """
        print("PyPI恶意包清理程序启动")
        print("="*50)
        
        try:
            # 1. 加载恶意包列表
            self.load_malicious_list()
            
            # 2. 扫描malregistry目录
            package_structure = self.scan_malregistry()
            
            # 3. 查找恶意项目
            malicious_items = self.find_malicious_items(package_structure)
            
            if not malicious_items:
                print("未发现需要删除的恶意项目")
                return
            
            # 4. 分析删除策略
            deletion_plan = self.analyze_deletion_strategy(package_structure, malicious_items)
            
            # 5. 执行删除
            self.execute_deletion(deletion_plan, dry_run)
            
        except Exception as e:
            print(f"程序执行出错: {e}")
            raise


def main():
    """主函数"""
    # 配置路径
    malregistry_path = "/Users/blue/Documents/Github/pypi_malregistry"
    malicious_list_path = "/Users/blue/Documents/Github/MalDataCollect/empty.txt"
    
    # 创建清理器实例
    cleaner = PyPIMaliciousCleaner(malregistry_path, malicious_list_path)
    
    # 先进行试运行
    print("开始试运行...")
    cleaner.run(dry_run=True)
    
    # 询问是否执行实际删除
    print("\n" + "="*50)
    response = input("是否执行实际删除操作？(y/N): ").strip().lower()
    
    if response in ['y', 'yes']:
        print("开始实际删除...")
        cleaner.run(dry_run=False)
    else:
        print("取消删除操作")


if __name__ == "__main__":
    main()
