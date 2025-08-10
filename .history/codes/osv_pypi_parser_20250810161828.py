#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : osv_pypi_parser.py
# @Project  : MalDataCollect
# Time      : 2024/11/26 01:45
# Author    : honywen
# version   : python 3.8
# Description：Download OSV repository and parse PyPI malicious package JSON files
"""

import os
import git
import json
from datetime import datetime
from typing import Dict, List, Any


class OSVPyPIParser:
    def __init__(self, base_dir: str, repo_url: str = "https://github.com/ossf/malicious-packages"):
        self.base_dir = base_dir
        self.repo_url = repo_url
        self.repo_path = os.path.join(base_dir, "malicious-packages")
        self.pypi_malicious_dir = os.path.join(self.repo_path, "osv", "malicious", "pypi")
        self.parsed_data = {}
        
    def clone_or_pull_repo(self):
        """Clone or update the OSV repository"""
        try:
            if not os.path.exists(self.repo_path):
                print(f"Cloning repository to {self.repo_path}")
                git.Repo.clone_from(self.repo_url, self.repo_path)
            else:
                print("Pulling latest changes")
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            print("Repository updated successfully")
        except Exception as e:
            print(f"Error updating repository: {str(e)}")
            raise
    
    def _get_json_files(self, directory: str) -> List[str]:
        """Get all JSON files in directory"""
        json_files = []
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.json'):
                        json_files.append(os.path.join(root, file))
        return json_files
    
    def _extract_versions(self, affected: Dict[str, Any]) -> List[str]:
        """Extract version information from affected package data"""
        versions = []
        
        # 直接获取 versions 列表
        if "versions" in affected and isinstance(affected["versions"], list):
            versions.extend(affected["versions"])
        
        # 处理 ranges 情况
        if "ranges" in affected and isinstance(affected["ranges"], list):
            for range_info in affected["ranges"]:
                if isinstance(range_info, dict):
                    events = range_info.get("events", [])
                    if isinstance(events, list):
                        for event in events:
                            if isinstance(event, dict):
                                if "introduced" in event:
                                    introduced = event["introduced"]
                                    if introduced == "0" or introduced == 0:
                                        versions.append("all versions")
                                    else:
                                        versions.append(f">={introduced}")
                                if "fixed" in event:
                                    fixed = event["fixed"]
                                    versions.append(f"<{fixed}")
        
        return versions
    
    def _extract_references(self, osv_data: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from OSV data"""
        references = []
        if "references" in osv_data and isinstance(osv_data["references"], list):
            for ref in osv_data["references"]:
                if isinstance(ref, dict) and "url" in ref:
                    references.append(ref["url"])
        return references
    
    def _extract_credits(self, osv_data: Dict[str, Any]) -> List[str]:
        """Extract credit information from OSV data"""
        credits = []
        if "credits" in osv_data and isinstance(osv_data["credits"], list):
            for credit in osv_data["credits"]:
                if isinstance(credit, dict) and "name" in credit:
                    credits.append(credit["name"])
        return credits
    
    def _extract_malicious_origins(self, osv_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract malicious package origins information"""
        origins = []
        if "database_specific" in osv_data:
            db_specific = osv_data["database_specific"]
            if isinstance(db_specific, dict) and "malicious-packages-origins" in db_specific:
                origins_data = db_specific["malicious-packages-origins"]
                if isinstance(origins_data, list):
                    for origin in origins_data:
                        if isinstance(origin, dict):
                            origins.append(origin)
        return origins
    
    def parse_pypi_malicious_packages(self):
        """Parse all PyPI malicious package JSON files"""
        if not os.path.exists(self.pypi_malicious_dir):
            print(f"PyPI malicious directory not found: {self.pypi_malicious_dir}")
            return
        
        json_files = self._get_json_files(self.pypi_malicious_dir)
        print(f"Found {len(json_files)} JSON files to parse")
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    osv_data = json.load(f)
                
                # 解析基本信息
                osv_id = osv_data.get("id", "")
                summary = osv_data.get("summary", "")
                details = osv_data.get("details", "")
                modified = osv_data.get("modified", "")
                published = osv_data.get("published", "")
                
                # 解析受影响的包
                affected_list = osv_data.get("affected", [])
                if isinstance(affected_list, list):
                    for affected in affected_list:
                        if isinstance(affected, dict):
                            package_info = affected.get("package", {})
                            if isinstance(package_info, dict):
                                pkg_name = package_info.get("name", "")
                                ecosystem = package_info.get("ecosystem", "")
                                purl = package_info.get("purl", "")
                                
                                if pkg_name:  # 只处理有包名的数据
                                    versions = self._extract_versions(affected)
                                    references = self._extract_references(osv_data)
                                    credits = self._extract_credits(osv_data)
                                    malicious_origins = self._extract_malicious_origins(osv_data)
                                    
                                    # 构建包信息
                                    package_data = {
                                        "osv_id": osv_id,
                                        "summary": summary,
                                        "details": details,
                                        "modified": modified,
                                        "published": published,
                                        "ecosystem": ecosystem,
                                        "purl": purl,
                                        "affected_versions": versions,
                                        "references": references,
                                        "credits": credits,
                                        "malicious_origins": malicious_origins,
                                        "source_file": os.path.basename(json_file)
                                    }
                                    
                                    # 以包名为中心组织数据
                                    if pkg_name not in self.parsed_data:
                                        self.parsed_data[pkg_name] = []
                                    
                                    self.parsed_data[pkg_name].append(package_data)
                                    
            except Exception as e:
                print(f"Error parsing file {json_file}: {str(e)}")
                continue
        
        print(f"Successfully parsed {len(self.parsed_data)} unique packages")
    
    def save_parsed_data(self, output_file: str):
        """Save parsed data to JSON file"""
        try:
            # 添加元数据
            output_data = {
                "metadata": {
                    "total_packages": len(self.parsed_data),
                    "parsed_at": datetime.now().isoformat(),
                    "source": "OSV malicious packages repository",
                    "ecosystem": "PyPI"
                },
                "packages": self.parsed_data
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            
            print(f"Parsed data saved to {output_file}")
            
        except Exception as e:
            print(f"Error saving data: {str(e)}")
    
    def print_summary(self):
        """Print summary of parsed data"""
        print("\n=== Parsing Summary ===")
        print(f"Total unique packages: {len(self.parsed_data)}")
        
        # 统计版本信息
        total_versions = 0
        packages_with_versions = 0
        packages_without_versions = 0
        
        for pkg_name, entries in self.parsed_data.items():
            for entry in entries:
                if entry.get("affected_versions"):
                    total_versions += len(entry["affected_versions"])
                    packages_with_versions += 1
                else:
                    packages_without_versions += 1
        
        print(f"Packages with version info: {packages_with_versions}")
        print(f"Packages without version info: {packages_without_versions}")
        print(f"Total version entries: {total_versions}")
        
        # 显示前几个包作为示例
        print("\n=== Sample Packages ===")
        for i, (pkg_name, entries) in enumerate(list(self.parsed_data.items())[:5]):
            print(f"{i+1}. {pkg_name}: {len(entries)} OSV entries")
            for entry in entries[:2]:  # 只显示前2个条目
                print(f"   - {entry['osv_id']}: {entry['summary'][:50]}...")
    
    def start_parsing(self, output_file: str = None):
        """Start the complete parsing process"""
        print("Starting OSV PyPI malicious packages parsing...")
        
        # 1. 克隆/更新仓库
        self.clone_or_pull_repo()
        
        # 2. 解析PyPI恶意包
        self.parse_pypi_malicious_packages()
        
        # 3. 打印摘要
        self.print_summary()
        
        # 4. 保存结果
        if output_file:
            self.save_parsed_data(output_file)
        else:
            # 默认输出文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_output = os.path.join(self.base_dir, f"osv_pypi_malicious_{timestamp}.json")
            self.save_parsed_data(default_output)


def main():
    """Main function for testing"""
    # 设置基础目录
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 创建解析器实例
    parser = OSVPyPIParser(base_dir)
    
    # 开始解析
    parser.start_parsing()


if __name__ == "__main__":
    main() 