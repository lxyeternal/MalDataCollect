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
    def __init__(self, base_dir: str, repo_url: str = "https://github.com/ossf/malicious-packages", 
                 local_registry_path: str = "/Users/blue/Documents/Github/pypi_malregistry"):
        self.base_dir = base_dir
        self.repo_url = repo_url
        self.repo_path = os.path.join(base_dir, "malicious-packages")
        self.pypi_malicious_dir = os.path.join(self.repo_path, "osv", "malicious", "pypi")
        self.local_registry_path = local_registry_path
        self.parsed_data = {}
        self.mal_2025_packages = []  # 存储MAL-2025开头的包
        
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
    
    def generate_sql_query(self, package_names: List[str]) -> str:
        """为给定的包名列表生成BigQuery SQL查询语句"""
        if not package_names:
            return ""
        
        # 构建WHERE条件
        if len(package_names) == 1:
            where_condition = f'name = "{package_names[0]}"'
        else:
            where_condition = ' OR '.join([f'name = "{name}"' for name in package_names])
        
        # 生成完整的SQL查询
        sql_query = f"""SELECT name, version, author, author_email, uploaded_via, upload_time, size, python_version, packagetype, path
FROM `bigquery-public-data.pypi.distribution_metadata` 
WHERE {where_condition}"""
        
        return sql_query
    
    def _check_local_package_exists(self, package_name: str) -> bool:
        """检查本地registry中是否已存在该包"""
        if not os.path.exists(self.local_registry_path):
            return False
        package_path = os.path.join(self.local_registry_path, package_name)
        return os.path.exists(package_path) and os.path.isdir(package_path)
    
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
                                    
                                    # 检查本地是否已有该包
                                    local_exists = self._check_local_package_exists(pkg_name)
                                    
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
                                        "source_file": os.path.basename(json_file),
                                        "local_exists": local_exists
                                    }
                                    
                                    # 检查是否为MAL-2025开头的ID
                                    if osv_id.startswith("MAL-2025"):
                                        self.mal_2025_packages.append({
                                            "package_name": pkg_name,
                                            "osv_id": osv_id,
                                            "local_exists": local_exists
                                        })
                                    
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
            # 生成MAL-2025包的SQL查询
            mal_2025_package_names = list(set([pkg["package_name"] for pkg in self.mal_2025_packages]))
            sql_query = self.generate_sql_query(mal_2025_package_names) if mal_2025_package_names else ""
            
            # 统计本地已存在的包
            local_exists_count = sum(1 for pkg in self.mal_2025_packages if pkg["local_exists"])
            
            # 添加元数据
            output_data = {
                "metadata": {
                    "total_packages": len(self.parsed_data),
                    "mal_2025_count": len(self.mal_2025_packages),
                    "mal_2025_unique_packages": len(mal_2025_package_names),
                    "mal_2025_local_exists": local_exists_count,
                    "parsed_at": datetime.now().isoformat(),
                    "source": "OSV malicious packages repository",
                    "ecosystem": "PyPI",
                    "local_registry_path": self.local_registry_path
                },
                "mal_2025_packages": self.mal_2025_packages,
                "mal_2025_sql_query": sql_query,
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
        
        # MAL-2025统计信息
        mal_2025_package_names = list(set([pkg["package_name"] for pkg in self.mal_2025_packages]))
        local_exists_count = sum(1 for pkg in self.mal_2025_packages if pkg["local_exists"])
        
        print(f"\n=== MAL-2025 Statistics ===")
        print(f"MAL-2025 total entries: {len(self.mal_2025_packages)}")
        print(f"MAL-2025 unique packages: {len(mal_2025_package_names)}")
        print(f"MAL-2025 packages exist locally: {local_exists_count}")
        print(f"MAL-2025 packages missing locally: {len(mal_2025_package_names) - local_exists_count}")
        
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
        
        print(f"\n=== Version Statistics ===")
        print(f"Packages with version info: {packages_with_versions}")
        print(f"Packages without version info: {packages_without_versions}")
        print(f"Total version entries: {total_versions}")
        
        # 显示MAL-2025包示例
        print("\n=== MAL-2025 Sample Packages ===")
        for i, pkg in enumerate(self.mal_2025_packages[:10]):  # 只显示前10个
            status = "✅ Local" if pkg["local_exists"] else "❌ Missing"
            print(f"{i+1}. {pkg['package_name']} ({pkg['osv_id']}) - {status}")
        
        if len(self.mal_2025_packages) > 10:
            print(f"... and {len(self.mal_2025_packages) - 10} more MAL-2025 packages")
        
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