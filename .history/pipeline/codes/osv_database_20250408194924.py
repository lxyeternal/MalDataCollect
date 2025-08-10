# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : osv_database.py
# @Project  : MalDataCollect
# Time      : 2024/11/26 01:45
# Author    : honywen
# version   : python 3.8
# Description：Parse and collect malicious package information from OSV
"""


import os
import git
import json
from npm_collect import npm_pkg_links
from pypi_bigquery import query_bigquery, download_packages
from file_operation import create_package_info, save_package_info


class OSVDatabase:
    def __init__(self, google_cloud_key, pypi_dataset_path, npm_dataset_path, npm_mirrors, base_dir, records_dir, repo_url):
        self.google_cloud_key = google_cloud_key
        self.pypi_dataset_path = pypi_dataset_path
        self.npm_dataset_path = npm_dataset_path
        self.npm_mirrors = npm_mirrors
        self.base_dir = base_dir
        self.records_dir = records_dir
        self.repo_url = repo_url
        self.repo_path = os.path.join(base_dir, "malicious-packages")
        # 预加载已采集的包和已解析的OSV ID
        self.collected_packages = self._load_collected_packages()
        self.processed_ids = self._load_processed_ids()
        self.new_osv_data = []

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

    def _load_processed_ids(self):
        """加载已经处理过的OSV ID集合"""
        processed_ids = {'npm': set(), 'pip': set()}
        processed_file = os.path.join(self.records_dir, "processed_osv_ids.json")
        if os.path.exists(processed_file):
            try:
                with open(processed_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        processed_ids['npm'] = set(data.get('npm', []))
                        processed_ids['pip'] = set(data.get('pip', []))
            except Exception as e:
                print(f"读取已处理ID记录文件失败: {str(e)}")
        return processed_ids

    def clone_or_pull_repo(self):
        """Clone or update the OSV repository"""
        if not os.path.exists(self.repo_path):
            print(f"Cloning repository to {self.repo_path}")
            git.Repo.clone_from(self.repo_url, self.repo_path)
        else:
            print("Pulling latest changes")
            repo = git.Repo(self.repo_path)
            repo.remotes.origin.pull()

    def _get_affected_versions(self, affected):
        """
        从受影响的包信息中提取版本信息
        支持直接的版本列表和范围事件两种格式
        """
        versions = []
        # 直接获取 versions 列表
        if "versions" in affected:
            versions.extend(affected["versions"])
        # 处理 ranges 情况
        if "ranges" in affected:
            for range_info in affected["ranges"]:
                if isinstance(range_info, dict):
                    events = range_info.get("events", [])
                    for event in events:
                        if isinstance(event, dict) and "introduced" in event:
                            # 如果 introduced 为 "0"，表示从第一个版本开始就受影响
                            if event["introduced"] == "0" or event["introduced"] == 0:
                                versions.append("0")
        return versions

    def filter_new_osv_files(self):
        """Filter out already processed OSV files and cache new ones"""
        path_manager_map = {'npm': 'npm', 'pip': 'pypi'}
        for package_manager in ['npm', 'pip']:
            osv_dir = os.path.join(self.repo_path, "osv", "malicious", path_manager_map[package_manager])
            print(f"Checking for new OSV files in {osv_dir}")
            json_files = self._get_json_files(osv_dir)

            for json_file in json_files:
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        osv_data = json.load(f)

                    osv_id = osv_data.get("id", "")  # 如果没有 id，使用空字符串
                    if osv_id in self.processed_ids[package_manager]:
                        print(f"已经处理过的ID: {osv_id}")
                        continue

                    affected_list = osv_data.get("affected", [])
                    if isinstance(affected_list, list):
                        for affected in affected_list:
                            if isinstance(affected, dict):
                                package_info = affected.get("package", {})
                                if isinstance(package_info, dict):
                                    pkg_name = package_info.get("name", "")  # 如果没有名称，使用空字符串
                                    versions = self._get_affected_versions(affected)

                                    # 保存数据，即使某些字段为空
                                    self.new_osv_data.append({
                                        "package_manager": package_manager,
                                        "osv_id": osv_id,
                                        "pkg_name": pkg_name,
                                        "versions": versions,
                                        "file_path": json_file
                                    })
                except Exception as e:
                    print(f"处理文件 {json_file} 时发生错误: {str(e)}")
                    continue  # 继续处理下一个文件

    def collect_osv(self):
        """Collect malicious package data from filtered OSV data"""
        for osv_entry in self.new_osv_data:
            package_manager = osv_entry["package_manager"]
            osv_id = osv_entry["osv_id"]
            pkg_name = osv_entry["pkg_name"]
            versions = osv_entry["versions"]
            file_path = osv_entry["file_path"]

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    osv_data = json.load(f)

                affected_list = osv_data.get("affected", [])
                if not isinstance(affected_list, list):
                    print(f"affected 不是列表类型: {osv_id}")
                    continue

                for affected in affected_list:
                    if not isinstance(affected, dict):
                        continue

                    package_info = affected.get("package", {})
                    if not isinstance(package_info, dict):
                        continue

                    if package_info.get("name") != pkg_name:
                        continue

                    # 检查是否已采集
                    pkg_key = "npm" if package_manager == "npm" else "pip"
                    if pkg_name in self.collected_packages[pkg_key]:
                        print(f"已经采集过该包：{pkg_name}")
                        continue  # 只跳过这个包，继续处理其他的

                    # Try to download package
                    try:
                        if package_manager == "pip":
                            query_result = query_bigquery(self.google_cloud_key, [pkg_name])
                            if query_result:
                                download_packages(self.pypi_dataset_path, query_result)
                        elif package_manager == "npm":
                            if isinstance(self.npm_mirrors, dict):
                                npm_pkg_links(self.npm_mirrors, pkg_name, self.npm_dataset_path)
                    except Exception as e:
                        print(f"下载包失败 {pkg_name}: {str(e)}")
                        continue  # 如果下载失败，跳过此包

                    # Get package details and save
                    try:
                        self._save_package_info(osv_data, package_info, affected, pkg_name, versions, package_manager)
                        self.collected_packages[pkg_key].add(pkg_name)
                        self.processed_ids[package_manager].add(osv_id)
                        # 每次处理完一个ID，立即保存到文件
                        self._save_processed_ids()
                    except Exception as e:
                        print(f"获取 {pkg_name} 信息失败: {str(e)}")
                        self._save_basic_package_info(osv_data, pkg_name, versions, package_manager)
                        self.processed_ids[package_manager].add(osv_id)
                        # 每次处理完一个ID，立即保存到文件
                        self._save_processed_ids()

            except Exception as e:
                print(f"处理OSV数据失败 {osv_id}: {str(e)}")

    def _get_json_files(self, directory):
        """Get all JSON files in directory"""
        json_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.json'):
                    json_files.append(os.path.join(root, file))
        return json_files

    def _get_affected_versions(self, affected):
        """Extract affected version information"""
        versions = []

        # 直接的versions字段
        if "versions" in affected and isinstance(affected["versions"], list):
            return affected["versions"]

        # ranges字段
        ranges = affected.get("ranges", [])
        if isinstance(ranges, list):
            for range_info in ranges:
                if not isinstance(range_info, dict):
                    continue
                events = range_info.get("events", [])
                if not isinstance(events, list):
                    continue
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    if "introduced" in event:
                        versions.append(f">={event['introduced']}"
                                     if event['introduced'] != "0"
                                     else "all versions")
                    if "fixed" in event:
                        versions.append(f"<{event['fixed']}")

        return versions

    def _save_package_info(self, osv_data, package_info, affected,
                          pkg_name, affected_versions, package_manager):
        """Save package information in standardized format"""
        try:
            # Get CWE information
            cwe_info = []
            db_specific = affected.get("database_specific", {})
            if isinstance(db_specific, dict) and "cwes" in db_specific:
                cwes = db_specific["cwes"]
                if isinstance(cwes, list):
                    for cwe in cwes:
                        if isinstance(cwe, dict):
                            cwe_id = cwe.get("cweId", "")
                            if cwe_id:
                                cwe_info.append(cwe_id)

            # Get GHSA ID
            ghsa_id = ""
            aliases = osv_data.get("aliases", [])
            if isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.startswith("GHSA-"):
                        ghsa_id = alias
                        break

            # Get credit information
            credit = ""
            credits = osv_data.get("credits", [])
            if isinstance(credits, list) and credits:
                if isinstance(credits[0], dict):
                    credit = credits[0].get("name", "")

            # Get reference links
            ref_links = []
            references = osv_data.get("references", [])
            if isinstance(references, list):
                for ref in references:
                    if isinstance(ref, dict) and "url" in ref:
                        ref_links.append(ref["url"])

            # Create package info
            pkg_info = create_package_info(
                package_name=pkg_name,
                affected_version=affected_versions[0] if affected_versions else "",
                data_source_link=ref_links[0] if ref_links else "",
                update_date=osv_data.get("modified", ""),
                cve="",
                cwe=", ".join(cwe_info),
                fix_method="",
                overview=osv_data.get("details", osv_data.get("summary", "")),
                package_type="malicious",
                snyk_id=ghsa_id,
                published=osv_data.get("published", ""),
                credit=credit,
                reference_links=ref_links
            )

            save_package_info(self.records_dir, "osv", package_manager, pkg_info)

        except Exception as e:
            print(f"保存 {pkg_name} 信息失败: {str(e)}")
            self._save_basic_package_info(osv_data, pkg_name, affected_versions, package_manager)

    def _save_basic_package_info(self, osv_data, pkg_name, affected_versions, package_manager):
        """Save basic package information if detailed info fails"""
        basic_info = create_package_info(
            package_name=pkg_name,
            affected_version=affected_versions[0] if affected_versions else "",
            data_source_link=osv_data.get("id", ""),
            update_date=osv_data.get("modified", ""),
            overview=osv_data.get("summary", "")
        )
        save_package_info(self.records_dir, "osv", package_manager, basic_info)

    def _save_processed_ids(self):
        """保存已经处理过的OSV ID集合到文件"""
        processed_file = os.path.join(self.records_dir, "processed_osv_ids.json")
        try:
            with open(processed_file, 'w', encoding='utf-8') as f:
                json.dump({"npm": list(self.processed_ids['npm']), "pip": list(self.processed_ids['pip'])}, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"保存已处理ID记录文件失败: {str(e)}")

    def start_collect(self):
        """Start the collection process"""
        self.clone_or_pull_repo()
        self.filter_new_osv_files()
        self.collect_osv()
