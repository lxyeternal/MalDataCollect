# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : file_operation.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 01:48
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import json
from datetime import datetime
from typing import Dict, List, Optional


def save_package_info(base_dir: str, data_source: str, package_manager: str, pkg_info: Dict) -> None:
    """
    Save package information to JSON file based on data source and package manager.
    All packages from the same source and manager are saved in one JSON file.
    Uses package_name as the key in the JSON structure.

    Args:
        base_dir: Base directory for all records
        data_source: Data source ('snyk' or 'osv')
        package_manager: Package manager ('pip' or 'npm')
        pkg_info: Package information dictionary
    """
    os.makedirs(base_dir, exist_ok=True)

    # Generate filename using data source and package manager
    filename = f"{data_source}_{package_manager}_packages.json"
    filepath = os.path.join(base_dir, filename)

    # Get package name as key
    pkg_name = pkg_info['package_name']

    # Load existing data or create new structure
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {
                "metadata": {
                    "data_source": data_source,
                    "package_manager": package_manager,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "packages": {}
            }
    else:
        data = {
            "metadata": {
                "data_source": data_source,
                "package_manager": package_manager,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "packages": {}
        }

    # Update or add package information
    if pkg_name in data["packages"]:
        # If package exists, update its information
        data["packages"][pkg_name].update(pkg_info)
    else:
        # If new package, add it directly
        data["packages"][pkg_name] = pkg_info

    # Update last modified time
    data["metadata"]["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save updated data
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def create_package_info(
        package_name: str,
        affected_version: Optional[str] = None,
        download_success: bool = False,
        source_data: Optional[Dict] = None,
        **kwargs
) -> Dict:
    """
    Create standardized package information dictionary

    Args:
        package_name: Package name
        affected_version: Affected package version (optional)
        download_success: Whether source code download was successful
        source_data: Original data from query (for failed downloads)
        **kwargs: Additional package information

    Returns:
        Dictionary containing package information
    """
    pkg_info = {
        "package_name": package_name,
        "collection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # Package details
        "versions": {
            "affected": affected_version if affected_version else "",
            "all_versions": kwargs.get("all_versions", [])
        },
        "security_score": kwargs.get("security_score", ""),
        "cve": kwargs.get("cve", ""),
        "cwe": kwargs.get("cwe", ""),
        "fix_method": kwargs.get("fix_method", ""),
        "overview": kwargs.get("overview", ""),
        "update_date": kwargs.get("update_date", ""),
        "package_type": kwargs.get("package_type", ""),

        # Reference information
        "data_source_link": kwargs.get("data_source_link", ""),
        "reference_links": kwargs.get("reference_links", []),
        "snyk_id": kwargs.get("snyk_id", ""),
        "published": kwargs.get("published", ""),
        "disclosed": kwargs.get("disclosed", ""),
        "credit": kwargs.get("credit", ""),

        # Download information
        "download_info": {
            "download_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S") if download_success else "",
            "download_path": kwargs.get("download_path", "")
        }
    }
    # Add original source data if download failed
    if not download_success and source_data is not None:
        pkg_info["original_data"] = source_data
    return pkg_info



def mkdir(base_path: str, pkg_name: str, version: str) -> None:
    dirpath = os.path.join(base_path, pkg_name, version)
    folder = os.path.exists(dirpath)
    if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
        os.makedirs(dirpath)  # makedirs 创建文件时如果路径不存在会创建这个路径
    else:
        pass