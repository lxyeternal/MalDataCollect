#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : run_osv_parser.py
# @Project  : MalDataCollect
# Time      : 2024/11/26 01:45
# Author    : honywen
# version   : python 3.8
# Description：Run OSV PyPI malicious packages parser
"""

import os
import sys
import json
from datetime import datetime
from osv_pypi_parser import OSVPyPIParser


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {str(e)}")
        return {}


def main():
    """Main function to run the OSV parser"""
    # 获取脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(os.path.dirname(script_dir), "configs")
    records_dir = os.path.join(os.path.dirname(script_dir), "records")
    
    # 加载配置
    config_file = os.path.join(config_dir, "osv_parser_config.json")
    config = load_config(config_file)
    
    if not config:
        print("Using default configuration")
        config = {
            "osv_parser": {
                "repository": {
                    "url": "https://github.com/ossf/malicious-packages",
                    "local_path": "malicious-packages"
                },
                "output": {
                    "directory": "records",
                    "filename_prefix": "osv_pypi_malicious",
                    "include_timestamp": True
                }
            }
        }
    
    # 设置输出文件路径
    if config["osv_parser"]["output"]["include_timestamp"]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"{config['osv_parser']['output']['filename_prefix']}_{timestamp}.json"
    else:
        output_filename = f"{config['osv_parser']['output']['filename_prefix']}.json"
    
    output_path = os.path.join(records_dir, output_filename)
    
    print("=== OSV PyPI Malicious Packages Parser ===")
    print(f"Script directory: {script_dir}")
    print(f"Config directory: {config_dir}")
    print(f"Records directory: {records_dir}")
    print(f"Output file: {output_path}")
    print(f"Repository URL: {config['osv_parser']['repository']['url']}")
    print()
    
    try:
        # 创建解析器实例
        parser = OSVPyPIParser(
            base_dir=os.path.dirname(script_dir),
            repo_url=config["osv_parser"]["repository"]["url"]
        )
        
        # 开始解析
        parser.start_parsing(output_path)
        
        print(f"\n✅ Parsing completed successfully!")
        print(f"Output saved to: {output_path}")
        
    except Exception as e:
        print(f"\n❌ Error during parsing: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 