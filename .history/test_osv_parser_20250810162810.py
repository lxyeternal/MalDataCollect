#!/usr/bin/env python
# -*-coding:utf-8 -*-

"""
测试OSV PyPI解析器
"""

import os
import sys
from datetime import datetime

# 添加codes目录到Python路径
sys.path.append('codes')

from osv_pypi_parser import OSVPyPIParser


def main():
    """测试主函数"""
    print("=== OSV PyPI Malicious Packages Parser Test ===\n")
    
    # 设置路径
    base_dir = os.path.dirname(os.path.abspath(__file__))
    local_registry_path = "/Users/blue/Documents/Github/pypi_malregistry"
    
    print(f"Base directory: {base_dir}")
    print(f"Local registry path: {local_registry_path}")
    print(f"Local registry exists: {os.path.exists(local_registry_path)}")
    
    # 创建解析器
    parser = OSVPyPIParser(
        base_dir=base_dir,
        local_registry_path=local_registry_path
    )
    
    # 设置输出文件
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"osv_pypi_malicious_{timestamp}.json"
    
    print(f"Output file: {output_file}\n")
    
    try:
        # 开始解析
        parser.start_parsing(output_file)
        
        print(f"\n✅ 解析完成!")
        print(f"结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"\n❌ 解析过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()