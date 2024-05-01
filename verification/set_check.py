# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : set_check.py
# @Project  : MalDataCollect
# Time      : 1/5/24 8:06 pm
# Author    : honywen
# version   : python 3.8
# Description：
"""


import os
import tarfile
import zipfile
import shutil


class DataCheck:
    def __init__(self):
        self.pypi_malregistry = "/Users/blue/Documents/GitHub/pypi_malregistry"
        self.pkg_original_dir = "/Users/blue/Documents/MalDataset/osv_pypi/"
        self.pkg_target_dir = "/Users/blue/Documents/MalDataset/unzip_target/"
        self.malsnippet_dir = "./malsnippets/"
        self.versions = set()
        self.extension_tar = ".tar.gz"
        self.extension_zip = ".zip"
        self.extension_whl = ".whl"
        self.malware_pkgs = []
        self.mal_snippets = set()
        self.package_pyfiles = list()

    def malware_load(self):
        self.malware_pkgs = os.listdir(self.pypi_malregistry)

    def load_malsnippets(self):
        snippets_files = os.listdir(self.malsnippet_dir)
        for snippets_file in snippets_files:
            file_path = os.path.join(self.malsnippet_dir, snippets_file)
            with open(file_path, "r") as fr:
                content = fr.read().strip()
                self.mal_snippets.add(content)

    def package_decompress(self, original_path, target_path):
        # 创建目标解压目录
        os.makedirs(target_path, exist_ok=True)
        # 确保是文件
        if os.path.isfile(original_path):
            successful_extraction = True  # 标记是否成功解压
            try:
                # 根据文件扩展名选择解压方法
                if original_path.endswith('.tar.gz'):
                    with tarfile.open(original_path, 'r:gz') as archive:
                        archive.extractall(target_path)
                elif original_path.endswith('.zip'):
                    with zipfile.ZipFile(original_path, 'r') as archive:
                        archive.extractall(target_path)
                elif original_path.endswith('.whl'):
                    with zipfile.ZipFile(original_path, 'r') as archive:
                        archive.extractall(target_path)
                elif original_path.endswith('.py'):
                    shutil.copy(original_path, target_path)
            except Exception as e:
                successful_extraction = False
                print(f"Error processing file: {original_path}. Error: {e}")
            # 如果解压失败，删除目标解压目录
            if not successful_extraction:
                shutil.rmtree(target_path)

    def gci(self, packagepath):
        # 遍历filepath下所有文件，包括子目录
        files = os.listdir(packagepath)
        for fi in files:
            fi_d = os.path.join(packagepath, fi)
            if os.path.isdir(fi_d):
                self.gci(fi_d)
            else:
                if fi_d.endswith('.py'):
                    self.package_pyfiles.append(fi_d)
    def remove_setup(self, source_code):
        lines = source_code.split('\n')
        start = None
        end = None
        bracket_count = 0
        for i, line in enumerate(lines):
            if 'setup(' in line:
                start = i
                bracket_count += line.count('(') - line.count(')')
                if bracket_count == 0:
                    end = i
                    break
            elif start is not None:
                bracket_count += line.count('(') - line.count(')')
                if bracket_count == 0:
                    end = i
                    break
        if start is not None and end is not None:
            del lines[start:end + 1]
        return '\n'.join(lines).strip()

    def start(self):
        self.malware_load()
        self.load_malsnippets()
        checked_dir = "/Users/blue/Documents/MalDataset/checked_target/"
        packages = os.listdir(self.pkg_original_dir)
        for package in packages:
            flag = 0  # 初始化flag为0
            for version in os.listdir(os.path.join(self.pkg_original_dir, package)):
                if flag:  # 检查flag，如果已经设为1，跳出循环
                    break
                for file in os.listdir(os.path.join(self.pkg_original_dir, package, version)):
                    if flag:  # 再次检查flag，如果已经设为1，跳出循环
                        break
                    original_path = os.path.join(self.pkg_original_dir, package, version, file)
                    target_path = os.path.join(self.pkg_target_dir, package)
                    self.package_decompress(original_path, target_path)
                    self.package_pyfiles.clear()
                    self.gci(target_path)
                    for pyfile in self.package_pyfiles:
                        if pyfile.endswith('setup.py') or pyfile.endswith('__init__.py'):
                            with open(pyfile, "r") as fr:
                                code = fr.read().strip()
                                # if pyfile.endswith('setup.py'):
                                #     code = self.remove_setup(code)
                        for snippet in self.mal_snippets:
                            if snippet in code:
                                shutil.move(os.path.join(self.pkg_original_dir, package), os.path.join(checked_dir, package))
                                flag = 1  # 设置flag为1
                                break  # 成功复制后，退出内层循环


if __name__ == '__main__':
    data_check = DataCheck()
    data_check.start()