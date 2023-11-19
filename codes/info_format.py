# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# @File     : info_format.py
# @Project  : MalDataCollect
# Time      : 2023/11/20 02:46
# Author    : honywen
# version   : python 3.8
# Description：
"""


def format_infodata(pkg_info_dict) -> list:
    item_name_list = ['Exploit Maturity', 'Attack Complexity', 'Confidentiality', 'Integrity', 'Availability',
                           'Attack Vector', 'Privileges Required', 'User Interaction', 'Scope', 'Snyk ID', 'Published',
                           'Disclosed', 'Credit']
    format_info_list = list()
    for info in item_name_list:
        try:
            format_info_list.append(pkg_info_dict[info])
        except:
            format_info_list.append('')
    return format_info_list