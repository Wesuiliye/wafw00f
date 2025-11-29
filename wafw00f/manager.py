#!/usr/bin/env python3
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

import os
from functools import partial
from pluginbase import PluginBase

def load_plugins():
    '''
    动态加载一个指定目录（plugins）下的所有 Python 模块作为 “插件”
    '''
    here = os.path.abspath(os.path.dirname(__file__))
    get_path = partial(os.path.join, here)
    plugin_dir = get_path('plugins')

    # 初始化插件系统
    plugin_base = PluginBase(
        package='wafw00f.plugins', searchpath=[plugin_dir]
    )
    # 从 PluginBase 实例创建一个 PluginSource 对象。
    plugin_source = plugin_base.make_plugin_source(
        searchpath=[plugin_dir], persist=True
    )

    # 遍历并加载所有插件
    plugin_dict = {}
    for plugin_name in plugin_source.list_plugins():
        plugin_dict[plugin_name] = plugin_source.load_plugin(plugin_name)

    return plugin_dict
