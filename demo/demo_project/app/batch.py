"""批处理入口：含动态导入，用于如实标注可达性盲区。"""
import importlib
import os


def run_plugin():
    name = os.getenv("REPORT_PLUGIN", "app.report")
    mod = importlib.import_module(name)
    return mod


def run():
    return run_plugin()
