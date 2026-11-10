"""经营报表渲染：依赖 PyYAML / requests。"""
import yaml
import requests


def load_config(path="config.yaml"):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def push_report(url, payload):
    return requests.post(url, json=payload, timeout=5)
