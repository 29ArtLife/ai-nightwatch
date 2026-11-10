"""内部 API：Flask + urllib3。"""
from flask import Flask, jsonify
import urllib3

app = Flask(__name__)
http = urllib3.PoolManager()


@app.get("/health")
def health():
    return jsonify(ok=True)


def fetch(url):
    return http.request("GET", url, timeout=3).data
