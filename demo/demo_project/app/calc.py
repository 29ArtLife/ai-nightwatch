"""指标计算：numpy。"""
import numpy as np


def growth(values):
    arr = np.asarray(values, dtype=float)
    return (arr[1:] - arr[:-1]) / arr[:-1]
