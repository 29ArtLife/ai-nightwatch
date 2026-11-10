"""日期处理：python-dateutil。"""
from dateutil import parser


def parse_day(s):
    return parser.parse(s).date()
