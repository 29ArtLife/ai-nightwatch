"""报表模板：Jinja2。"""
import jinja2

env = jinja2.Environment(autoescape=True)


def render(name, **ctx):
    return env.from_string(name).render(**ctx)
