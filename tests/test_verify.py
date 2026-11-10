import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from verify import deps, vrange  # noqa: E402
from verify.alias import canonical, group  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_pre_release_range():
    entry = {"ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "5.1b7"}, {"fixed": "5.3.1"}]}]}
    assert vrange.entry_hits(entry, "5.1")[0] is True
    assert vrange.entry_hits(entry, "5.3.1")[0] is False
    assert vrange.entry_hits(entry, "5.0")[0] is False


def test_last_affected_inclusive():
    entry = {"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"last_affected": "3.3.1"}]}]}
    assert vrange.entry_hits(entry, "3.3.1")[0] is True
    assert vrange.entry_hits(entry, "3.3.2")[0] is False


def test_invalid_version_undetermined():
    entry = {"ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}
    assert vrange.entry_hits(entry, "5.1.0-M1")[0] is None


def test_alias_dsu():
    recs = [{"id": "GHSA-a", "aliases": ["CVE-1"]},
            {"id": "PYSEC-1", "aliases": ["CVE-1"]},
            {"id": "GHSA-b", "aliases": ["CVE-2"]}]
    groups = group(recs)
    assert len(groups) == 2
    one = [g for g in groups.values() if len(g) == 2][0]
    assert canonical(one) == "CVE-1"


def test_deps_demo_project():
    ds = deps.load_project(os.path.join(ROOT, "demo/demo_project"))
    assert len(ds) == 11
    by = {d["canonical"]: d for d in ds}
    assert by["django"]["scope"] == "dev"
    assert by["pyyaml"]["version"] == "5.1"
