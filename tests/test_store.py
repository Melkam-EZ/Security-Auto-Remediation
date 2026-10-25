import pytest

from conftest import make_table
from secrem.store import Conflict, FindingStore


@pytest.fixture
def store(world):
    return world.store


def item(fid="r#x", **kw):
    return {"finding_id": fid, "rule_id": "r", "state": "DETECTED", "updated_epoch": 1, "evidence": {"a": [1]}, **kw}


def test_create_refuses_to_overwrite(store):
    store.create(item(detail="first"))
    with pytest.raises(Conflict):
        store.create(item(detail="second"))
    assert store.get("r#x")["detail"] == "first"


def test_stale_writer_loses_and_versions_increase(store):
    a = store.create(item())
    b = store.get("r#x")
    a2 = store.save(dict(a, state="REPORTED"))
    assert a2["version"] == 2
    with pytest.raises(Conflict):
        store.save(dict(b, state="FAILED"))                     # b still holds version 1
    assert store.get("r#x")["state"] == "REPORTED"


def test_json_fields_roundtrip_and_counters_stay_out_of_listings(store):
    store.create(item(pre_state={"k": "v"}, history=[{"at": "t"}]))
    got = store.get("r#x")
    assert got["evidence"] == {"a": [1]} and got["pre_state"] == {"k": "v"} and got["history"] == [{"at": "t"}]
    assert store.bump("2026060112", 9999999999) == 1 and store.bump("2026060112", 9999999999) == 2
    assert store.counter("2026060112") == 2 and store.counter("other") == 0
    assert [f["finding_id"] for f in store.all()] == ["r#x"]


def test_by_state_and_open_for_rule(store):
    store.create(item("r#a"))
    store.create(item("r#b", state="RESOLVED"))
    assert [f["finding_id"] for f in store.by_state("DETECTED")] == ["r#a"]
    assert [f["finding_id"] for f in store.open_for_rule("r")] == ["r#a"]
