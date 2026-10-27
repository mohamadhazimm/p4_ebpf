import importlib.util
import csv
import json
from pathlib import Path
import sys
import types

import pytest


ROOT = Path(__file__).resolve().parents[2]


def pytest_addoption(parser):
    group = parser.getgroup("collector-validation")
    group.addoption("--audit-csv", help="Explicit final window CSV; never selected implicitly")
    group.addoption("--audit-features", help="JSON array of actual model input columns")
    group.addoption("--audit-evidence", help="JSON evidence bundle described in README.md")
    group.addoption("--audit-seed", type=int, default=20261019)
    group.addoption("--audit-require-evidence", action="store_true",
                    help="Fail rather than skip any unavailable dataset or measurement")


def unavailable(request, reason):
    if request.config.getoption("--audit-require-evidence"):
        pytest.fail("UNVERIFIED: " + reason)
    pytest.skip("UNVERIFIED: " + reason)


@pytest.fixture(scope="session")
def audit_dataset(request):
    path = request.config.getoption("--audit-csv")
    if not path:
        unavailable(request, "final CSV not supplied (--audit-csv)")
    with Path(path).open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        assert reader.fieldnames and len(reader.fieldnames) == len(set(reader.fieldnames)), "C5: duplicate header"
        rows = list(reader)
    assert rows and all(None not in row and None not in row.values() for row in rows), "C1/C5: ragged or empty CSV"
    assert all("label" in row for row in rows), "D: missing labels"
    return rows


@pytest.fixture(scope="session")
def feature_columns(request):
    path = request.config.getoption("--audit-features")
    if not path:
        unavailable(request, "actual model feature list not supplied (--audit-features)")
    columns = json.loads(Path(path).read_text())
    assert isinstance(columns, list) and columns and all(isinstance(name, str) for name in columns)
    assert len(columns) == len(set(columns)), "D1: duplicate feature columns"
    return columns


@pytest.fixture(scope="session")
def audit_evidence(request):
    path = request.config.getoption("--audit-evidence")
    if not path:
        unavailable(request, "measurement bundle not supplied (--audit-evidence)")
    bundle = json.loads(Path(path).read_text())
    assert isinstance(bundle, dict)
    bundle["_base"] = str(Path(path).resolve().parent)
    return bundle


@pytest.fixture
def collector(monkeypatch):
    listener = types.ModuleType("listen_cpu_reports")
    listener.collect_indexes_on_iface = lambda *args, **kwargs: []
    monkeypatch.setitem(sys.modules, "listen_cpu_reports", listener)
    original_path = list(sys.path)
    spec = importlib.util.spec_from_file_location("audit_collector", ROOT / "hybrid_collector.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = original_path
    return module


@pytest.fixture
def source_module(monkeypatch):
    def load(relative):
        monkeypatch.syspath_prepend(str((ROOT / relative).parent))
        spec = importlib.util.spec_from_file_location("audit_source", ROOT / relative)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return load