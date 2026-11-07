"""Smoke test: the package and its subpackages import cleanly."""

import importlib

import pytest

import fwlens

SUBPACKAGES = ["parsers", "db", "analysis", "rag", "agent", "api", "ui"]


def test_version_is_set() -> None:
    assert fwlens.__version__ == "0.1.0"


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_imports(name: str) -> None:
    importlib.import_module(f"fwlens.{name}")
