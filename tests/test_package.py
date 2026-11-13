"""Package metadata."""

import importlib
import importlib.metadata as md

import uakep


def test_version_comes_from_package_metadata():
    assert uakep.__version__ == md.version("uakep")


def test_version_fallback_outside_an_install(monkeypatch):
    def missing(name):
        raise md.PackageNotFoundError(name)

    monkeypatch.setattr(md, "version", missing)
    try:
        assert importlib.reload(uakep).__version__ == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(uakep)
    assert uakep.__version__ == md.version("uakep")
