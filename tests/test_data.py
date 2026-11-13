"""Vendored test data matches the checksums recorded with its source and version."""

import hashlib
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parent / "data"
SOURCES = sorted(p for p in DATA.iterdir() if p.is_dir())
NOT_DATA = {"README.md", "SHA256SUMS", "LICENSE"}


def _manifest(folder: Path) -> dict[str, str]:
    entries = {}
    for line in (folder / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        entries[name.lstrip("*")] = digest
    return entries


@pytest.mark.parametrize("folder", SOURCES, ids=lambda p: p.name)
def test_every_file_is_recorded_and_unchanged(folder):
    assert (folder / "README.md").is_file(), "each source needs a README with its provenance"
    manifest = _manifest(folder)
    files = {p.name for p in folder.iterdir() if p.is_file() and p.name not in NOT_DATA}
    assert files == set(manifest), "SHA256SUMS must list exactly the data files"
    for name, digest in manifest.items():
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == digest, name
