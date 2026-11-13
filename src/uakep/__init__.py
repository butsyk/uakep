"""uakep: Ukrainian qualified electronic signatures (КЕП, ДСТУ 4145-2002) in pure Python."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("uakep")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
