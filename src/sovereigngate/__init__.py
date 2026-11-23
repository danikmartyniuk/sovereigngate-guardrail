try:
    from ._version import __version__ as _vcs_version
except ImportError:
    _vcs_version = "0+unknown"

__version__: str = _vcs_version
__all__ = ["__version__"]
