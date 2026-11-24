from importlib.metadata import PackageNotFoundError, version


def _resolve_version() -> str:
    try:
        return version("sovereigngate-guardrail")
    except PackageNotFoundError:
        return "0.1.0"


__version__: str = _resolve_version()
__all__ = ["__version__"]
