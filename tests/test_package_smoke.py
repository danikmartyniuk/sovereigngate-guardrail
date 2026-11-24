from importlib.metadata import PackageNotFoundError, version

import pytest
from typer.testing import CliRunner

import sovereigngate
from sovereigngate import __version__
from sovereigngate.cli import app


def test_package_import_exposes_version() -> None:
    assert __version__ == version("sovereigngate-guardrail")


def test_package_version_falls_back_when_distribution_metadata_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_distribution(distribution_name: str) -> str:
        raise PackageNotFoundError(distribution_name)

    monkeypatch.setattr(sovereigngate, "version", missing_distribution)

    assert sovereigngate._resolve_version() == "0.1.0"


def test_cli_version_displays_bounded_product_description() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"SovereignGate {__version__}" in result.stdout
    assert "configurable data-minimization and technical safeguard controls" in result.stdout
