from importlib.metadata import version

from typer.testing import CliRunner

from sovereigngate import __version__
from sovereigngate.cli import app


def test_package_import_exposes_version() -> None:
    assert __version__ == version("sovereigngate-guardrail")


def test_cli_version_displays_bounded_product_description() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"SovereignGate {__version__}" in result.stdout
    assert "configurable data-minimization and technical safeguard controls" in result.stdout
