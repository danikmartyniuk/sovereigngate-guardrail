import typer

from sovereigngate import __version__

_REGULATORY_DESCRIPTION = (
    "configurable data-minimization and technical safeguard controls "
    "(supporting GDPR Art. 5(1)(c) & Art. 32)."
)

app = typer.Typer(
    add_completion=False,
    help=f"SovereignGate provides {_REGULATORY_DESCRIPTION}",
    invoke_without_command=True,
    no_args_is_help=True,
)


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version and product description."),
) -> None:
    if version:
        typer.echo(f"SovereignGate {__version__}: {_REGULATORY_DESCRIPTION}")
        raise typer.Exit()
