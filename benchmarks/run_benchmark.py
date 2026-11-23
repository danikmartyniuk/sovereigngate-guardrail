import sys

from typer.main import get_command

from sovereigngate.cli import app


def main() -> None:
    get_command(app).main(args=["benchmark", *sys.argv[1:]], prog_name="sovereigngate")


if __name__ == "__main__":
    main()
