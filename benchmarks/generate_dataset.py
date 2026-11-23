from argparse import ArgumentParser
from pathlib import Path

from sovereigngate.benchmark import BenchmarkError, generate_dataset, write_dataset


def main() -> None:
    parser = ArgumentParser(
        description="Generate the deterministic, synthetic eu-synthetic-v1 JSONL dataset."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/eu-synthetic-v1.jsonl"),
        help="Output JSONL path (default: benchmarks/eu-synthetic-v1.jsonl).",
    )
    arguments = parser.parse_args()
    try:
        samples = generate_dataset()
        write_dataset(arguments.output, samples)
    except BenchmarkError:
        parser.error("Unable to generate or write the synthetic benchmark dataset.")
    print("Generated 1,000 synthetic eu-synthetic-v1 records.")


if __name__ == "__main__":
    main()
