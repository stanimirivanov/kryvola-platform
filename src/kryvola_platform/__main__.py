"""Validate an explicit inventory; missing paths and invalid data fail closed."""

import argparse
from pathlib import Path

from kryvola_platform.inventory import validate_inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    validate_inventory(args.inventory)
    print("Valid foundation inventory: every capability remains unqualified and disabled.")


if __name__ == "__main__":
    main()
