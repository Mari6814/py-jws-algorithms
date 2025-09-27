"""Main entry point for the jws_algorithms CLI when run as a module."""

import sys
from pathlib import Path

from .cli import generate_keys, sign, verify


def main() -> None:
    """Main entry point for the CLI when run as a module."""
    if len(sys.argv) < 2:
        print("Usage: python -m jws_algorithms.cli <command>")
        print("Commands: gen-keys, sign, verify")
        print("Or use: uv run jws-gen-keys, uv run jws-sign, uv run jws-verify")
        sys.exit(1)

    command = sys.argv[1]
    # Remove the command from argv so the individual functions can parse their arguments
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    if command in ("gen-keys", "generate-keys"):
        generate_keys()
    elif command == "sign":
        sign()
    elif command == "verify":
        verify()
    else:
        print(f"Error: Unknown command '{command}'")
        print("Available commands: gen-keys, sign, verify")
        sys.exit(1)


if __name__ == "__main__":
    main()
