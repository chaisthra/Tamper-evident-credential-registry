"""Demo helper: copy a file and flip one bit of one byte, to show a forged copy fails verification."""  # Purpose.

import argparse  # Command-line arguments.
from pathlib import Path  # File paths.

FLIP_MASK = 0x01  # XOR with 1 changes only the lowest bit: the smallest possible edit.


def tamper(src: Path, dst: Path, offset: int) -> int:  # Does the edit.
    """Write src to dst with the byte at `offset` altered (middle of file if offset < 0). Returns the offset used."""  # Contract.
    data = bytearray(src.read_bytes())  # Mutable copy of the original bytes.
    index = len(data) // 2 if offset < 0 else offset  # Default: middle of the file.
    data[index] ^= FLIP_MASK  # Flip one bit.
    dst.parent.mkdir(parents=True, exist_ok=True)  # Make sure the output folder exists.
    dst.write_bytes(bytes(data))  # Save the forged copy.
    return index  # Report where the change was made.


def main() -> None:  # Entry point.
    """Parse arguments and run tamper(); prints what was changed."""  # Contract.
    parser = argparse.ArgumentParser(description="Flip one byte of a file")  # Simple parser.
    parser.add_argument("src", type=Path)  # Original file.
    parser.add_argument("dst", type=Path)  # Where to write the forged copy.
    parser.add_argument("--offset", type=int, default=-1)  # Which byte; -1 means "middle".
    args = parser.parse_args()  # Read sys.argv.
    index = tamper(args.src, args.dst, args.offset)  # Do it.
    print(f"flipped one bit of byte {index}: {args.src} -> {args.dst}")  # Tell the audience what happened.


if __name__ == "__main__":  # Only when run directly.
    main()  # Run.
