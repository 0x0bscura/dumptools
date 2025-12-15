#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys
from datetime import datetime

# ANSI colours
RESET = "\033[0m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
GREY = "\033[90m"
RED = "\033[91m"

# ASCII Art - replace with your design
ASCII_ART = f"""{RED}
▗▄▄▄ ▗▖ ▗▖▗▖  ▗▖▗▄▄▖  ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖
▐▌  █▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌
▐▌  █▐▌ ▐▌▐▌  ▐▌▐▛▀▘  ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌
▐▙▄▄▀▝▚▄▞▘▐▌  ▐▌▐▌   ▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌

{YELLOW}DumpScan - Scan text dumps for strings with live status output
{RED}made by 0bscura with <3{RESET}
"""

def use_colour():
    return sys.stdout.isatty()

def colour(text, c):
    return f"{c}{text}{RESET}" if use_colour() else text

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def scan_file(path, needles, ignore_case, output_file, results):
    found = False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                hay = line.lower() if ignore_case else line
                for needle in needles:
                    if needle in hay:
                        msg = (
                            f"\n[{ts()}] "
                            f"{colour('[+]', GREEN)} "
                            f"Found {needle} in {path} (line {line_no}): {line.strip()}"
                        )
                        print(msg)
                        if output_file:
                            output_file.write(f"{path}, {line_no}, {line.strip()}\n")
                        results.append((needle, path, line_no, line.strip()))
                        found = True
    except Exception:
        pass
    return found


def main():
    # Print ASCII art
    print(ASCII_ART)
    
    parser = argparse.ArgumentParser(
        description="Scan text dumps for a string with live status output."
    )
    parser.add_argument("needle", help="String or email to search for")
    parser.add_argument(
        "-f", "--file",
        action="store_true",
        help="Treat needle as a file path containing search strings"
    )
    parser.add_argument(
        "-p", "--path",
        default=".",
        help="Directory to scan recursively (default: current directory)"
    )
    parser.add_argument(
        "-i", "--ignore-case",
        action="store_true",
        help="Case-insensitive search"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save results"
    )

    args = parser.parse_args()

    # Load needles from file if -f flag is set
    if args.file:
        needle_file = Path(args.needle)
        with open(needle_file, "r") as f:
            needles = [line.strip() for line in f if line.strip()]
    else:
        needles = [args.needle]

    if args.ignore_case:
        needles = [n.lower() for n in needles]

    # Print configuration
    print(f"\nNeedles: {needles}")
    print(f"Path: {args.path}")
    print(f"Case-insensitive: {args.ignore_case}")
    print(f"Output file: {args.output or 'None'}\n")

    base = Path(args.path)
    files = [f for f in base.rglob("*.txt") if f.is_file()]
    total = len(files)

    # List all files before scanning
    print(f"[{ts()}] {colour('[*]', YELLOW)} Files to scan ({total}):")
    for file in files:
        print(f"  {colour('→', GREEN)} {file}")
    print()

    output_file = open(args.output, "w") if args.output else None
    results = []

    try:
        for idx, file in enumerate(files, start=1):
            status = (
                f"[{ts()}] "
                f"{colour('[*]', YELLOW)} "
                f"Checking file {idx}/{total}: {file}..."
            )

            sys.stdout.write(status)
            sys.stdout.flush()

            found = scan_file(file, needles, args.ignore_case, output_file, results)

            if not found:
                clear = " " * (len(status) + 10)
                sys.stdout.write("\r" + clear)
                sys.stdout.write(
                    f"\r[{ts()}] "
                    f"{colour('[-]', GREY)} "
                    f"Checking file {idx}/{total}: {file}... Nothing found.\n"
                )
            else:
                sys.stdout.write("\n")
    finally:
        if output_file:
            output_file.close()

    # Print summary
    print(f"\n[{ts()}] {colour('[*]', YELLOW)} Scan Complete!")
    print(f"[{ts()}] {colour('[+]', GREEN)} Total hits: {len(results)}\n")
    
    if results:
        for needle, path, line_no, content in results:
            print(f"  {colour('→', GREEN)} {needle}: {path} (line {line_no})")
            print(f"    {content}\n")

if __name__ == "__main__":
    main()