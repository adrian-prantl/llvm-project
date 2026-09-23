"""
Run a compiler command that links a binary and codesign the result.

Usage: codesign_wrapper.py --codesign "<codesign command>" -- <compiler> <args>

This backs the %link and %linkxx substitutions and mirrors what Makefile.rules
does for the API tests: after a successful link, the output is signed with
"$(CODESIGN) -s -", so that inferiors get the entitlements required to debug
them.
"""

import argparse
import shlex
import subprocess
import sys


def get_output(args):
    """Returns the output file named by -o, or None if there is none."""
    output = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-o" and i + 1 < len(args):
            output = args[i + 1]
            i += 1
        elif arg.startswith("-o") and len(arg) > 2:
            output = arg[2:]
        i += 1
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--codesign", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing compiler command")

    output = get_output(command[1:])
    if output is None or output == "-":
        parser.error("%link requires an output file (-o <file>)")

    result = subprocess.run(command)
    if result.returncode != 0:
        return result.returncode

    return subprocess.run(shlex.split(args.codesign) + ["-s", "-", output]).returncode


if __name__ == "__main__":
    sys.exit(main())
