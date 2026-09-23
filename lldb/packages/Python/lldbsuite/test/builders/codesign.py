"""
Compute the command used to codesign test binaries on Darwin.

This module is also loaded by the lit configuration of the Shell tests, so it
must not import anything from lldbsuite.
"""

import os
import re

TRIPLE_RE = re.compile(
    r"""^(?P<arch>[a-zA-Z0-9_]+) # arch (required)
        (?:-(?P<vendor>[a-zA-Z0-9_]+))? # vendor (optional)
        (?:-(?P<os>[a-zA-Z_]+)(?P<os_version>[\d.]+)?)? # os + version (optional)
        (?:-(?P<env>[a-zA-Z0-9_]+))? # env/abi (optional)
        $""",
    re.X,
)


def split_triple(triple):
    if m := TRIPLE_RE.match(triple):
        return m.groups()
    return [None] * TRIPLE_RE.groups


def get_codesign_command(triple):
    """Returns the codesign command for binaries built for the given triple."""
    _, _, operating_system, _, env = split_triple(triple)

    if operating_system in [None, "darwin", "macos", "macosx"]:
        entitlements_file = "entitlements-macos.plist"
    else:
        if env == "simulator":
            entitlements_file = "entitlements-simulator.plist"
        else:
            entitlements_file = "entitlements.plist"

    builder_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.dirname(builder_dir)
    entitlements = os.path.join(test_dir, "make", entitlements_file)
    return "codesign --entitlements {}".format(entitlements)
