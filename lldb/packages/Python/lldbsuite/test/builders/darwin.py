import os
import subprocess

from .builder import Builder
from .codesign import get_codesign_command
from lldbsuite.test import configuration
import lldbsuite.test.lldbutil as lldbutil


class BuilderDarwin(Builder):
    def getExtraMakeArgs(self):
        """
        Helper function to return extra argumentsfor the make system. This
        method is meant to be overridden by platform specific builders.
        """
        args = dict()

        if configuration.dsymutil:
            args["DSYMUTIL"] = configuration.dsymutil

        if configuration.apple_sdk and "internal" in configuration.apple_sdk:
            sdk_root = lldbutil.get_xcode_sdk_root(configuration.apple_sdk)
            if sdk_root:
                private_frameworks = os.path.join(
                    sdk_root, "System", "Library", "PrivateFrameworks"
                )
                args["FRAMEWORK_INCLUDES"] = "-F{}".format(private_frameworks)

        if triple := self.getTriple():
            args["CODESIGN"] = get_codesign_command(triple)

        # Return extra args as a formatted string.
        return ["{}={}".format(key, value) for key, value in args.items()]

    def getArchCFlags(self):
        return []

    def _getDebugInfoArgs(self, debug_info):
        if debug_info == "dsym":
            return ["MAKE_DSYM=YES"]
        return super(BuilderDarwin, self)._getDebugInfoArgs(debug_info)
