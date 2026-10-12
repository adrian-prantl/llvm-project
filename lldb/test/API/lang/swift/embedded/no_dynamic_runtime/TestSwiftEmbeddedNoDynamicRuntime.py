import lldb
from lldbsuite.test.lldbtest import *
from lldbsuite.test.decorators import *
import lldbsuite.test.lldbutil as lldbutil


class TestSwiftEmbeddedNoDynamicRuntime(TestBase):
    @skipEmbeddedSwiftOnWindows
    @skipUnlessEmbeddedSwift
    @swiftTest
    def test(self):
        """Test that LLDB doesn't load the dynamic Swift runtime into an
        Embedded Swift process."""
        self.build()
        # Validation consults a non-embedded expression context, which imports
        # the dynamic Swift standard library.
        self.runCmd("settings set symbols.swift-validate-typesystem true")
        target, _, _, _ = lldbutil.run_to_source_breakpoint(
            self, "break here", lldb.SBFileSpec("main.swift")
        )

        self.expect("frame variable number", substrs=["42"])
        self.expect("expression number", substrs=["42"])

        for module in target.module_iter():
            self.assertNotIn(
                "swiftCore",
                module.GetFileSpec().GetFilename(),
                "dynamic Swift runtime loaded into an Embedded Swift process",
            )
