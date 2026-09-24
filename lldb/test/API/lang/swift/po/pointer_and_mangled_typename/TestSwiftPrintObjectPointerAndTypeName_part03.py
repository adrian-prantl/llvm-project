import lldb
import lldbsuite.test.lldbutil as lldbutil
from lldbsuite.test.lldbtest import *
from lldbsuite.test.decorators import *


class TestCase(TestBase):

    def setUp(self):
        TestBase.setUp(self)

        self.log = self.getBuildArtifact("expr.log")
        self.runCmd(f"log enable lldb expr -f {self.log}")
        self.inferior = None

    def _filecheck(self, key):
        self.filecheck_log(self.log, __file__, f"-check-prefix=CHECK-{key}")

    # main.swift runs each scenario in its own scope, in source order, so one
    # process visits them all. Each breakpoint is deleted once hit because
    # some patterns are prefixes of others ("break class-only protocol").
    def run_to(self, bkpt_pattern):
        src = lldb.SBFileSpec("main.swift")
        if not self.inferior:
            target, self.inferior, _, bkpt = lldbutil.run_to_source_breakpoint(
                self, bkpt_pattern, src
            )
            target.BreakpointDelete(bkpt.GetID())
        else:
            threads = lldbutil.continue_to_source_breakpoint(
                self, self.inferior, bkpt_pattern, src
            )
            self.assertEqual(len(threads), 1, f"no stop at {bkpt_pattern}")

    @swiftTest
    @skipEmbeddedSwiftOnWindows
    def test(self):
        self.build()
        self.run_to("break described struct")
        self.expect("po value", substrs=["DescribedStruct"])
        self._filecheck("DESC-STRUCT")
        # CHECK-DESC-STRUCT: stringForPrintObject(UnsafeRawPointer(bitPattern: {{[0-9]+}}), mangledTypeName: "1a15DescribedStructVD")

        self.run_to("break described class")
        self.expect("po value", substrs=["DescribedClass"])
        self._filecheck("DESC-CLASS")
        # CHECK-DESC-CLASS: stringForPrintObject(UnsafeRawPointer(bitPattern: {{[0-9]+}}), mangledTypeName: "1a14DescribedClassCD")

        self.run_to("break described enum")
        self.expect("po value", substrs=["DescribedEnum"])
        self._filecheck("DESC-ENUM")
        # CHECK-DESC-ENUM: stringForPrintObject(UnsafeRawPointer(bitPattern: {{.*}}), mangledTypeName: "1a13DescribedEnumOD")

        self.run_to("break class-only protocol")
        self.expect("po value", substrs=["DescribedConformance"])
        self._filecheck("CLASS-ONLY-PROTOCOL")
        # CHECK-CLASS-ONLY-PROTOCOL: stringForPrintObject(UnsafeRawPointer(bitPattern: {{[0-9]+}}), mangledTypeName: "1a20DescribedConformanceCD")
