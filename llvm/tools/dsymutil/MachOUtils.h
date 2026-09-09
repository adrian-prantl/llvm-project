//===-- MachOUtils.h - Mach-o specific helpers for dsymutil  --------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TOOLS_DSYMUTIL_MACHOUTILS_H
#define LLVM_TOOLS_DSYMUTIL_MACHOUTILS_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"

#include <string>

namespace llvm {
class MCStreamer;
class raw_fd_ostream;
namespace dsymutil {
class DebugMap;
struct LinkOptions;
namespace MachOUtils {

struct ArchAndFile {
  std::string Arch;
  std::string Path;
  int FD = -1;

  llvm::Error createTempFile();
  llvm::StringRef getPath() const;
  int getFD() const;

  ArchAndFile(StringRef Arch) : Arch(std::string(Arch)) {}
  ArchAndFile(ArchAndFile &&A) = default;
  ArchAndFile &operator=(ArchAndFile &&A) = default;
  ~ArchAndFile();
};

struct DwarfRelocationApplicationInfo {
  // The position in the stream that should be patched, starting from the
  // Dwarf's segment file address.
  uint64_t AddressFromDwarfStart;
  int32_t Value;
  // If we should subtract the Dwarf segment's VM address from value before
  // writing it.
  bool ShouldSubtractDwarfVM;

  DwarfRelocationApplicationInfo(uint64_t AddressFromDwarfVM, uint32_t Value,
                                 bool ShouldSubtractDwarfVM)
      : AddressFromDwarfStart(AddressFromDwarfVM), Value(Value),
        ShouldSubtractDwarfVM(ShouldSubtractDwarfVM) {}
};

bool generateUniversalBinary(SmallVectorImpl<ArchAndFile> &ArchFiles,
                             StringRef OutputFileName, const LinkOptions &,
                             StringRef SDKPath, bool Fat64 = false);

/// A relocation to attach to the emitted __debug_info. \p Offset is a byte
/// offset into that section, and \p TargetAddress is the address the relocated
/// field refers to, which selects the section the relocation names.
struct DwarfRelocation {
  uint64_t Offset;
  uint64_t TargetAddress;
  unsigned Size;
};

/// Write a relocatable object holding the input binary's sections and symbols
/// plus the linked DWARF, so it stands in for the object files the debug map
/// names. The passed \a MS must be writing Mach-O through a MachObjectWriter.
bool generateRelocatableObject(
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS, const DebugMap &DM,
    MCStreamer &MS, raw_fd_ostream &OutFile,
    ArrayRef<DwarfRelocation> DwarfRelocs);

bool generateDsymCompanion(
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS, const DebugMap &DM,
    MCStreamer &MS, raw_fd_ostream &OutFile,
    const std::vector<MachOUtils::DwarfRelocationApplicationInfo>
        &RelocationsToApply,
    bool AllowSectionHeaderOffsetOverflow);

std::string getArchName(StringRef Arch);
} // namespace MachOUtils
} // namespace dsymutil
} // namespace llvm
#endif // LLVM_TOOLS_DSYMUTIL_MACHOUTILS_H
