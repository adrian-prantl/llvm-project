//===-- llvm/BinaryFormat/Swift.h ---Swift Constants-------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//

#ifndef LLVM_BINARYFORMAT_SWIFT_H
#define LLVM_BINARYFORMAT_SWIFT_H

#include <llvm/ADT/StringRef.h>
#include <llvm/Support/ErrorHandling.h>
#include <Optional>

namespace llvm {
namespace binaryformat {

enum Swift5ReflectionSectionKind {
#define HANDLE_SWIFT_SECTION(KIND, MACHO, ELF, COFF) KIND,
#include "llvm/BinaryFormat/Swift.def"
#undef HANDLE_SWIFT_SECTION
  unknown,
  last = unknown
};
} // end of namespace binaryformat
} // end of namespace llvm

/// Abstract base class responsible for providing the correct reflection section
/// string identifier for a given object file type (Mach-O, ELF, COFF).
class SwiftObjectFileFormat {
public:
  virtual ~SwiftObjectFileFormat() {}
  virtual llvm::StringRef
  getSectionName(llvm::binaryformat::Swift5ReflectionSectionKind section) = 0;
  virtual std::optional<llvm::StringRef> getSegmentName() {
    return {};
  }
  /// Get the name of the segment in the symbol rich binary that may contain
  /// Swift metadata.
  virtual std::optional<llvm::StringRef> getSymbolRichSegmentName() {
    return {};
  }
  /// Predicate to identify if the named section can contain reflection data.
  virtual bool sectionContainsReflectionData(llvm::StringRef sectionName) = 0;
};

/// Responsible for providing the Mach-O reflection section identifiers.
class SwiftObjectFileFormatMachO : public SwiftObjectFileFormat {
public:
  llvm::StringRef getSectionName(
      llvm::binaryformat::Swift5ReflectionSectionKind section) override {
    switch (section) {
#define HANDLE_SWIFT_SECTION(KIND, MACHO, ELF, COFF)                           \
  case llvm::binaryformat::KIND:                                               \
    return MACHO;
#include "llvm/BinaryFormat/Swift.def"
#undef HANDLE_SWIFT_SECTION
    case llvm::binaryformat::unknown:
      return {};
    }
    llvm_unreachable("Section type not found.");
  }

  std::optional<llvm::StringRef> getSegmentName() override {
    return {"__TEXT"};
  }

  std::optional<llvm::StringRef> getSymbolRichSegmentName() override {
    return {"__DWARF"};
  }

  bool sectionContainsReflectionData(llvm::StringRef sectionName) override {
    return sectionName.startswith("__swift5_") || sectionName == "__const";
  }
};

/// Responsible for providing the ELF reflection section identifiers.
class SwiftObjectFileFormatELF : public SwiftObjectFileFormat {
public:
  llvm::StringRef getSectionName(
      llvm::binaryformat::Swift5ReflectionSectionKind section) override {
    switch (section) {
#define HANDLE_SWIFT_SECTION(KIND, MACHO, ELF, COFF)                           \
  case llvm::binaryformat::KIND:                                               \
    return ELF;
#include "llvm/BinaryFormat/Swift.def"
#undef HANDLE_SWIFT_SECTION
    case llvm::binaryformat::unknown:
      return {};
    }
    llvm_unreachable("Section type not found.");
  }

  bool sectionContainsReflectionData(llvm::StringRef sectionName) override {
    return sectionName.startswith("swift5_");
  }
};

/// Responsible for providing the COFF reflection section identifiers
class SwiftObjectFileFormatCOFF : public SwiftObjectFileFormat {
public:
  llvm::StringRef getSectionName(
      llvm::binaryformat::Swift5ReflectionSectionKind section) override {
    switch (section) {
#define HANDLE_SWIFT_SECTION(KIND, MACHO, ELF, COFF)                           \
  case llvm::binaryformat::KIND:                                               \
    return COFF;
#include "llvm/BinaryFormat/Swift.def"
#undef HANDLE_SWIFT_SECTION
    case llvm::binaryformat::unknown:
      return {};
    }
    llvm_unreachable("Section type not found.");
  }

  bool sectionContainsReflectionData(llvm::StringRef sectionName) override {
    return sectionName.startswith(".sw5");
  }
};

#endif
