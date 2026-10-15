//===-- DLanguage.cpp -----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "DLanguage.h"

#include "lldb/Core/Mangled.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"

#include "llvm/Demangle/Demangle.h"

#include <cstdlib>
#include <string_view>

using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(DLanguage)

/// The mangling scheme that this plugin registered.
static Mangled::ManglingScheme g_d_scheme = Mangled::eManglingSchemeNone;

void DLanguage::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(), "D Language",
                                CreateInstance);
  // A D mangled name begins with `_D`, followed by a numeric length. One known
  // exception is the symbol `_Dmain`. See `SymbolName` and `LName` in
  // https://dlang.org/spec/abi.html#name_mangling
  g_d_scheme =
      Mangled::RegisterManglingScheme({"_D0", "_D1", "_D2", "_D3", "_D4", "_D5",
                                       "_D6", "_D7", "_D8", "_D9", "_Dmain"},
                                      eLanguageTypeD);
}

void DLanguage::Terminate() {
  Mangled::UnregisterManglingScheme(g_d_scheme);
  PluginManager::UnregisterPlugin(CreateInstance);
}

// Static Functions
Language *DLanguage::CreateInstance(lldb::LanguageType language) {
  if (language == eLanguageTypeD)
    return new DLanguage();
  return nullptr;
}

bool DLanguage::IsSourceFile(llvm::StringRef file_path) const {
  const auto suffixes = {".d", ".di"};
  for (auto suffix : suffixes) {
    if (file_path.ends_with_insensitive(suffix))
      return true;
  }
  return false;
}

Language::DemangledName
DLanguage::DemangleSymbol(ConstString mangled,
                          const DemangleOptions &options) const {
  llvm::StringRef M = mangled.GetStringRef();
  char *demangled_cstr = llvm::dlangDemangle(M);

  if (Log *log = GetLog(LLDBLog::Demangle)) {
    if (demangled_cstr && demangled_cstr[0])
      LLDB_LOG(log, "demangled dlang: {0} -> \"{1}\"", M, demangled_cstr);
    else
      LLDB_LOG(log, "demangled dlang: {0} -> error: failed to demangle",
               static_cast<std::string_view>(M));
  }

  DemangledName demangled;
  if (demangled_cstr) {
    demangled.name = demangled_cstr;
    std::free(demangled_cstr);
  }
  return demangled;
}
