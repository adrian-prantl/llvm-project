//===-- ReflectionContextEmbedded.cpp -------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#include "SwiftLanguageRuntimeImpl.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "swift/Demangling/Demangle.h"

#ifndef LLDB_HAVE_SWIFT_COMPILER
#include "swift/SwiftRemoteMirror/SwiftRemoteMirror.h"
#include <memory.h>
#endif

using namespace lldb;
using namespace lldb_private;

#ifdef LLDB_HAVE_SWIFT_COMPILER

namespace {

/// An implementation of the generic ReflectionContextInterface that
/// instantiates the Swift compiler's ReflectionContext template with target
/// pointer width, either 32-bit or 64-bit pointers, and ObjC interoperability
/// enabled or disabled.
template <typename ReflectionContext>
class ReflectionContextEmbedded
    : public SwiftLanguageRuntimeImpl::ReflectionContextInterface {
  ReflectionContext m_reflection_ctx;
  swift::reflection::TypeConverter m_type_converter;

public:
  ReflectionContextEmbedded(
      std::shared_ptr<swift::reflection::MemoryReader> reader,
      SwiftMetadataCache *swift_metadata_cache)
      : m_reflection_ctx(reader, swift_metadata_cache),
        m_type_converter(m_reflection_ctx.getBuilder()) {}

  llvm::Optional<uint32_t> AddImage(
      llvm::function_ref<std::pair<swift::remote::RemoteRef<void>, uint64_t>(
          swift::ReflectionSectionKind)>
          find_section,
      llvm::SmallVector<llvm::StringRef, 1> likely_module_names) override {
    return m_reflection_ctx.addImage(find_section, likely_module_names);
  }

  llvm::Optional<uint32_t>
  AddImage(swift::remote::RemoteAddress image_start,
           llvm::SmallVector<llvm::StringRef, 1> likely_module_names) override {
    return m_reflection_ctx.addImage(image_start, likely_module_names);
  }

  llvm::Optional<uint32_t> ReadELF(
      swift::remote::RemoteAddress ImageStart,
      llvm::Optional<llvm::sys::MemoryBlock> FileBuffer,
      llvm::SmallVector<llvm::StringRef, 1> likely_module_names = {}) override {
    return m_reflection_ctx.readELF(ImageStart, FileBuffer,
                                    likely_module_names);
  }

  const swift::reflection::TypeRef *
  GetTypeRefOrNull(StringRef mangled_type_name) override {
    swift::Demangle::Demangler dem;
    swift::Demangle::NodePointer node = dem.demangleSymbol(mangled_type_name);
    const swift::reflection::TypeRef *type_ref = GetTypeRefOrNull(dem, node);
    if (!type_ref)
      LLDB_LOG(GetLog(LLDBLog::Types), "Could not find typeref for type: {0}",
               mangled_type_name);
    return type_ref;
  }

  virtual const swift::reflection::TypeRef *
  GetTypeRefOrNull(swift::Demangle::Demangler &dem,
                   swift::Demangle::NodePointer node) override {
    auto type_ref_or_err =
        swift::Demangle::decodeMangledType(m_reflection_ctx.getBuilder(), node);
    if (type_ref_or_err.isError()) {
      LLDB_LOG(GetLog(LLDBLog::Types),
               "Could not find typeref: decode mangled type failed. Error: {0}",
               type_ref_or_err.getError()->copyErrorString());
      return nullptr;
    }
    return type_ref_or_err.getType();
  }

  const swift::reflection::TypeInfo *
  GetClassInstanceTypeInfo(const swift::reflection::TypeRef *type_ref,
                           swift::remote::TypeInfoProvider *provider) override {
    if (!type_ref)
      return nullptr;
    return m_type_converter.getClassInstanceTypeInfo(type_ref, 0, provider);
  }

  const swift::reflection::TypeInfo *
  GetTypeInfo(const swift::reflection::TypeRef *type_ref,
              swift::remote::TypeInfoProvider *provider) override {
    if (!type_ref)
      return nullptr;

    Log *log(GetLog(LLDBLog::Types));
    if (log && log->GetVerbose()) {
      std::stringstream ss;
      type_ref->dump(ss);
      LLDB_LOGF(log,
                "[TargetReflectionContext::getTypeInfo] Getting "
                "type info for typeref:\n%s",
                ss.str().c_str());
    }

    auto type_info = m_reflection_ctx.getTypeInfo(type_ref, provider);
    if (log && !type_info) {
      std::stringstream ss;
      type_ref->dump(ss);
      LLDB_LOGF(log,
                "[TargetReflectionContext::getTypeInfo] Could not get "
                "type info for typeref:\n%s",
                ss.str().c_str());
    }

    if (type_info && log && log->GetVerbose()) {
      std::stringstream ss;
      type_info->dump(ss);
      log->Printf("[TargetReflectionContext::getTypeInfo] Found "
                  "type info:\n%s",
                  ss.str().c_str());
    }
    return type_info;
  }

  swift::reflection::MemoryReader &GetReader() override {
    return m_reflection_ctx.getReader();
  }

  const swift::reflection::TypeRef *
  LookupSuperclass(const swift::reflection::TypeRef *tr) override {
    return m_reflection_ctx.getBuilder().lookupSuperclass(tr);
  }

  bool ForEachSuperClassType(
      swift::remote::TypeInfoProvider *tip, lldb::addr_t pointer,
      std::function<bool(SwiftLanguageRuntimeImpl::SuperClassType)> fn)
      override {
    // Guard against faulty self-referential metadata.
    unsigned limit = 256;
    auto md_ptr = m_reflection_ctx.readMetadataFromInstance(pointer);
    if (!md_ptr)
      return false;

    // Class object.
    while (md_ptr && *md_ptr && --limit) {
      // Reading metadata is potentially expensive since (in a remote
      // debugging scenario it may even incur network traffic) so we
      // just return closures that the caller can use to query details
      // if they need them.'
      auto metadata = *md_ptr;
      if (fn({[=]() -> const swift::reflection::RecordTypeInfo * {
                auto *ti = m_reflection_ctx.getMetadataTypeInfo(metadata, tip);
                return llvm::dyn_cast_or_null<
                    swift::reflection::RecordTypeInfo>(ti);
              },
              [=]() -> const swift::reflection::TypeRef * {
                return m_reflection_ctx.readTypeFromMetadata(metadata);
              }}))
        return true;

      // Continue with the base class.
      md_ptr = m_reflection_ctx.readSuperClassFromClassMetadata(metadata);
    }
    return false;
  }

  llvm::Optional<std::pair<const swift::reflection::TypeRef *,
                           swift::reflection::RemoteAddress>>
  ProjectExistentialAndUnwrapClass(
      swift::reflection::RemoteAddress existential_address,
      const swift::reflection::TypeRef &existential_tr) override {
    return m_reflection_ctx.projectExistentialAndUnwrapClass(
        existential_address, existential_tr);
  }

  const swift::reflection::TypeRef *
  ReadTypeFromMetadata(lldb::addr_t metadata_address,
                       bool skip_artificial_subclasses) override {
    return m_reflection_ctx.readTypeFromMetadata(metadata_address,
                                                 skip_artificial_subclasses);
  }

  const swift::reflection::TypeRef *
  ReadTypeFromInstance(lldb::addr_t instance_address,
                       bool skip_artificial_subclasses) override {
    auto metadata_address =
        m_reflection_ctx.readMetadataFromInstance(instance_address);
    if (!metadata_address) {
      LLDB_LOGF(GetLog(LLDBLog::Types),
                "could not read heap metadata for object at %llu\n",
                instance_address);
      return nullptr;
    }

    return m_reflection_ctx.readTypeFromMetadata(*metadata_address,
                                                 skip_artificial_subclasses);
  }

  llvm::Optional<bool> IsValueInlinedInExistentialContainer(
      swift::remote::RemoteAddress existential_address) override {
    return m_reflection_ctx.isValueInlinedInExistentialContainer(
        existential_address);
  }

  const swift::reflection::TypeRef *ApplySubstitutions(
      const swift::reflection::TypeRef *type_ref,
      swift::reflection::GenericArgumentMap substitutions) override{
    return type_ref->subst(m_reflection_ctx.getBuilder(), substitutions);
  }

  swift::remote::RemoteAbsolutePointer StripSignedPointer(
      swift::remote::RemoteAbsolutePointer pointer) override {
    return m_reflection_ctx.stripSignedPointer(pointer);
  }
};

} // namespace

namespace lldb_private {
std::unique_ptr<SwiftLanguageRuntimeImpl::ReflectionContextInterface>
SwiftLanguageRuntimeImpl::ReflectionContextInterface::CreateReflectionContext(
    uint8_t ptr_size, std::shared_ptr<swift::remote::MemoryReader> reader,
    bool objc_interop, SwiftMetadataCache *swift_metadata_cache) {
  using ReflectionContext32ObjCInterop =
      ReflectionContextEmbedded<swift::reflection::ReflectionContext<
          swift::External<swift::WithObjCInterop<swift::RuntimeTarget<4>>>>>;
  using ReflectionContext32NoObjCInterop =
      ReflectionContextEmbedded<swift::reflection::ReflectionContext<
          swift::External<swift::NoObjCInterop<swift::RuntimeTarget<4>>>>>;
  using ReflectionContext64ObjCInterop =
      ReflectionContextEmbedded<swift::reflection::ReflectionContext<
          swift::External<swift::WithObjCInterop<swift::RuntimeTarget<8>>>>>;
  using ReflectionContext64NoObjCInterop =
      ReflectionContextEmbedded<swift::reflection::ReflectionContext<
          swift::External<swift::NoObjCInterop<swift::RuntimeTarget<8>>>>>;
  if (ptr_size == 4) {
    if (objc_interop)
      return std::make_unique<ReflectionContext32ObjCInterop>(
          reader, swift_metadata_cache);
    return std::make_unique<ReflectionContext32NoObjCInterop>(
        reader, swift_metadata_cache);
  }
  if (ptr_size == 8) {
    if (objc_interop)
      return std::make_unique<ReflectionContext64ObjCInterop>(
          reader, swift_metadata_cache);
    return std::make_unique<ReflectionContext64NoObjCInterop>(
        reader, swift_metadata_cache);
  }
  return {};
}
}

#else

namespace {

/// An implementation of the generic ReflectionContextInterface that
/// uses the less capable C interface to link against the system libraries.
class ReflectionContextSystem
    : public SwiftLanguageRuntimeImpl::ReflectionContextInterface {
  std::shared_ptr<swift::reflection::MemoryReader> m_reader;
  SwiftReflectionContextRef m_reflection_ctx;
  llvm::BumpPtrAllocator m_pool;

public:
  ReflectionContextSystem(
      uint8_t ptr_size, std::shared_ptr<swift::reflection::MemoryReader> reader,
      SwiftMetadataCache *swift_metadata_cache)
      : m_reader(reader) {
    assert(m_reader);

    m_reflection_ctx = swift_reflection_createReflectionContext(
        m_reader.get(), ptr_size,
        [](void *reader_context, const void *bytes, void *context) {
          free(const_cast<void*>(bytes));
        },
        [](void *reader, uint64_t address, uint64_t size,
           void **outFreeContext) -> const void * {
          uint8_t *dest = (uint8_t *)malloc(size);
          if (static_cast<LLDBMemoryReader *>(reader)->readBytes(
                  swift::reflection::RemoteAddress(address), dest, size))
            return dest;
          free(dest);
          return nullptr;
        },
        [](void *reader, uint64_t address) -> uint64_t {
          std::string s;
          if (static_cast<LLDBMemoryReader *>(reader)->readString(
                  swift::reflection::RemoteAddress(address), s))
            return s.size();
          return 0;
        },
        [](void *reader, const char *name, uint64_t name_length) -> uint64_t {
          return static_cast<LLDBMemoryReader *>(reader)
              ->getSymbolAddress(std::string(name, name_length))
              .getAddressData();
        });
  }

  ~ReflectionContextSystem() {
    swift_reflection_destroyReflectionContext(m_reflection_ctx);
  }
  llvm::Optional<uint32_t> AddImage(
      llvm::function_ref<std::pair<swift::remote::RemoteRef<void>, uint64_t>(
          swift::ReflectionSectionKind)>
          find_section,
      llvm::SmallVector<llvm::StringRef, 1> likely_module_names) override {
    return {};
  }

  llvm::Optional<uint32_t>
  AddImage(swift::remote::RemoteAddress image_start,
           llvm::SmallVector<llvm::StringRef, 1> likely_module_names) override {
    return {};
  }

  llvm::Optional<uint32_t> ReadELF(
      swift::remote::RemoteAddress ImageStart,
      llvm::Optional<llvm::sys::MemoryBlock> FileBuffer,
      llvm::SmallVector<llvm::StringRef, 1> likely_module_names = {}) override {
    return {};
  }

  const swift::reflection::TypeRef *
  GetTypeRefOrNull(StringRef mangled_type_name) override {
    swift_typeref_t ctype_ref = swift_reflection_typeRefForMangledTypeName(
        m_reflection_ctx, mangled_type_name.data(), mangled_type_name.size());
    auto *type_ref = reinterpret_cast<swift::reflection::TypeRef *>(ctype_ref);
    if (!type_ref)
      LLDB_LOG(GetLog(LLDBLog::Types), "Could not find typeref for type: {0}",
               mangled_type_name);
    return type_ref;
  }

  virtual const swift::reflection::TypeRef *
  GetTypeRefOrNull(swift::Demangle::Demangler &dem,
                   swift::Demangle::NodePointer node) override {
    auto mangling = swift::Demangle::mangleNode(node);
    if (!mangling.isSuccess())
      return nullptr;
    std::string remangled = mangling.result();
    return GetTypeRefOrNull(remangled);
  }

  const swift::reflection::TypeInfo *
  GetClassInstanceTypeInfo(const swift::reflection::TypeRef *type_ref,
                           swift::remote::TypeInfoProvider *provider) override {
    if (!type_ref)
      return nullptr;

    swift_typeinfo_t info = swift_reflection_infoForTypeRef(
        m_reflection_ctx, reinterpret_cast<swift_typeref_t>(type_ref));
    switch (info.Kind) {
    case SWIFT_STRUCT: {
      const std::vector<swift::reflection::FieldInfo> fields;
      return new (m_pool) swift::reflection::RecordTypeInfo(
          info.Size, info.Alignment, info.Stride, 0, false,
          swift::reflection::RecordKind::Struct, fields);
    }
    default:
      LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", info.Kind);
      return nullptr;
    }
  }

  const swift::reflection::TypeInfo *
  GetTypeInfo(const swift::reflection::TypeRef *type_ref,
              swift::remote::TypeInfoProvider *provider) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return nullptr;
  }

  swift::reflection::MemoryReader &GetReader() override {
    return *m_reader;
  }

  const swift::reflection::TypeRef *
  LookupSuperclass(const swift::reflection::TypeRef *tr) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return nullptr;
  }

  bool ForEachSuperClassType(
      swift::remote::TypeInfoProvider *tip, lldb::addr_t pointer,
      std::function<bool(SwiftLanguageRuntimeImpl::SuperClassType)> fn)
      override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return false;
  }

  llvm::Optional<std::pair<const swift::reflection::TypeRef *,
                           swift::reflection::RemoteAddress>>
  ProjectExistentialAndUnwrapClass(
      swift::reflection::RemoteAddress existential_address,
      const swift::reflection::TypeRef &existential_tr) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return {};
  }

  const swift::reflection::TypeRef *
  ReadTypeFromMetadata(lldb::addr_t metadata_address,
                       bool skip_artificial_subclasses) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return nullptr;
  }

  const swift::reflection::TypeRef *
  ReadTypeFromInstance(lldb::addr_t instance_address,
                       bool skip_artificial_subclasses) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return nullptr;
  }

  llvm::Optional<bool> IsValueInlinedInExistentialContainer(
      swift::remote::RemoteAddress existential_address) override {
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return {};
  }

  const swift::reflection::TypeRef *ApplySubstitutions(
      const swift::reflection::TypeRef *type_ref,
      swift::reflection::GenericArgumentMap substitutions) override{
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return nullptr;
  }

  swift::remote::RemoteAbsolutePointer
  StripSignedPointer(swift::remote::RemoteAbsolutePointer pointer) override {
    // Not supported by API.
    LLDB_LOG(GetLog(LLDBLog::Types), "{0} is not implemented", LLVM_PRETTY_FUNCTION);
    return pointer;
  }
};

} // namespace

namespace lldb_private {
std::unique_ptr<SwiftLanguageRuntimeImpl::ReflectionContextInterface>
SwiftLanguageRuntimeImpl::ReflectionContextInterface::CreateReflectionContext(
    uint8_t ptr_size, std::shared_ptr<swift::remote::MemoryReader> reader,
    bool objc_interop, SwiftMetadataCache *swift_metadata_cache) {
  // This parameter isn't supported by the interface.
  if (!objc_interop)
    return {};

  return std::make_unique<ReflectionContextSystem>(ptr_size, reader,
                                                   swift_metadata_cache);
}

#endif
} // namespace lldb_private
