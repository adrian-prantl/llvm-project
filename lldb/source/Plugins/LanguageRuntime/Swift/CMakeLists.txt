if(NOT LLDB_HAVE_SWIFT_COMPILER)
  if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(SWIFT_REMOTE_MIRROR "/usr/lib/swift/libswiftRemoteMirror.dylib")
  endif()
endif()

add_lldb_library(lldbPluginSwiftLanguageRuntime PLUGIN
  LLDBMemoryReader.cpp
  ReflectionContext.cpp
  SwiftLanguageRuntime.cpp
  SwiftLanguageRuntimeDynamicTypeResolution.cpp
  SwiftLanguageRuntimeNames.cpp
  SwiftLanguageRuntimeRemoteAST.cpp
  SwiftMetadataCache.cpp

  LINK_LIBS
    ${SWIFT_AST}
    ${SWIFT_BASIC}
    ${SWIFT_REMOTE_AST}
    ${SWIFT_REMOTE_INSPECTION}
    ${SWIFT_REMOTE_MIRROR}

    "swiftDemangle"
    lldbCore
    lldbExpression
    lldbInterpreter
    lldbTarget
    lldbUtility
    lldbPluginExpressionParserClang
    lldbPluginProcessUtility
    lldbPluginSwiftLanguage
)
