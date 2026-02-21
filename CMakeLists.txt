cmake_minimum_required(VERSION 3.20)
project(ProcessHackerMCP VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static -Wl,-Bstatic -lstdc++ -lpthread")
set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")

# nlohmann/json for JSON-RPC
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

include_directories(include)

# Add the main MCP Router Executable
add_executable(ProcessHackerMCP
    src/Main.cpp
    src/McpServer.cpp
)

target_include_directories(ProcessHackerMCP PRIVATE include)
target_link_libraries(ProcessHackerMCP PRIVATE nlohmann_json::nlohmann_json)

# Tiny C Compiler (TCC) Local Source Build
set(TCC_SRC_DIR "${CMAKE_SOURCE_DIR}/third_party/tinycc/win32")
set(TCC_BUILD_OUTPUT "${TCC_SRC_DIR}/tcc.exe")
set(TCC_TARGET_DIR "${CMAKE_BINARY_DIR}/tcc")

add_custom_command(
    OUTPUT "${TCC_BUILD_OUTPUT}"
    COMMAND cmd.exe /c "build-tcc.bat -c cl"
    WORKING_DIRECTORY "${TCC_SRC_DIR}"
    COMMENT "Compiling Tiny C Compiler (TCC) from source using MSVC..."
)

add_custom_target(tcc_build ALL
    DEPENDS "${TCC_BUILD_OUTPUT}"
)

# Copy TCC artifacts (executable, libs, includes) to build dir so the router can use it dynamically
add_custom_command(
    TARGET tcc_build POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${TCC_TARGET_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${TCC_SRC_DIR}/tcc.exe" "${TCC_TARGET_DIR}/tcc.exe"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${TCC_SRC_DIR}/libtcc.dll" "${TCC_TARGET_DIR}/libtcc.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${TCC_SRC_DIR}/include" "${TCC_TARGET_DIR}/include"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${TCC_SRC_DIR}/lib" "${TCC_TARGET_DIR}/lib"
    COMMENT "Deploying TCC to ${TCC_TARGET_DIR}..."
)

# Build the Built-in Extension DLL
add_library(builtin_ext SHARED 
    extensions/builtin_ext/BuiltinExt.cpp
)
target_include_directories(builtin_ext PRIVATE include)
target_link_libraries(builtin_ext PRIVATE nlohmann_json::nlohmann_json)
set_target_properties(builtin_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the Sample Extension DLL
add_library(sample_ext SHARED 
    extensions/sample_ext/SampleExt.cpp
)
target_include_directories(sample_ext PRIVATE include)
set_target_properties(sample_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the VehButNot Stealth Extension DLL
add_library(vehbutnot_ext SHARED 
    extensions/vehbutnot_ext/VehButNotExt.cpp
    extensions/vehbutnot_ext/VehButNot.cpp
)
target_include_directories(vehbutnot_ext PRIVATE include extensions/vehbutnot_ext)
target_link_libraries(vehbutnot_ext PRIVATE nlohmann_json::nlohmann_json ntdll)
set_target_properties(vehbutnot_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the Pattern Scanner Extension DLL
add_library(pattern_scanner_ext SHARED 
    extensions/pattern_scanner_ext/PatternScannerExt.cpp
)
target_include_directories(pattern_scanner_ext PRIVATE include)
target_link_libraries(pattern_scanner_ext PRIVATE nlohmann_json::nlohmann_json psapi)
set_target_properties(pattern_scanner_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the Freezer Extension DLL
add_library(freezer_ext SHARED 
    extensions/freezer_ext/FreezerExt.cpp
)
target_include_directories(freezer_ext PRIVATE include)
target_link_libraries(freezer_ext PRIVATE nlohmann_json::nlohmann_json)
set_target_properties(freezer_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the RTTI Dumper Extension DLL
add_library(rtti_dumper_ext SHARED 
    extensions/rtti_dumper_ext/RttiDumperExt.cpp
)
target_include_directories(rtti_dumper_ext PRIVATE include)
target_link_libraries(rtti_dumper_ext PRIVATE nlohmann_json::nlohmann_json psapi)
set_target_properties(rtti_dumper_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the Memory Patcher Extension DLL
add_library(memory_patcher_ext SHARED 
    extensions/memory_patcher_ext/MemoryPatcherExt.cpp
)
target_include_directories(memory_patcher_ext PRIVATE include)
target_link_libraries(memory_patcher_ext PRIVATE nlohmann_json::nlohmann_json psapi)
set_target_properties(memory_patcher_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)

# Build the Auto Compiler Extension DLL
add_library(auto_compiler_ext SHARED 
    extensions/auto_compiler_ext/AutoCompilerExt.cpp
)
target_include_directories(auto_compiler_ext PRIVATE include)
target_link_libraries(auto_compiler_ext PRIVATE nlohmann_json::nlohmann_json psapi)
set_target_properties(auto_compiler_ext PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/extensions"
)
