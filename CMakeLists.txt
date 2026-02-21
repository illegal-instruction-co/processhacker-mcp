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
