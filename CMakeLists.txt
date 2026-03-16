cmake_minimum_required(VERSION 3.20)
project(VEHDebugger VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# MSVC 설정
if(MSVC)
    add_compile_options(/utf-8)
    # Static CRT (/MT) — 타겟 프로세스에 vcruntime 의존성 없도록
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Windows only
if(NOT WIN32)
    message(FATAL_ERROR "VEH Debugger is Windows-only")
endif()

# Zydis disassembler (vendored in third_party/)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis/zydis-src)

# nlohmann/json (header-only)
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/third_party)

# Common includes
add_library(veh_common INTERFACE)
target_include_directories(veh_common INTERFACE ${CMAKE_SOURCE_DIR}/src/common)

add_subdirectory(src/dll)
add_subdirectory(src/adapter)
add_subdirectory(src/mcp)
add_subdirectory(test_target)
