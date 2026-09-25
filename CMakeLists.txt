cmake_minimum_required(VERSION 3.20)
project(VEHDebugger VERSION 1.1.18 LANGUAGES CXX)

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

# asmjit + asmtk text assembler (vendored, x86 back end only; see third_party/asmjit/VENDORED.txt)
file(GLOB ASMTK_SOURCES
    ${CMAKE_SOURCE_DIR}/third_party/asmjit/asmjit-src/asmjit/core/*.cpp
    ${CMAKE_SOURCE_DIR}/third_party/asmjit/asmjit-src/asmjit/x86/*.cpp
    ${CMAKE_SOURCE_DIR}/third_party/asmjit/asmjit-src/asmjit/support/*.cpp
    ${CMAKE_SOURCE_DIR}/third_party/asmtk/asmtk-src/src/asmtk/*.cpp)
add_library(asmtk STATIC ${ASMTK_SOURCES})
target_include_directories(asmtk PUBLIC
    ${CMAKE_SOURCE_DIR}/third_party/asmjit/asmjit-src
    ${CMAKE_SOURCE_DIR}/third_party/asmtk/asmtk-src/src)
target_compile_definitions(asmtk PUBLIC ASMJIT_STATIC ASMTK_STATIC ASMJIT_NO_AARCH64 ASMJIT_NO_JIT
    ASMJIT_NO_BUILDER ASMJIT_NO_COMPILER ASMJIT_NO_UJIT ASMJIT_NO_LOGGING)

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
