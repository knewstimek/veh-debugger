set(DLL_SOURCES
    dllmain.cpp
    veh_handler.cpp
    breakpoint.cpp
    hw_breakpoint.cpp
    memory.cpp
    threads.cpp
    stack_walk.cpp
    pipe_server.cpp
)

set(DLL_DEFS
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# DLL 이름: 디버거 티 안 나게 위장
# vcruntime_net.dll / vcruntime_net32.dll
set(DLL_OUTPUT_NAME "vcruntime_net")

add_library(veh-debugger SHARED ${DLL_SOURCES})
target_link_libraries(veh-debugger PRIVATE veh_common nlohmann_json dbghelp ntdll delayimp)
target_link_options(veh-debugger PRIVATE "/DELAYLOAD:dbghelp.dll")
target_compile_definitions(veh-debugger PRIVATE ${DLL_DEFS} VEH_64BIT)
set_target_properties(veh-debugger PROPERTIES OUTPUT_NAME ${DLL_OUTPUT_NAME})

# 32비트 빌드 (별도 cmake -A Win32 호출)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(veh-debugger PROPERTIES OUTPUT_NAME "${DLL_OUTPUT_NAME}32")
    target_compile_definitions(veh-debugger PRIVATE VEH_32BIT)
endif()
