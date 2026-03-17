add_executable(veh-debug-adapter
    main.cpp
    dap_server.cpp
    transport.cpp
    injector.cpp
    pipe_client.cpp
    disassembler.cpp
    zydis_disassembler.cpp
    symbol_engine.cpp
)

target_link_libraries(veh-debug-adapter PRIVATE
    veh_common
    nlohmann_json
    Zydis
    ws2_32
    dbghelp
)

target_compile_definitions(veh-debug-adapter PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# DAP 파일 트레이스 로그 (C:\tmp\veh_dap_trace.log)
option(VEH_DAP_TRACE "Enable DAP file-based trace logging" OFF)
if(VEH_DAP_TRACE)
    target_compile_definitions(veh-debug-adapter PRIVATE VEH_DAP_TRACE)
endif()
