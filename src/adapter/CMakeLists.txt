add_executable(veh-debug-adapter
    main.cpp
    dap_server.cpp
    transport.cpp
    injector.cpp
    pipe_client.cpp
    disassembler.cpp
    zydis_disassembler.cpp
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
