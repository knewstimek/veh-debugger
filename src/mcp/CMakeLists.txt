add_executable(veh-mcp-server
	main.cpp
	mcp_server.cpp
	tools_common.cpp
	tools_session.cpp
	session_operations.cpp
	tools_breakpoint.cpp
	tools_inspect.cpp
    analysis_store.cpp
    tools_analysis.cpp
	tools_memory.cpp
	tools_system.cpp
	tools_kernel_debug.cpp
	tools_kd_trace.cpp
	kd_capture_store.cpp
	kd_capture_collect.cpp
	kernel_debug_client.cpp
	tools_trace.cpp
    tools_instrumentation.cpp
	tools_checkpoint.cpp
	tools_orchestration.cpp
	debug_session.cpp
	remote_work.cpp
	batch_executor.cpp
	trace_basic_blocks_tool.cpp
	trace_code_artifact.cpp
	trace_event_artifact.cpp
	trace_output_file.cpp
	assembler.cpp
	installer.cpp
	../adapter/expr_eval.cpp
	../adapter/transport.cpp
	../adapter/pipe_client.cpp
	../adapter/injector.cpp
	../adapter/disassembler.cpp
	../adapter/zydis_disassembler.cpp
)

# Native storage fault boundaries without launching a target or KD connection.
add_executable(kd_capture_store_tests
    ${CMAKE_SOURCE_DIR}/test/kd_capture_store_tests.cpp
    kd_capture_store.cpp
    ../adapter/disassembler.cpp
    ../adapter/zydis_disassembler.cpp)
target_link_libraries(kd_capture_store_tests PRIVATE veh_common nlohmann_json Zydis bcrypt)
target_include_directories(kd_capture_store_tests PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/third_party)
target_compile_definitions(kd_capture_store_tests PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

target_link_libraries(veh-mcp-server PRIVATE
	veh_common
	veh_remote
	nlohmann_json
	Zydis
	asmtk
	ws2_32
	dbghelp
	shell32
)

target_include_directories(veh-mcp-server PRIVATE
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_SOURCE_DIR}/third_party
)

target_compile_definitions(veh-mcp-server PRIVATE
	_CRT_SECURE_NO_WARNINGS
	WIN32_LEAN_AND_MEAN
	NOMINMAX
	UNICODE
	_UNICODE
)
