add_executable(veh-mcp-server
	main.cpp
	mcp_server.cpp
	installer.cpp
	../adapter/transport.cpp
	../adapter/pipe_client.cpp
	../adapter/injector.cpp
	../adapter/disassembler.cpp
	../adapter/zydis_disassembler.cpp
)

target_link_libraries(veh-mcp-server PRIVATE
	veh_common
	nlohmann_json
	Zydis
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
