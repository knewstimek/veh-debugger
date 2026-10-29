add_executable(guest_backend_fixture guest_backend_fixture.cpp)
target_include_directories(guest_backend_fixture PRIVATE ../src/common)
target_compile_definitions(guest_backend_fixture PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(ipc_transport_regression ipc_transport_regression.cpp ../src/adapter/pipe_client.cpp)
target_include_directories(ipc_transport_regression PRIVATE ../src ../src/common)
target_compile_definitions(ipc_transport_regression PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(trace_path_regression trace_path_regression.cpp)
target_compile_definitions(trace_path_regression PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

# Loaded only by test_target --symbol-lookup; duplicate export names exercise ambiguity.
add_library(symbol_lookup_a SHARED symbol_lookup_probe.cpp)
add_library(symbol_lookup_b SHARED symbol_lookup_probe.cpp)
target_compile_definitions(symbol_lookup_a PRIVATE SYMBOL_PROBE_A)
foreach(probe symbol_lookup_a symbol_lookup_b)
    target_compile_options(${probe} PRIVATE /Zi /Od)
    target_link_options(${probe} PRIVATE /DEBUG /PDB:$<TARGET_FILE_DIR:${probe}>/${probe}.pdb)
endforeach()

add_executable(test_target main.cpp)
add_dependencies(test_target symbol_lookup_a symbol_lookup_b)
target_compile_definitions(test_target PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
)
# PDB 생성 — 소스 레벨 디버깅 테스트용
# /Zi: PDB에 디버그 정보 저장, /Od: 최적화 비활성 (라인 정보 정확도)
target_compile_options(test_target PRIVATE /Zi /Od)
target_link_options(test_target PRIVATE /DEBUG /PDB:$<TARGET_FILE_DIR:test_target>/test_target.pdb)

# Deferred (pending) breakpoint tests: the host late-loads deferred_dll.dll
add_library(deferred_dll SHARED deferred_dll.cpp)
add_executable(deferred_host deferred_host.cpp)
add_dependencies(deferred_host deferred_dll)
foreach(target deferred_dll deferred_host)
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
    target_compile_options(${target} PRIVATE /Zi /Od)
    target_link_options(${target} PRIVATE /DEBUG /PDB:$<TARGET_FILE_DIR:${target}>/${target}.pdb)
endforeach()
