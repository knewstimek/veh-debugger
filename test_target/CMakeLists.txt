add_executable(test_target main.cpp)
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
