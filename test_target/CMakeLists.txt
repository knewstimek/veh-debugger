add_executable(test_target main.cpp)
target_compile_definitions(test_target PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
)
# PDB 생성 — 소스 레벨 디버깅 테스트용
# /Zi: PDB에 디버그 정보 저장, /Od: 최적화 비활성 (라인 정보 정확도)
target_compile_options(test_target PRIVATE /Zi /Od)
target_link_options(test_target PRIVATE /DEBUG /PDB:$<TARGET_FILE_DIR:test_target>/test_target.pdb)
